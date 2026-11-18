package endpoint

import (
	"go/parser"
	"go/token"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

func TestDNSNormalization(t *testing.T) {
	cases := []struct{ input, want string }{
		{"  ExAmPlE.COM.\t", "example.com"},
		{"BÜCHER.example", "xn--bcher-kva.example"},
		{"bu\u0308cher.example", "xn--bcher-kva.example"},
		{"faß.example", "xn--fa-hia.example"},
		{"fass.example", "fass.example"},
		{"example。COM。", "example.com"},
		{"LOCALHOST", "localhost"},
		{strings.Repeat("a", 63) + ".example", strings.Repeat("a", 63) + ".example"},
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			for _, normalize := range []func(string) (Name, error){NormalizeHost, NormalizeIdentity} {
				got, err := normalize(tc.input)
				if err != nil || got.DNS != tc.want || got.Original != tc.input || got.IP.IsValid() || got.Scope != "" {
					t.Fatalf("DNS normalization mismatch: %#v, %v", got, err)
				}
			}
		})
	}
}

func TestIPNormalization(t *testing.T) {
	cases := []struct {
		input, ip, scope string
		identityOK       bool
	}{
		{"192.0.2.1", "192.0.2.1", "", true},
		{"2001:0DB8::1", "2001:db8::1", "", true},
		{"[2001:db8::1]", "2001:db8::1", "", true},
		{"::ffff:192.0.2.1", "192.0.2.1", "", true},
		{"[::ffff:c000:201]", "192.0.2.1", "", true},
		{"[fe80::1%eth0]", "fe80::1", "eth0", false},
		{"fe80::1%2", "fe80::1", "2", false},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := NormalizeHost(tc.input)
			if err != nil || got.IP != netip.MustParseAddr(tc.ip) || got.Scope != tc.scope || got.DNS != "" || got.Original != tc.input {
				t.Fatalf("host mismatch: %#v, %v", got, err)
			}
			identity, err := NormalizeIdentity(tc.input)
			if tc.identityOK && (err != nil || identity.IP != got.IP || identity.Scope != "") || !tc.identityOK && err == nil {
				t.Fatalf("identity mismatch: %#v, %v", identity, err)
			}
		})
	}
}

func TestInvalidNames(t *testing.T) {
	cases := []string{
		"", " ", ".", ".example", "a..example", "example..", "a b", "a\u00a0b", "a\x1bb",
		"*.example", "https://example.com", "user:secret@example.com", "example.com/path", "example.com:443",
		"[example.com]", "[192.0.2.1]", "[::1]:443", "::1%", "fe80::1%eth%0", "::ffff:192.0.2.1%eth0",
		"_service.example", "-bad.example", "bad-.example", "xn--.example", strings.Repeat("a", 64) + ".example",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62),
		"127.1", "0177.0.0.1", "0x7f000001", "2130706433", "192.168.001.1", "256.0.0.1", "1.2.3.4.5", "１２７。１",
	}
	for i, input := range cases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			for _, normalize := range []func(string) (Name, error){NormalizeHost, NormalizeIdentity} {
				got, err := normalize(input)
				if err == nil || got != (Name{}) {
					t.Fatal("invalid input accepted or returned partial result")
				}
				if strings.ContainsAny(err.Error(), "\n\r\x1b") || strings.Contains(err.Error(), "secret") {
					t.Fatal("unsafe diagnostic")
				}
			}
		})
	}
}

func TestDistinctHostAndIdentity(t *testing.T) {
	host, hostErr := NormalizeHost("192.0.2.1")
	identity, identityErr := NormalizeIdentity("Service.Example.")
	if hostErr != nil || identityErr != nil || host.IP != netip.MustParseAddr("192.0.2.1") || identity.DNS != "service.example" || identity.IP.IsValid() {
		t.Fatal("distinct host and identity were not preserved")
	}
	if _, err := NormalizeIdentity(""); err == nil {
		t.Fatal("identity was implicitly supplied")
	}
}

func TestNormalizationHasNoNetworkImports(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "normalize.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"errors": true, "net/netip": true, "strings": true, "unicode": true, "golang.org/x/net/idna": true}
	for _, spec := range file.Imports {
		name, err := strconv.Unquote(spec.Path.Value)
		if err != nil || !allowed[name] {
			t.Fatalf("unexpected normalization import: %s", spec.Path.Value)
		}
	}
}
