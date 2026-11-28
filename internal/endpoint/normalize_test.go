package endpoint

import (
	"errors"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func requireReason(t *testing.T, err error, want Reason) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error = %v (%T), want *Error with reason %d", err, err, want)
	}
	if e.Reason != want {
		t.Fatalf("reason = %d, want %d (error: %v)", e.Reason, want, err)
	}
}

func TestConnectionHostCanonicalForms(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		display string
		canon   string
		kind    Kind
		zone    string
	}{
		{"root dot and case", "EXAMPLE.com.", "EXAMPLE.com.", "example.com", KindDNSName, ""},
		{"surrounding ASCII whitespace", " \t example.com\r\n", "example.com", "example.com", KindDNSName, ""},
		{"single label", "LocalHost", "LocalHost", "localhost", KindDNSName, ""},
		{"non-transitional IDNA", "faß.de", "faß.de", "xn--fa-hia.de", KindDNSName, ""},
		{"dotted-decimal IPv4", "192.0.2.1", "192.0.2.1", "192.0.2.1", KindIPv4, ""},
		{"IPv6 plain", "2001:db8::1", "2001:db8::1", "2001:db8::1", KindIPv6, ""},
		{"IPv6 bracketed", "[2001:db8::1]", "[2001:db8::1]", "2001:db8::1", KindIPv6, ""},
		{"IPv6 uppercase", "2001:DB8::1", "2001:DB8::1", "2001:db8::1", KindIPv6, ""},
		{"IPv6 bracketed uppercase", "[2001:DB8::1]", "[2001:DB8::1]", "2001:db8::1", KindIPv6, ""},
		{"IPv4-mapped plain", "::ffff:192.0.2.1", "::ffff:192.0.2.1", "192.0.2.1", KindIPv4, ""},
		{"IPv4-mapped bracketed", "[::ffff:192.0.2.1]", "[::ffff:192.0.2.1]", "192.0.2.1", KindIPv4, ""},
		{"loopback IPv6", "::1", "::1", "::1", KindIPv6, ""},
		{"link-local with scope", "fe80::1%eth0", "fe80::1%eth0", "fe80::1", KindIPv6, "eth0"},
		{"bracketed link-local with scope", "[fe80::1%eth0]", "[fe80::1%eth0]", "fe80::1", KindIPv6, "eth0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := ParseConnectionHost(tc.input)
			if err != nil {
				t.Fatalf("ParseConnectionHost(%q) error: %v", tc.input, err)
			}
			if h.Display() != tc.display {
				t.Errorf("Display() = %q, want %q", h.Display(), tc.display)
			}
			if h.Canonical() != tc.canon {
				t.Errorf("Canonical() = %q, want %q", h.Canonical(), tc.canon)
			}
			if h.Kind() != tc.kind {
				t.Errorf("Kind() = %d, want %d", h.Kind(), tc.kind)
			}
			if h.Zone() != tc.zone {
				t.Errorf("Zone() = %q, want %q", h.Zone(), tc.zone)
			}
		})
	}
}

func TestExpectedIdentityCanonicalForms(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		display string
		canon   string
		kind    Kind
	}{
		{"DNS name with case and root dot", "EXAMPLE.com.", "EXAMPLE.com.", "example.com", KindDNSName},
		{"single-label name", "Intranet", "Intranet", "intranet", KindDNSName},
		{"non-transitional IDNA", "faß.de", "faß.de", "xn--fa-hia.de", KindDNSName},
		{"dotted-decimal IPv4", "192.0.2.10", "192.0.2.10", "192.0.2.10", KindIPv4},
		{"IPv6 plain", "2001:db8::1", "2001:db8::1", "2001:db8::1", KindIPv6},
		{"IPv6 bracketed uppercase", "[2001:DB8::1]", "[2001:DB8::1]", "2001:db8::1", KindIPv6},
		{"IPv4-mapped", "::ffff:192.0.2.1", "::ffff:192.0.2.1", "192.0.2.1", KindIPv4},
		{"link-local without scope", "fe80::1", "fe80::1", "fe80::1", KindIPv6},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, err := ParseExpectedIdentity(tc.input)
			if err != nil {
				t.Fatalf("ParseExpectedIdentity(%q) error: %v", tc.input, err)
			}
			if id.Display() != tc.display {
				t.Errorf("Display() = %q, want %q", id.Display(), tc.display)
			}
			if id.Canonical() != tc.canon {
				t.Errorf("Canonical() = %q, want %q", id.Canonical(), tc.canon)
			}
			if id.Kind() != tc.kind {
				t.Errorf("Kind() = %d, want %d", id.Kind(), tc.kind)
			}
		})
	}
}

func TestEquivalentSpellingsShareCanonicalIdentity(t *testing.T) {
	hostGroups := [][]string{
		{"example.com", "EXAMPLE.com", "example.com.", "Example.COM."},
		{"faß.de", "FAß.de", "xn--fa-hia.de"},
		{"2001:db8::1", "[2001:db8::1]", "2001:DB8::1", "[2001:0db8::0001]"},
		{"::ffff:192.0.2.1", "192.0.2.1", "[::ffff:192.0.2.1]"},
	}
	for _, group := range hostGroups {
		first, err := ParseConnectionHost(group[0])
		if err != nil {
			t.Fatalf("ParseConnectionHost(%q): %v", group[0], err)
		}
		for _, spelling := range group[1:] {
			h, err := ParseConnectionHost(spelling)
			if err != nil {
				t.Fatalf("ParseConnectionHost(%q): %v", spelling, err)
			}
			if h.Canonical() != first.Canonical() || h.Kind() != first.Kind() || h.Zone() != first.Zone() {
				t.Errorf("%q identity (%q, %d, %q) differs from %q (%q, %d, %q)",
					spelling, h.Canonical(), h.Kind(), h.Zone(),
					group[0], first.Canonical(), first.Kind(), first.Zone())
			}
		}
	}
}

func TestDisplaySpellingDoesNotAffectIdentity(t *testing.T) {
	upper, err := ParseConnectionHost("EXAMPLE.com.")
	if err != nil {
		t.Fatal(err)
	}
	lower, err := ParseConnectionHost("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if upper.Display() == lower.Display() {
		t.Fatalf("display spellings should differ, both are %q", upper.Display())
	}
	if upper.Canonical() != lower.Canonical() {
		t.Fatalf("canonical values differ: %q vs %q", upper.Canonical(), lower.Canonical())
	}
}

func TestFaßIsNotFolded(t *testing.T) {
	h, err := ParseConnectionHost("faß.de")
	if err != nil {
		t.Fatal(err)
	}
	if h.Canonical() == "fass.de" {
		t.Fatalf("ß folded to ss: %q", h.Canonical())
	}
	if h.Canonical() != "xn--fa-hia.de" {
		t.Fatalf("canonical = %q, want xn--fa-hia.de", h.Canonical())
	}
}

func TestLabelAndWireBoundaries(t *testing.T) {
	label61 := strings.Repeat("a", 61)
	label62 := strings.Repeat("a", 62)
	label63 := strings.Repeat("a", 63)
	label64 := strings.Repeat("a", 64)
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"63-octet label accepted", label63 + ".example", false},
		{"64-octet label rejected", label64 + ".example", true},
		{"wire length 255 accepted", label63 + "." + label63 + "." + label63 + "." + label61, false},
		{"wire length 256 rejected", label63 + "." + label63 + "." + label63 + "." + label62, true},
		{"single label accepted", "localhost", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, herr := ParseConnectionHost(tc.input)
			_, ierr := ParseExpectedIdentity(tc.input)
			if (herr != nil) != tc.wantErr {
				t.Errorf("ParseConnectionHost error = %v, wantErr %v", herr, tc.wantErr)
			}
			if (ierr != nil) != tc.wantErr {
				t.Errorf("ParseExpectedIdentity error = %v, wantErr %v", ierr, tc.wantErr)
			}
		})
	}
}

func TestMalformedNamesAreRejected(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Reason
	}{
		{"empty", "", ReasonEmpty},
		{"whitespace only", " \t\r\n", ReasonEmpty},
		{"embedded space", "exa mple.com", ReasonWhitespaceOrControl},
		{"embedded tab", "exa\tmple.com", ReasonWhitespaceOrControl},
		{"NUL control", "example\x00.com", ReasonWhitespaceOrControl},
		{"DEL control", "exa\x7fmple.com", ReasonWhitespaceOrControl},
		{"empty interior label", "a..b", ReasonInvalidName},
		{"leading dot", ".example.com", ReasonInvalidName},
		{"double terminal dot", "example.com..", ReasonInvalidName},
		{"lone root dot", ".", ReasonInvalidName},
		{"leftmost wildcard", "*.example.com", ReasonWildcard},
		{"trailing wildcard", "example.*", ReasonWildcard},
		{"underscore rejected by STD3", "_sip.example.com", ReasonInvalidName},
		{"percent in a name", "example%1.com", ReasonInvalidName},
		{"root dot produced by UTS #46 mapping", "example。", ReasonInvalidName},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConnectionHost(tc.input)
			requireReason(t, err, tc.want)
			_, err = ParseExpectedIdentity(tc.input)
			requireReason(t, err, tc.want)
		})
	}
}

func TestURLPathUserinfoAndPortFormsAreRejected(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Reason
	}{
		{"scheme and host", "https://example.com", ReasonURLOrPath},
		{"path", "example.com/path", ReasonURLOrPath},
		{"user name", "user@example.com", ReasonURLOrPath},
		{"query", "example.com?x=1", ReasonURLOrPath},
		{"fragment", "example.com#frag", ReasonURLOrPath},
		{"DNS host with port", "example.com:443", ReasonHostPort},
		{"IPv4 with port", "192.0.2.1:443", ReasonHostPort},
		{"bracketed IPv6 with port", "[2001:db8::1]:443", ReasonHostPort},
		{"bracketed IPv6 with unterminated bracket", "[::1", ReasonInvalidIP},
		{"bare IPv6 with stray bracket", "2001:db8::1]", ReasonInvalidIP},
		{"brackets around IPv4", "[192.0.2.1]", ReasonInvalidIP},
		{"doubled closing bracket", "[2001:db8::1]]", ReasonInvalidIP},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConnectionHost(tc.input)
			requireReason(t, err, tc.want)
			_, err = ParseExpectedIdentity(tc.input)
			requireReason(t, err, tc.want)
		})
	}
}

func TestIPv4AcceptsDottedDecimalOnly(t *testing.T) {
	for _, input := range []string{"192.0.2.1", "198.51.100.7"} {
		h, err := ParseConnectionHost(input)
		if err != nil || h.Kind() != KindIPv4 || h.Canonical() != input {
			t.Errorf("ParseConnectionHost(%q) = (%q, %d, %v), want dotted-decimal IPv4", input, h.Canonical(), h.Kind(), err)
		}
	}
}

func TestLegacyNumericIPv4FormsAreRejected(t *testing.T) {
	inputs := []string{
		"127.1",
		"0x7f.0.0.1",
		"0177.0.0.1",
		"2130706433",
		"192.168.001.1",
		"256.0.0.1",
		"1.2.3.0x1",
		"0x7f",
		"127.0.0.1.",
	}
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			_, err := ParseConnectionHost(input)
			requireReason(t, err, ReasonLegacyNumericIP)
			_, err = ParseExpectedIdentity(input)
			requireReason(t, err, ReasonLegacyNumericIP)
		})
	}
}

func TestIPv6InterfaceScopeRules(t *testing.T) {
	type okCase struct {
		input, canon, zone string
	}
	accepted := []okCase{
		{"fe80::1%eth0", "fe80::1", "eth0"},
		{"[fe80::1%eth0]", "fe80::1", "eth0"},
		{"fe80::1%eth0.1-a_b", "fe80::1", "eth0.1-a_b"},
	}
	for _, tc := range accepted {
		h, err := ParseConnectionHost(tc.input)
		if err != nil {
			t.Errorf("ParseConnectionHost(%q): %v", tc.input, err)
			continue
		}
		if h.Canonical() != tc.canon || h.Zone() != tc.zone || h.Kind() != KindIPv6 {
			t.Errorf("ParseConnectionHost(%q) = (%q, %q, %d), want (%q, %q, IPv6)",
				tc.input, h.Canonical(), h.Zone(), h.Kind(), tc.canon, tc.zone)
		}
	}

	rejected := []struct {
		name, input string
		want        Reason
	}{
		{"link-local without scope", "fe80::1", ReasonZoneRequired},
		{"bracketed link-local without scope", "[fe80::1]", ReasonZoneRequired},
		{"empty scope", "fe80::1%", ReasonZoneMalformed},
		{"scope with percent", "fe80::1%e%th", ReasonZoneMalformed},
		{"scope with whitespace", "fe80::1%et h0", ReasonWhitespaceOrControl},
		{"scope on documentation prefix", "2001:db8::1%eth0", ReasonZoneNotPermitted},
		{"scope on IPv4-mapped address", "::ffff:192.0.2.1%eth0", ReasonZoneNotPermitted},
		{"scope on bracketed documentation prefix", "[2001:db8::1%eth0]", ReasonZoneNotPermitted},
		{"scope on IPv4", "192.0.2.1%eth0", ReasonZoneNotPermitted},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConnectionHost(tc.input)
			requireReason(t, err, tc.want)
		})
	}
}

func TestExpectedIdentityRejectsScopePortURLAndWildcard(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Reason
	}{
		{"scope on IPv6", "fe80::1%eth0", ReasonZoneInIdentity},
		{"bracketed scope", "[fe80::1%eth0]", ReasonZoneInIdentity},
		{"scope on documentation prefix", "2001:db8::1%eth0", ReasonZoneInIdentity},
		{"DNS name with port", "example.com:443", ReasonHostPort},
		{"bracketed IPv6 with port", "[2001:db8::1]:443", ReasonHostPort},
		{"URL", "https://example.com", ReasonURLOrPath},
		{"wildcard", "*.example.com", ReasonWildcard},
		{"empty", "  ", ReasonEmpty},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseExpectedIdentity(tc.input)
			requireReason(t, err, tc.want)
		})
	}
}

func TestIPConnectionWithDNSIdentityIsIndependent(t *testing.T) {
	h, err := ParseConnectionHost("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	id, err := ParseExpectedIdentity("service.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if h.Canonical() != "192.0.2.10" || h.Kind() != KindIPv4 {
		t.Errorf("connection host = (%q, %d)", h.Canonical(), h.Kind())
	}
	if id.Canonical() != "service.example.com" || id.Kind() != KindDNSName {
		t.Errorf("expected identity = (%q, %d)", id.Canonical(), id.Kind())
	}
}

func TestRejectedInputsReturnNoValue(t *testing.T) {
	inputs := []string{
		"", "a..b", "https://x", "x:443", "*.example.com", "127.1",
		"fe80::1", "fe80::1%eth0/x", "2001:db8::1%eth0", "exa mple.com",
	}
	for _, input := range inputs {
		h, err := ParseConnectionHost(input)
		if err != nil && h != (ConnectionHost{}) {
			t.Errorf("ParseConnectionHost(%q) returned %+v with error", input, h)
		}
		id, err := ParseExpectedIdentity(input)
		if err != nil && id != (ExpectedIdentity{}) {
			t.Errorf("ParseExpectedIdentity(%q) returned %+v with error", input, id)
		}
	}
}

func TestErrorEchoIsEscapedAndBounded(t *testing.T) {
	input := "\x1b[31m" + strings.Repeat("a", 1000)
	_, err := ParseConnectionHost(input)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if strings.ContainsRune(msg, 0x1b) {
		t.Errorf("error text contains a raw escape byte: %q", msg)
	}
	if !strings.Contains(msg, `\x1b`) {
		t.Errorf("error text does not show the escaped control byte: %q", msg)
	}
	if len(msg) > 400 {
		t.Errorf("error text length %d is not bounded", len(msg))
	}
}

func TestPackageDoesNotImportNetworkOrResolver(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		checked++
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, imp := range parsed.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("import path in %s: %v", file, err)
			}
			if path == "net" || (strings.HasPrefix(path, "net/") && path != "net/netip") {
				t.Errorf("%s imports %q; parsing must not use networking or a resolver", file, path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no non-test source files were inspected")
	}
}
