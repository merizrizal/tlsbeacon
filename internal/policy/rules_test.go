package policy

import (
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func addr(s string) netip.Addr     { return netip.MustParseAddr(s) }
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func candidate(ip string, port int) Candidate {
	a := addr(ip)
	c := Candidate{Address: a, Port: port, Target: ip}
	if a.Unmap().Is4() {
		c.Route = RouteGateway
	}
	return c
}

func makePolicy(t *testing.T, rules ...Rule) Policy {
	t.Helper()
	p, err := New(&Input{Version: Version, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPolicyValidationAndEmpty(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("missing policy accepted")
	}
	for _, in := range []*Input{
		{}, {Version: 2}, {Version: Version, Rules: []Rule{{CIDR: "host.example", Port: 443}}},
		{Version: Version, Rules: []Rule{{CIDR: "0.0.0.0/0", Port: 0}}},
		{Version: Version, Rules: []Rule{{CIDR: "0.0.0.0/0", Port: 65536}}},
		{Version: Version, Rules: []Rule{{CIDR: "0.0.0.0/0", Port: 443, Acknowledge: 128}}},
		{Version: Version, Rules: []Rule{{CIDR: "0.0.0.0/0", Port: 443, Target: "https://secret.example"}}},
		{Version: Version, Rules: []Rule{{CIDR: "::/0", Port: 443, Interface: "bad%scope"}}},
		{Version: Version, Metadata: []string{"example.com"}},
	} {
		if _, err := New(in); err == nil {
			t.Fatalf("malformed policy accepted: %#v", in)
		}
	}
	p := makePolicy(t)
	if p.Authorize(candidate("8.8.8.8", 443)) || (Policy{}).Authorize(candidate("8.8.8.8", 443)) || (Policy{}).Equal(Policy{}) {
		t.Fatal("empty or missing policy allowed a target")
	}
	if _, valid := p.Digest(); !valid {
		t.Fatal("valid empty policy lacks identity")
	}
	if _, valid := (Policy{}).Digest(); valid {
		t.Fatal("missing policy has valid identity")
	}
}

func TestPublicGrantDenyAndPortBoundaries(t *testing.T) {
	p := makePolicy(t,
		Rule{CIDR: "8.8.8.0/24", Port: 443},
		Rule{CIDR: "8.8.8.8/32", Port: 443, Deny: true},
		Rule{CIDR: "8.8.8.8/32", Port: 8443},
	)
	for _, tc := range []struct {
		ip   string
		port int
		want bool
	}{
		{"8.8.8.0", 443, true}, {"8.8.8.7", 443, true}, {"8.8.8.8", 443, false},
		{"8.8.8.8", 8443, true}, {"8.8.8.255", 443, true}, {"8.8.9.0", 443, false},
		{"8.8.8.7", 444, false}, {"8.8.8.7", 0, false}, {"8.8.8.7", 65536, false},
	} {
		if got := p.Authorize(candidate(tc.ip, tc.port)); got != tc.want {
			t.Fatalf("%s:%d got %v want %v", tc.ip, tc.port, got, tc.want)
		}
	}
	if p.Authorize(Candidate{Address: addr("8.8.8.7"), Port: 443}) {
		t.Fatal("missing configured target accepted")
	}
	v6 := makePolicy(t, Rule{CIDR: "2606:4700::/32", Port: 443})
	if !v6.Authorize(candidate("2606:4700:4700::1111", 443)) || v6.Authorize(candidate("2606:4701::1", 443)) {
		t.Fatal("public IPv6 CIDR grant failed")
	}
}

func TestClassificationBoundaries(t *testing.T) {
	cases := []struct {
		ip   string
		want Class
	}{
		{"9.255.255.255", 0}, {"10.0.0.0", Private}, {"10.255.255.255", Private}, {"11.0.0.0", 0},
		{"172.15.255.255", 0}, {"172.16.0.0", Private}, {"172.31.255.255", Private}, {"172.32.0.0", 0},
		{"192.168.0.0", Private}, {"192.168.255.255", Private}, {"192.169.0.0", 0},
		{"126.255.255.255", 0}, {"127.0.0.1", Loopback}, {"127.255.255.255", Loopback}, {"128.0.0.0", 0},
		{"169.253.255.255", 0}, {"169.254.0.0", LinkLocal}, {"169.254.169.254", LinkLocal | Metadata},
		{"169.254.170.2", LinkLocal | Metadata}, {"169.254.255.255", LinkLocal}, {"169.255.0.0", 0},
		{"100.63.255.255", 0}, {"100.64.0.0", SpecialUse}, {"100.100.100.200", SpecialUse | Metadata}, {"100.127.255.255", SpecialUse}, {"100.128.0.0", 0},
		{"192.0.0.9", SpecialUse}, {"192.31.196.1", SpecialUse}, {"198.18.0.0", SpecialUse},
		{"198.19.255.255", SpecialUse}, {"198.20.0.0", 0}, {"203.0.113.1", SpecialUse}, {"240.0.0.1", SpecialUse},
		{"::1", Loopback}, {"2001:db8::1", SpecialUse}, {"2001:1::3", SpecialUse}, {"2001:200::1", 0},
		{"2620:4f:8000::1", SpecialUse}, {"3fff::1", SpecialUse}, {"5f00::1", SpecialUse},
		{"fbff:ffff::1", SpecialUse}, {"fc00::1", Private}, {"fd00:ec2::254", Private | Metadata},
		{"fdff:ffff::1", Private}, {"fe00::1", SpecialUse}, {"fe80::1", LinkLocal}, {"febf:ffff::1", LinkLocal}, {"fec0::1", SpecialUse},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			if got := classify(addr(tc.ip), nil); got != tc.want {
				t.Fatalf("classes %b want %b", got, tc.want)
			}
		})
	}
}

func TestEveryPublishedSpecialRangeBoundary(t *testing.T) {
	for _, network := range specialRanges {
		t.Run(network.String(), func(t *testing.T) {
			first := network.Masked().Addr()
			last := lastAddress(network)
			for _, ip := range []netip.Addr{first, last} {
				if ip.IsUnspecified() || ip.IsMulticast() || ip == addr("255.255.255.255") {
					continue
				}
				classes := classify(ip, nil)
				if classes&(Private|Loopback|LinkLocal|SpecialUse) == 0 {
					t.Fatalf("boundary %s lacks protected class", ip)
				}
				if classes&SpecialUse != 0 && !ip.Is4In6() {
					full := makePolicy(t, Rule{CIDR: network.String(), Port: 443, Acknowledge: classes})
					missing := makePolicy(t, Rule{CIDR: network.String(), Port: 443, Acknowledge: classes &^ SpecialUse})
					if !full.Authorize(candidate(ip.String(), 443)) || missing.Authorize(candidate(ip.String(), 443)) {
						t.Fatalf("boundary %s did not enforce its special-use acknowledgment", ip)
					}
				}
			}
		})
	}
}

func lastAddress(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	if a.Is4() {
		value := a.As4()
		for bit := p.Bits(); bit < 32; bit++ {
			value[bit/8] |= byte(1 << (7 - uint(bit%8)))
		}
		return netip.AddrFrom4(value)
	}
	value := a.As16()
	for bit := p.Bits(); bit < 128; bit++ {
		value[bit/8] |= byte(1 << (7 - uint(bit%8)))
	}
	return netip.AddrFrom16(value)
}

func TestClassAcknowledgmentsAndMetadataOverlay(t *testing.T) {
	cases := []struct {
		ip, cidr string
		required Class
	}{
		{"10.1.2.3", "10.0.0.0/8", Private}, {"127.0.0.1", "127.0.0.0/8", Loopback},
		{"169.254.1.2", "169.254.0.0/16", LinkLocal}, {"192.0.2.1", "192.0.2.0/24", SpecialUse},
		{"169.254.169.254", "169.254.0.0/16", LinkLocal | Metadata},
		{"169.254.170.2", "169.254.0.0/16", LinkLocal | Metadata},
		{"100.100.100.200", "100.64.0.0/10", SpecialUse | Metadata},
		{"fd00:ec2::254", "fc00::/7", Private | Metadata},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			for ack := Class(0); ack <= allClasses; ack++ {
				p := makePolicy(t, Rule{CIDR: tc.cidr, Port: 443, Acknowledge: ack})
				want := ack&tc.required == tc.required
				if got := p.Authorize(candidate(tc.ip, 443)); got != want {
					t.Fatalf("ack %b got %v want %v", ack, got, want)
				}
			}
		})
	}
	p, err := New(&Input{Version: Version, Metadata: []string{"10.2.0.0/16"}, Rules: []Rule{{CIDR: "10.0.0.0/8", Port: 443, Acknowledge: Private}}})
	if err != nil || p.Authorize(candidate("10.2.3.4", 443)) || !p.Authorize(candidate("10.3.3.4", 443)) {
		t.Fatal("operator metadata extension not enforced")
	}
	p = makePolicy(t, Rule{CIDR: "169.254.0.0/16", Port: 443, Acknowledge: LinkLocal}, Rule{CIDR: "169.254.0.0/16", Port: 443, Acknowledge: Metadata})
	if p.Authorize(candidate("169.254.169.254", 443)) {
		t.Fatal("separate insufficient grants combined into authority")
	}
}

func TestMappedAddressesAndInvalidDestinations(t *testing.T) {
	p := makePolicy(t, Rule{CIDR: "::ffff:10.0.0.1/104", Port: 443, Acknowledge: Private}, Rule{CIDR: "::/0", Port: 443, Acknowledge: allClasses})
	if !p.Authorize(candidate("::ffff:10.1.2.3", 443)) || !p.Authorize(candidate("10.1.2.3", 443)) {
		t.Fatal("mapped grant did not match IPv4")
	}
	if p.Authorize(candidate("::ffff:127.0.0.1", 443)) {
		t.Fatal("IPv6 broad rule bypassed underlying IPv4 policy")
	}
	v4 := makePolicy(t, Rule{CIDR: "0.0.0.0/0", Port: 443, Acknowledge: allClasses})
	v6 := makePolicy(t, Rule{CIDR: "::/0", Port: 443, Acknowledge: allClasses})
	for _, ip := range []string{"0.0.0.0", "255.255.255.255", "224.0.0.1", "::ffff:224.0.0.1", "::", "ff02::1"} {
		if v4.Authorize(candidate(ip, 443)) || v6.Authorize(candidate(ip, 443)) {
			t.Fatalf("invalid target %s allowed", ip)
		}
	}
	b := candidate("10.1.2.255", 443)
	b.Route = RouteDirect
	b.LocalSubnet = prefix("10.1.2.0/24")
	if v4.Authorize(b) {
		t.Fatal("known directed broadcast allowed")
	}
	b.LocalSubnet = prefix("10.1.2.254/31")
	if !v4.Authorize(b) {
		t.Fatal("point-to-point /31 endpoint rejected")
	}
	b.Route = RouteUnknown
	b.LocalSubnet = netip.Prefix{}
	if v4.Authorize(b) {
		t.Fatal("unverified route accepted")
	}
	b.Route = RouteDirect
	if v4.Authorize(b) {
		t.Fatal("direct route without subnet accepted")
	}
	b.LocalSubnet = prefix("10.2.0.0/16")
	if v4.Authorize(b) {
		t.Fatal("unrelated local subnet accepted")
	}
}

func TestTargetAndInterfaceNarrowing(t *testing.T) {
	p := makePolicy(t, Rule{CIDR: "fe80::/10", Port: 443, Acknowledge: LinkLocal, Target: "SERVICE.Example.", Interface: "eth0"})
	c := Candidate{Address: addr("fe80::1"), Port: 443, Target: "service.example", Interface: "eth0"}
	if !p.Authorize(c) {
		t.Fatal("matching scoped rule denied")
	}
	for _, bad := range []Candidate{
		{Address: addr("fe80::1"), Port: 443, Target: "service.example"},
		{Address: addr("fe80::1"), Port: 443, Target: "other.example", Interface: "eth0"},
		{Address: addr("fe80::1"), Port: 443, Target: "service.example", Interface: "eth1"},
		{Address: addr("fe80::1%eth1"), Port: 443, Target: "service.example", Interface: "eth0"},
	} {
		if p.Authorize(bad) {
			t.Fatalf("narrowing bypass: %#v", bad)
		}
	}
	literal := makePolicy(t, Rule{CIDR: "fe80::/10", Port: 443, Acknowledge: LinkLocal, Target: "[fe80::1%eth0]"})
	if !literal.Authorize(Candidate{Address: addr("fe80::1%eth0"), Port: 443, Target: "fe80::1%eth0"}) || literal.Authorize(Candidate{Address: addr("fe80::1%eth1"), Port: 443, Target: "fe80::1%eth0"}) {
		t.Fatal("configured scoped numeric target not enforced")
	}
	broad := makePolicy(t, Rule{CIDR: "0.0.0.0/0", Port: 443})
	if broad.Authorize(Candidate{Address: addr("8.8.8.8"), Port: 443, Target: "8.8.4.4", Route: RouteGateway}) {
		t.Fatal("configured numeric target mismatched candidate")
	}
	if broad.Authorize(Candidate{Address: addr("8.8.8.8"), Port: 443, Target: "host.example", Interface: "eth0", Route: RouteGateway}) {
		t.Fatal("IPv4 interface scope accepted")
	}
}

func TestCanonicalIdentityAndIsolation(t *testing.T) {
	a := &Input{Version: Version, Rules: []Rule{
		{CIDR: "10.0.0.17/8", Port: 443, Acknowledge: Private, Target: "Example.COM."},
		{CIDR: "2001:0db8::1/32", Port: 8443, Acknowledge: SpecialUse},
	}, Metadata: []string{"10.3.4.5/16", "10.3.0.0/16"}}
	b := &Input{Version: Version, Rules: []Rule{
		{CIDR: "2001:db8::/32", Port: 8443, Acknowledge: SpecialUse},
		{CIDR: "::ffff:10.0.0.0/104", Port: 443, Acknowledge: Private, Target: "example.com"},
		{CIDR: "10.0.0.0/8", Port: 443, Acknowledge: Private, Target: "example.com"},
	}, Metadata: []string{"10.3.0.0/16", "10.3.4.0/24", "169.254.169.254/32"}}
	pa, err := New(a)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := New(b)
	if err != nil || !pa.Equal(pb) {
		t.Fatal("canonical equivalent policies differ")
	}
	before, _ := pa.Digest()
	a.Rules[0].CIDR = "0.0.0.0/0"
	a.Metadata[0] = "0.0.0.0/0"
	after, _ := pa.Digest()
	if before != after || !pa.Equal(pb) {
		t.Fatal("policy changed through input alias")
	}
	b.Rules[0].Port++
	changed, err := New(b)
	if err != nil || pa.Equal(changed) {
		t.Fatal("real policy change not distinguished")
	}
	deny := makePolicy(t, Rule{CIDR: "8.8.8.0/24", Port: 443, Deny: true})
	denyWithAck := makePolicy(t, Rule{CIDR: "8.8.8.0/24", Port: 443, Deny: true, Acknowledge: Private})
	if !deny.Equal(denyWithAck) {
		t.Fatal("irrelevant deny acknowledgments changed identity")
	}
}

func TestClassificationDocumentationMatchesImplementation(t *testing.T) {
	data, err := os.ReadFile("../../docs/network-policy.md")
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string][]netip.Prefix{
		"Private": privateRanges, "Loopback": loopbackRanges, "Link-local": linkLocalRanges,
		"Other special-use IPv4": {}, "Other special-use IPv6": {}, "Built-in metadata overlay": metadataRanges,
	}
	for _, p := range specialRanges {
		key := "Other special-use IPv6"
		if p.Addr().Is4() {
			key = "Other special-use IPv4"
		}
		rows[key] = append(rows[key], p)
	}
	pattern := regexp.MustCompile("`([^`]+)`")
	found := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, "|")
		if len(fields) < 4 {
			continue
		}
		name := strings.TrimSpace(fields[1])
		want, exists := rows[name]
		if !exists {
			continue
		}
		if found[name] {
			t.Fatalf("duplicate table row %s", name)
		}
		found[name] = true
		got := pattern.FindAllStringSubmatch(fields[2], -1)
		if len(got) != len(want) {
			t.Fatalf("%s has %d prefixes, want %d", name, len(got), len(want))
		}
		for i := range want {
			p, err := netip.ParsePrefix(got[i][1])
			if err != nil || p != want[i] {
				t.Fatalf("%s prefix %d: %s, want %s", name, i, got[i][1], want[i])
			}
		}
	}
	for name := range rows {
		if !found[name] {
			t.Fatalf("missing table row %s", name)
		}
	}
	if !strings.Contains(string(data), ClassificationVersion) {
		t.Fatal("classification version missing from documentation")
	}
}

func TestPolicyHasNoNetworkOrProxyImports(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "rules.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"crypto/sha256": true, "encoding/json": true, "errors": true, "net/netip": true, "sort": true, "strings": true, "github.com/merizrizal/tlsbeacon/internal/endpoint": true}
	for _, spec := range file.Imports {
		name, err := strconv.Unquote(spec.Path.Value)
		if err != nil || !allowed[name] {
			t.Fatalf("unexpected import %s", spec.Path.Value)
		}
	}
}
