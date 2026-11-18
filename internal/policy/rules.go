package policy

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"

	"github.com/merizrizal/tlsbeacon/internal/endpoint"
)

const Version = 1
const ClassificationVersion = "tlsbeacon-special-use-v1"

type Class uint8

const (
	Private Class = 1 << iota
	Loopback
	LinkLocal
	SpecialUse
	Metadata
)

const allClasses = Private | Loopback | LinkLocal | SpecialUse | Metadata

var invalidPolicy = errors.New("invalid destination policy")

type Rule struct {
	CIDR        string
	Port        int
	Deny        bool
	Acknowledge Class
	Target      string
	Interface   string
}

type Input struct {
	Version  int
	Rules    []Rule
	Metadata []string
}

type RouteKind uint8

const (
	RouteUnknown RouteKind = iota
	RouteGateway
	RouteDirect
)

type Candidate struct {
	Address     netip.Addr
	Port        int
	Target      string
	Interface   string
	Route       RouteKind
	LocalSubnet netip.Prefix
}

type compiledRule struct {
	prefix netip.Prefix
	port   uint16
	deny   bool
	ack    Class
	target string
	scope  string
}

type Policy struct {
	valid     bool
	rules     []compiledRule
	metadata  []netip.Prefix
	identity  [sha256.Size]byte
	canonical string
}

type canonicalPolicy struct {
	Version        int      `json:"version"`
	Classification string   `json:"classification"`
	Rules          []Rule   `json:"rules"`
	Metadata       []string `json:"metadata"`
}

func New(input *Input) (Policy, error) {
	if input == nil || input.Version != Version {
		return Policy{}, invalidPolicy
	}
	canonical := canonicalPolicy{Version: Version, Classification: ClassificationVersion, Rules: []Rule{}, Metadata: []string{}}
	for _, r := range input.Rules {
		p, err := canonicalPrefix(r.CIDR)
		if err != nil || r.Port < 1 || r.Port > 65535 || r.Acknowledge & ^allClasses != 0 {
			return Policy{}, invalidPolicy
		}
		r.CIDR = p.String()
		if r.Deny {
			r.Acknowledge = 0
		}
		if r.Target != "" {
			r.Target, err = canonicalTarget(r.Target)
			if err != nil {
				return Policy{}, invalidPolicy
			}
		}
		if !validScope(r.Interface) {
			return Policy{}, invalidPolicy
		}
		canonical.Rules = append(canonical.Rules, r)
	}
	for _, raw := range input.Metadata {
		p, err := canonicalPrefix(raw)
		if err != nil {
			return Policy{}, invalidPolicy
		}
		canonical.Metadata = append(canonical.Metadata, p.String())
	}
	sort.Slice(canonical.Rules, func(i, j int) bool {
		a, _ := json.Marshal(canonical.Rules[i])
		b, _ := json.Marshal(canonical.Rules[j])
		return string(a) < string(b)
	})
	canonical.Rules = dedupRules(canonical.Rules)
	sort.Slice(canonical.Metadata, func(i, j int) bool {
		a, _ := netip.ParsePrefix(canonical.Metadata[i])
		b, _ := netip.ParsePrefix(canonical.Metadata[j])
		if a.Addr().Is4() != b.Addr().Is4() {
			return a.Addr().Is4()
		}
		if a.Bits() != b.Bits() {
			return a.Bits() < b.Bits()
		}
		return a.Addr().Compare(b.Addr()) < 0
	})
	canonical.Metadata = dedupStrings(canonical.Metadata)
	filtered := canonical.Metadata[:0]
	for _, raw := range canonical.Metadata {
		candidate, _ := netip.ParsePrefix(raw)
		redundant := false
		for _, builtin := range metadataRanges {
			if builtin.Bits() <= candidate.Bits() && builtin.Contains(candidate.Addr()) {
				redundant = true
				break
			}
		}
		for _, existing := range filtered {
			parent, _ := netip.ParsePrefix(existing)
			if parent.Bits() <= candidate.Bits() && parent.Contains(candidate.Addr()) {
				redundant = true
				break
			}
		}
		if !redundant {
			filtered = append(filtered, raw)
		}
	}
	canonical.Metadata = filtered
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return Policy{}, invalidPolicy
	}
	p := Policy{valid: true, identity: sha256.Sum256(encoded), canonical: string(encoded)}
	for _, r := range canonical.Rules {
		prefix, _ := netip.ParsePrefix(r.CIDR)
		p.rules = append(p.rules, compiledRule{prefix, uint16(r.Port), r.Deny, r.Acknowledge, r.Target, r.Interface})
	}
	for _, raw := range canonical.Metadata {
		prefix, _ := netip.ParsePrefix(raw)
		p.metadata = append(p.metadata, prefix)
	}
	return p, nil
}

func (p Policy) Digest() ([sha256.Size]byte, bool) { return p.identity, p.valid }

func (p Policy) Equal(other Policy) bool {
	return p.valid && other.valid && p.identity == other.identity && p.canonical == other.canonical
}

func (p Policy) Authorize(c Candidate) bool {
	if !p.valid || !c.Address.IsValid() || c.Port < 1 || c.Port > 65535 || c.Target == "" || !validScope(c.Interface) {
		return false
	}
	addr := c.Address
	scope := addr.Zone()
	if scope != "" && c.Interface != "" && scope != c.Interface {
		return false
	}
	if scope == "" {
		scope = c.Interface
	}
	if !validScope(scope) || addr.Is4In6() && scope != "" {
		return false
	}
	addr = addr.WithZone("").Unmap()
	if addr.Is4() && scope != "" || addr.Is6() && addr.IsLinkLocalUnicast() && scope == "" {
		return false
	}
	if addr.IsUnspecified() || addr.IsMulticast() || addr == netip.MustParseAddr("255.255.255.255") {
		return false
	}
	if addr.Is4() {
		if c.Route == RouteDirect {
			if !c.LocalSubnet.IsValid() || !c.LocalSubnet.Addr().Is4() || !c.LocalSubnet.Contains(addr) || directedBroadcast(addr, c.LocalSubnet) {
				return false
			}
		} else if c.Route != RouteGateway || c.LocalSubnet.IsValid() {
			return false
		}
	} else if c.Route != RouteUnknown || c.LocalSubnet.IsValid() {
		return false
	}
	name, err := endpoint.NormalizeHost(c.Target)
	if err != nil || name.IP.IsValid() && (name.IP != addr || name.Scope != "" && name.Scope != scope) {
		return false
	}
	target := nameKey(name)
	classes := classify(addr, p.metadata)
	allowed := false
	for _, rule := range p.rules {
		if !rule.prefix.Contains(addr) || int(rule.port) != c.Port || rule.target != "" && rule.target != target || rule.scope != "" && rule.scope != scope {
			continue
		}
		if rule.deny {
			return false
		}
		if rule.ack&classes == classes {
			allowed = true
		}
	}
	return allowed
}

func canonicalPrefix(raw string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(raw)
	if err != nil || !p.IsValid() {
		return netip.Prefix{}, invalidPolicy
	}
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked(), nil
	}
	return p.Masked(), nil
}

func canonicalTarget(raw string) (string, error) {
	n, err := endpoint.NormalizeHost(raw)
	if err != nil {
		return "", invalidPolicy
	}
	return nameKey(n), nil
}

func nameKey(n endpoint.Name) string {
	if n.IP.IsValid() {
		if n.Scope != "" {
			return n.IP.String() + "%" + n.Scope
		}
		return n.IP.String()
	}
	return n.DNS
}

func validScope(scope string) bool {
	if scope == "" {
		return true
	}
	n, err := endpoint.NormalizeHost("fe80::1%" + scope)
	return err == nil && n.Scope == scope
}

func directedBroadcast(addr netip.Addr, subnet netip.Prefix) bool {
	if !subnet.IsValid() || !addr.Is4() || !subnet.Addr().Is4() || subnet.Bits() > 30 || !subnet.Contains(addr) {
		return false
	}
	ip := addr.As4()
	base := subnet.Masked().Addr().As4()
	for bit := subnet.Bits(); bit < 32; bit++ {
		base[bit/8] |= byte(1 << (7 - uint(bit%8)))
	}
	return ip == base
}

func dedupRules(in []Rule) []Rule {
	out := in[:0]
	for _, r := range in {
		if len(out) == 0 || out[len(out)-1] != r {
			out = append(out, r)
		}
	}
	return out
}

func dedupStrings(in []string) []string {
	out := in[:0]
	for _, s := range in {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}

func prefixes(values string) []netip.Prefix {
	var result []netip.Prefix
	for _, value := range strings.Fields(values) {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}

var privateRanges = prefixes("10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7")
var loopbackRanges = prefixes("127.0.0.0/8 ::1/128")
var linkLocalRanges = prefixes("169.254.0.0/16 fe80::/10")
var metadataRanges = prefixes("169.254.169.254/32 169.254.170.2/32 100.100.100.200/32 fd00:ec2::254/128")
var specialRanges = prefixes("0.0.0.0/8 100.64.0.0/10 192.0.0.0/24 192.0.2.0/24 192.31.196.0/24 192.52.193.0/24 192.88.99.0/24 192.175.48.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 240.0.0.0/4 ::/8 100::/8 200::/7 400::/6 800::/5 1000::/4 4000::/3 6000::/3 8000::/3 a000::/3 c000::/3 e000::/4 f000::/5 f800::/6 fe00::/9 fec0::/10 64:ff9b::/96 64:ff9b:1::/48 100::/64 100:0:0:1::/64 2001::/23 2001:db8::/32 2002::/16 2620:4f:8000::/48 3fff::/20 5f00::/16")

func contains(ranges []netip.Prefix, addr netip.Addr) bool {
	for _, p := range ranges {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func classify(addr netip.Addr, extra []netip.Prefix) Class {
	var result Class
	if contains(privateRanges, addr) {
		result |= Private
	}
	if contains(loopbackRanges, addr) {
		result |= Loopback
	}
	if contains(linkLocalRanges, addr) {
		result |= LinkLocal
	}
	if contains(specialRanges, addr) && result == 0 {
		result |= SpecialUse
	}
	if contains(metadataRanges, addr) || contains(extra, addr) {
		result |= Metadata
	}
	return result
}
