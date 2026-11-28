// Package endpoint parses the connection host and the expected identity of a
// TLS endpoint as two separate, validated values.
//
// The connection host is where a probe would connect. The expected identity is
// the DNS name or IP address that a presented certificate must match. Parsing
// performs no DNS lookup, dials nothing and does not use a resolver. Display
// spelling is kept apart from the canonical value, and only the canonical value
// defines identity.
package endpoint

import (
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// asciiSpace is the ASCII whitespace removed from both ends of an input.
const asciiSpace = " \t\n\v\f\r"

const (
	maxQuotedBytes = 200 // bound for the input echoed in an error
	maxLabelOctets = 63  // RFC 1035 section 2.3.4: label length limit
	maxWireOctets  = 255 // RFC 1035 section 2.3.4: name length, including length octets
)

// Kind is the canonical form of a host.
type Kind int

const (
	// KindDNSName is a DNS name in lower-case A-label form, without a root dot.
	KindDNSName Kind = iota + 1
	// KindIPv4 is a dotted-decimal IPv4 address. An IPv4-mapped IPv6 address
	// has this kind too, because its IPv4 form governs identity and policy.
	KindIPv4
	// KindIPv6 is an IPv6 address without an interface scope.
	KindIPv6
)

// ConnectionHost is a validated destination host. Only values returned by
// ParseConnectionHost are valid; the zero value is not a host.
type ConnectionHost struct {
	display   string
	canonical string
	kind      Kind
	zone      string
}

// Display returns the input spelling without surrounding ASCII whitespace. It
// is non-authoritative and never affects identity.
func (h ConnectionHost) Display() string { return h.display }

// Canonical returns the identity text: a lower-case A-label for a DNS name, or
// the canonical address text. It never contains an interface scope.
func (h ConnectionHost) Canonical() string { return h.canonical }

// Kind reports the canonical form of the host.
func (h ConnectionHost) Kind() Kind { return h.kind }

// Zone returns the IPv6 interface scope, or "" when there is none.
func (h ConnectionHost) Zone() string { return h.zone }

// ExpectedIdentity is a validated DNS name or IP address that a certificate
// must match. It never carries a port, URL, wildcard or interface scope. Only
// values returned by ParseExpectedIdentity are valid.
type ExpectedIdentity struct {
	display   string
	canonical string
	kind      Kind
}

// Display returns the input spelling without surrounding ASCII whitespace. It
// is non-authoritative and never affects identity.
func (i ExpectedIdentity) Display() string { return i.display }

// Canonical returns the identity text: a lower-case A-label for a DNS name, or
// the canonical address text.
func (i ExpectedIdentity) Canonical() string { return i.canonical }

// Kind reports the canonical form of the identity.
func (i ExpectedIdentity) Kind() Kind { return i.kind }

// Field names the input that was rejected.
type Field string

const (
	// FieldConnectionHost names the connection host input.
	FieldConnectionHost Field = "connection host"
	// FieldExpectedIdentity names the expected identity input.
	FieldExpectedIdentity Field = "expected identity"
)

// Reason classifies why an input was rejected.
type Reason int

const (
	// ReasonEmpty means the input is blank after whitespace removal.
	ReasonEmpty Reason = iota + 1
	// ReasonWhitespaceOrControl means the input has embedded whitespace or a
	// control character.
	ReasonWhitespaceOrControl
	// ReasonURLOrPath means the input has a scheme, path, query, fragment or
	// user name.
	ReasonURLOrPath
	// ReasonHostPort means the input combines a host with a port.
	ReasonHostPort
	// ReasonWildcard means the input contains a wildcard.
	ReasonWildcard
	// ReasonLegacyNumericIP means the input is a numeric spelling whose meaning
	// depends on legacy parsing rules.
	ReasonLegacyNumericIP
	// ReasonInvalidIP means the input looks like an IP literal but is not valid.
	ReasonInvalidIP
	// ReasonInvalidName means the input is not a valid DNS name.
	ReasonInvalidName
	// ReasonZoneRequired means a link-local IPv6 connection has no interface scope.
	ReasonZoneRequired
	// ReasonZoneNotPermitted means an interface scope is attached to an address
	// that cannot carry one.
	ReasonZoneNotPermitted
	// ReasonZoneMalformed means the interface scope is empty or has characters
	// outside the accepted grammar.
	ReasonZoneMalformed
	// ReasonZoneInIdentity means an interface scope appears in an expected
	// identity, where it is never permitted.
	ReasonZoneInIdentity
)

// Error reports a rejected connection host or expected identity. The echoed
// input is escaped and bounded. A rejected parse returns no value.
type Error struct {
	Field  Field
	Reason Reason
	input  string
	detail string
}

// Error implements the error interface.
func (e *Error) Error() string {
	return string(e.Field) + " " + e.input + " rejected: " + e.detail
}

// parsed is the shared result of host parsing.
type parsed struct {
	display   string
	canonical string
	kind      Kind
	zone      string
}

// ParseConnectionHost validates a host that a probe would connect to. It
// accepts a DNS name, a dotted-decimal IPv4 address, or an IPv6 address with
// optional brackets. An IPv6 interface scope is accepted only on a link-local
// address, and it is then required.
func ParseConnectionHost(raw string) (ConnectionHost, error) {
	p, rejected := parseHost(FieldConnectionHost, raw, false)
	if rejected != nil {
		return ConnectionHost{}, rejected
	}
	return ConnectionHost{display: p.display, canonical: p.canonical, kind: p.kind, zone: p.zone}, nil
}

// ParseExpectedIdentity validates the DNS name or IP address that a certificate
// must match. It takes no port, URL, wildcard or interface scope. It is parsed
// independently of any connection host.
func ParseExpectedIdentity(raw string) (ExpectedIdentity, error) {
	p, rejected := parseHost(FieldExpectedIdentity, raw, true)
	if rejected != nil {
		return ExpectedIdentity{}, rejected
	}
	return ExpectedIdentity{display: p.display, canonical: p.canonical, kind: p.kind}, nil
}

// parseHost is the shared grammar. identity selects the expected-identity rules,
// which forbid an interface scope.
func parseHost(field Field, raw string, identity bool) (parsed, *Error) {
	text := strings.Trim(raw, asciiSpace)
	if text == "" {
		return parsed{}, newError(field, raw, ReasonEmpty, "enter a host name or IP address")
	}
	if strings.ContainsAny(text, asciiSpace) || hasControl(text) {
		return parsed{}, newError(field, raw, ReasonWhitespaceOrControl, "remove embedded spaces and control characters")
	}
	if strings.ContainsAny(text, "/?#@") {
		return parsed{}, newError(field, raw, ReasonURLOrPath, "enter only the host: no scheme, path, query, fragment or user name")
	}
	if strings.Contains(text, "*") {
		return parsed{}, newError(field, raw, ReasonWildcard, "wildcard patterns are not accepted; enter the exact name or address")
	}
	if strings.HasPrefix(text, "[") {
		if !strings.HasSuffix(text, "]") {
			if strings.Contains(text, "]") {
				return parsed{}, newError(field, raw, ReasonHostPort, "a port is not accepted here; give the port in its own field")
			}
			return parsed{}, newError(field, raw, ReasonInvalidIP, "a bracketed IPv6 address needs a closing ]")
		}
		inner := text[1 : len(text)-1]
		if strings.ContainsAny(inner, "[]") {
			return parsed{}, newError(field, raw, ReasonInvalidIP, "an IPv6 address takes one pair of brackets")
		}
		return parseIPv6(field, raw, text, inner, identity)
	}
	if strings.Contains(text, ":") {
		if strings.Count(text, ":") == 1 {
			return parsed{}, newError(field, raw, ReasonHostPort, "a port is not accepted here; give the port in its own field")
		}
		return parseIPv6(field, raw, text, text, identity)
	}
	if before, _, scoped := strings.Cut(text, "%"); scoped {
		if a, err := netip.ParseAddr(before); err == nil && a.Is4() {
			return parsed{}, newError(field, raw, ReasonZoneNotPermitted, "an interface scope applies only to IPv6 link-local addresses")
		}
	}
	if a, err := netip.ParseAddr(text); err == nil && a.Is4() {
		return parsed{display: text, canonical: a.String(), kind: KindIPv4}, nil
	}
	name := strings.TrimSuffix(text, ".")
	if numericLastLabel(name) {
		return parsed{}, newError(field, raw, ReasonLegacyNumericIP, "numeric spellings and IPv4 addresses with a trailing dot are not accepted; use dotted-decimal IPv4 such as 127.0.0.1")
	}
	canonical, rejected := canonicalName(field, raw, name)
	if rejected != nil {
		return parsed{}, rejected
	}
	return parsed{display: text, canonical: canonical, kind: KindDNSName}, nil
}

// parseIPv6 parses an IPv6 literal with an optional interface scope. display is
// the input spelling kept for display; addr is the literal without brackets.
func parseIPv6(field Field, raw, display, addr string, identity bool) (parsed, *Error) {
	addrText, zone, scoped := strings.Cut(addr, "%")
	ip, err := netip.ParseAddr(addrText)
	if err != nil || !ip.Is6() {
		return parsed{}, newError(field, raw, ReasonInvalidIP, "not a valid IPv6 address")
	}
	if scoped && identity {
		return parsed{}, newError(field, raw, ReasonZoneInIdentity, "an interface scope is never part of an expected identity; put the scope in the connection host instead, such as fe80::1%eth0")
	}
	// An IPv4-mapped address takes the IPv4 identity and policy classification.
	ip = ip.Unmap()
	if scoped {
		if !ip.Is6() || !ip.IsLinkLocalUnicast() {
			return parsed{}, newError(field, raw, ReasonZoneNotPermitted, "an interface scope is accepted only for an IPv6 link-local address (fe80::/10)")
		}
		if !validZone(zone) {
			return parsed{}, newError(field, raw, ReasonZoneMalformed, "the interface scope after % must be 1 or more ASCII letters, digits, '-', '_' or '.'")
		}
	} else if !identity && ip.Is6() && ip.IsLinkLocalUnicast() {
		return parsed{}, newError(field, raw, ReasonZoneRequired, "a link-local IPv6 connection needs an explicit interface scope, such as fe80::1%eth0")
	}
	if ip.Is4() {
		return parsed{display: display, canonical: ip.String(), kind: KindIPv4}, nil
	}
	p := parsed{display: display, canonical: ip.String(), kind: KindIPv6}
	if scoped {
		p.zone = zone
	}
	return p, nil
}

// canonicalName validates a DNS name after one terminal root dot was removed.
// The IDNA profile is non-transitional, with STD3 rules. Label and wire lengths
// are checked on the A-label output, because the profile does not check them.
func canonicalName(field Field, raw, name string) (string, *Error) {
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return "", newError(field, raw, ReasonInvalidName, "empty labels are not allowed: check for a leading dot or two adjacent dots")
		}
	}
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", newError(field, raw, ReasonInvalidName, "not a valid DNS name under non-transitional IDNA lookup rules with STD3 restrictions")
	}
	wire := 1 // the root's length octet
	for _, label := range strings.Split(ascii, ".") {
		if label == "" {
			return "", newError(field, raw, ReasonInvalidName, "empty labels are not allowed after IDNA processing")
		}
		if len(label) > maxLabelOctets {
			return "", newError(field, raw, ReasonInvalidName, "each DNS label must be 63 octets or fewer in ASCII form")
		}
		wire += len(label) + 1
	}
	if wire > maxWireOctets {
		return "", newError(field, raw, ReasonInvalidName, "the DNS name must be 255 octets or fewer on the wire, including length octets")
	}
	return ascii, nil
}

// numericLastLabel reports whether the final label is decimal digits or a 0x
// hexadecimal form. Such names are ambiguous with legacy numeric IPv4 spellings,
// which are rejected rather than resolved.
func numericLastLabel(name string) bool {
	last := name
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		last = name[i+1:]
	}
	if isDecimal(last) {
		return true
	}
	return len(last) >= 2 && (last[:2] == "0x" || last[:2] == "0X") && isHex(last[2:])
}

// validZone accepts only the interface-scope grammar: ASCII letters, digits, '-',
// '_' and '.', and at least one of them.
func validZone(zone string) bool {
	if zone == "" {
		return false
	}
	for i := 0; i < len(zone); i++ {
		c := zone[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if b := s[i]; b < 0x20 || b == 0x7f {
			return true
		}
	}
	return false
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}

func newError(field Field, raw string, reason Reason, detail string) *Error {
	return &Error{Field: field, Reason: reason, input: quote(raw), detail: detail}
}

// quote escapes and bounds operator-supplied text before it is shown.
func quote(s string) string {
	if len(s) > maxQuotedBytes {
		cut := maxQuotedBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "..."
	}
	return strconv.Quote(s)
}
