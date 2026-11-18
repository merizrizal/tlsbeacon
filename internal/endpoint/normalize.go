package endpoint

import (
	"errors"
	"net/netip"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

type Name struct {
	Original string
	DNS      string
	IP       netip.Addr
	Scope    string
}

var lookupProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.StrictDomainName(true),
	idna.BidiRule(),
	idna.VerifyDNSLength(true),
)

var invalidHost = errors.New("invalid connection host; provide a DNS name or IP address without a port or URL")
var invalidIdentity = errors.New("invalid expected identity; provide a DNS name or IP address without a port, URL, wildcard or zone; put any interface scope in the connection host")

func NormalizeHost(input string) (Name, error) {
	value, err := normalize(input, true)
	if err != nil {
		return Name{}, invalidHost
	}
	return value, nil
}

func NormalizeIdentity(input string) (Name, error) {
	value, err := normalize(input, false)
	if err != nil {
		return Name{}, invalidIdentity
	}
	return value, nil
}

func normalize(input string, allowScope bool) (Name, error) {
	text := strings.Trim(input, " \t\n\r\v\f")
	if text == "" || strings.ContainsAny(text, "/@\\*") || strings.IndexFunc(text, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return Name{}, invalidHost
	}
	result := Name{Original: input}
	bracketed := strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]")
	if bracketed {
		text = text[1 : len(text)-1]
	}
	if addr, err := netip.ParseAddr(text); err == nil {
		if bracketed && !addr.Is6() {
			return Name{}, invalidHost
		}
		scope := addr.Zone()
		if scope != "" && (!allowScope || addr.Is4In6() || strings.ContainsAny(scope, "%[]")) {
			return Name{}, invalidHost
		}
		result.IP = addr.WithZone("").Unmap()
		result.Scope = scope
		return result, nil
	}
	if bracketed || strings.ContainsAny(text, ":%[]") {
		return Name{}, invalidHost
	}
	for _, dot := range []string{".", "。", "．", "｡"} {
		if strings.HasSuffix(text, dot) {
			text = strings.TrimSuffix(text, dot)
			break
		}
	}
	ascii, err := lookupProfile.ToASCII(text)
	if err != nil {
		return Name{}, invalidHost
	}
	ascii = strings.TrimSuffix(strings.ToLower(ascii), ".")
	if ascii == "" || ambiguousNumeric(ascii) {
		return Name{}, invalidHost
	}
	result.DNS = ascii
	return result, nil
}

func ambiguousNumeric(name string) bool {
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return true
		}
		digits := label
		hex := strings.HasPrefix(digits, "0x")
		if hex {
			digits = digits[2:]
		}
		if digits == "" {
			return false
		}
		for _, c := range digits {
			if c >= '0' && c <= '9' || hex && c >= 'a' && c <= 'f' {
				continue
			}
			return false
		}
	}
	return true
}
