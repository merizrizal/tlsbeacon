package endpoint

import (
	"errors"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"
)

var invalidValues = errors.New("invalid endpoint values; provide required fields, positive durations and critical threshold below warning")

type TrustSelection struct {
	Profile  string
	Version  string
	Material string
}

type Values struct {
	Label    string
	Host     Name
	Port     int
	Identity Name
	Trust    TrustSelection
	Interval time.Duration
	Warning  time.Duration
	Critical time.Duration
	Enabled  bool
}

type CreateInput struct {
	Label, Host, Identity       string
	Port                        int
	Trust                       TrustSelection
	Interval, Warning, Critical *time.Duration
	Enabled                     *bool
}

type Patch struct {
	Label, Host, Identity       *string
	Port                        *int
	Trust                       *TrustSelection
	Interval, Warning, Critical *time.Duration
	Enabled                     *bool
}

type Decision struct {
	Values                Values
	Changed               bool
	NewMonitoringIdentity bool
}

func ParseDuration(input string) (time.Duration, error) {
	text := input
	if strings.HasPrefix(text, "+") {
		text = text[1:]
	}
	if text == "" {
		return 0, invalidValues
	}
	units := map[string]int64{"ns": 1, "us": 1000, "ms": 1000000, "s": int64(time.Second), "m": int64(time.Minute), "h": int64(time.Hour), "d": int64(24 * time.Hour)}
	total := new(big.Int)
	for len(text) > 0 {
		i, digits, dots := 0, 0, 0
		for i < len(text) && (text[i] >= '0' && text[i] <= '9' || text[i] == '.') {
			if text[i] == '.' {
				dots++
			} else {
				digits++
			}
			i++
		}
		if digits == 0 || dots > 1 {
			return 0, invalidValues
		}
		number := text[:i]
		j := i
		for j < len(text) && text[j] >= 'a' && text[j] <= 'z' {
			j++
		}
		unit, ok := units[text[i:j]]
		if !ok {
			return 0, invalidValues
		}
		fractionDigits := 0
		if dot := strings.IndexByte(number, '.'); dot >= 0 {
			fractionDigits = len(number) - dot - 1
			number = number[:dot] + number[dot+1:]
		}
		numerator, ok := new(big.Int).SetString(number, 10)
		if !ok {
			return 0, invalidValues
		}
		numerator.Mul(numerator, big.NewInt(unit))
		denominator := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(fractionDigits)), nil)
		quotient, remainder := new(big.Int), new(big.Int)
		quotient.QuoRem(numerator, denominator, remainder)
		if remainder.Sign() != 0 {
			return 0, invalidValues
		}
		total.Add(total, quotient)
		if !total.IsInt64() {
			return 0, invalidValues
		}
		text = text[j:]
	}
	if total.Sign() <= 0 {
		return 0, invalidValues
	}
	return time.Duration(total.Int64()), nil
}

func NewValues(input CreateInput) (Values, error) {
	host, err := NormalizeHost(input.Host)
	if err != nil {
		return Values{}, err
	}
	identity, err := NormalizeIdentity(input.Identity)
	if err != nil {
		return Values{}, err
	}
	v := Values{Label: input.Label, Host: host, Port: input.Port, Identity: identity, Trust: input.Trust, Interval: time.Hour, Warning: 30 * 24 * time.Hour, Critical: 7 * 24 * time.Hour, Enabled: true}
	if input.Interval != nil {
		v.Interval = *input.Interval
	}
	if input.Warning != nil {
		v.Warning = *input.Warning
	}
	if input.Critical != nil {
		v.Critical = *input.Critical
	}
	if input.Enabled != nil {
		v.Enabled = *input.Enabled
	}
	if !validValues(v) {
		return Values{}, invalidValues
	}
	return v, nil
}

func ApplyPatch(current Values, patch Patch) (Decision, error) {
	v := current
	if patch.Label != nil {
		v.Label = *patch.Label
	}
	if patch.Host != nil {
		host, err := NormalizeHost(*patch.Host)
		if err != nil {
			return Decision{}, err
		}
		if !sameName(host, current.Host) {
			v.Host = host
		}
	}
	if patch.Port != nil {
		v.Port = *patch.Port
	}
	if patch.Identity != nil {
		identity, err := NormalizeIdentity(*patch.Identity)
		if err != nil {
			return Decision{}, err
		}
		if !sameName(identity, current.Identity) {
			v.Identity = identity
		}
	}
	if patch.Trust != nil {
		v.Trust = *patch.Trust
	}
	if patch.Interval != nil {
		v.Interval = *patch.Interval
	}
	if patch.Warning != nil {
		v.Warning = *patch.Warning
	}
	if patch.Critical != nil {
		v.Critical = *patch.Critical
	}
	if patch.Enabled != nil {
		v.Enabled = *patch.Enabled
	}
	if !validValues(v) {
		return Decision{}, invalidValues
	}
	identityChanged := !sameName(v.Host, current.Host) || v.Port != current.Port || !sameName(v.Identity, current.Identity) || v.Trust != current.Trust
	return Decision{Values: v, Changed: v != current, NewMonitoringIdentity: identityChanged}, nil
}

func sameName(a, b Name) bool {
	return a.DNS == b.DNS && a.IP == b.IP && a.Scope == b.Scope
}

func validValues(v Values) bool {
	host, hostErr := NormalizeHost(v.Host.Original)
	identity, identityErr := NormalizeIdentity(v.Identity.Original)
	return hostErr == nil && identityErr == nil && sameName(host, v.Host) && sameName(identity, v.Identity) && utf8.ValidString(v.Label) && strings.TrimSpace(v.Label) != "" && v.Port >= 1 && v.Port <= 65535 && strings.TrimSpace(v.Trust.Profile) != "" && strings.TrimSpace(v.Trust.Version) != "" && v.Interval > 0 && v.Critical > 0 && v.Critical < v.Warning
}
