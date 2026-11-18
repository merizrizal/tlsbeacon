package endpoint

import (
	"go/parser"
	"go/token"
	"strconv"
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }

func exampleInput() CreateInput {
	return CreateInput{Label: "  例  ", Host: "Example.COM.", Port: 443, Identity: "Service.Example.", Trust: TrustSelection{Profile: "profile", Version: "v1", Material: "digest1"}}
}

func TestExactDurations(t *testing.T) {
	valid := map[string]time.Duration{
		"1ns": 1, "1us": time.Microsecond, "1ms": time.Millisecond,
		"1s": time.Second, "1m": time.Minute, "1h": time.Hour, "1d": 24 * time.Hour,
		".5s": 500 * time.Millisecond, "1.000000001s": time.Second + 1,
		"0.001us": 1, "0.000000000125d": 10800,
		"1h30m0.5s": time.Hour + 30*time.Minute + 500*time.Millisecond,
		"+1ns":      1, "09s": 9 * time.Second, "9223372036854775807ns": time.Duration(1<<63 - 1),
		"9223372036.854775807s": time.Duration(1<<63 - 1),
	}
	for input, want := range valid {
		t.Run(input, func(t *testing.T) {
			got, err := ParseDuration(input)
			if err != nil || got != want {
				t.Fatalf("got %v, %v; want %v", got, err, want)
			}
		})
	}
	for _, input := range []string{"", "0", "0s", "-1ns", "1", "ns", ".s", "1..2s", "1e3s", "1µs", "1 s", "0.1ns", "0.0001us", "9223372036854775808ns", "9223372036.854775808s", "9223372036854775807ns1ns", "106752d", "1s-1ns"} {
		t.Run("invalid/"+input, func(t *testing.T) {
			if got, err := ParseDuration(input); err == nil || got != 0 {
				t.Fatalf("accepted %q: %v %v", input, got, err)
			}
		})
	}
}

func TestCreateValues(t *testing.T) {
	input := exampleInput()
	v, err := NewValues(input)
	if err != nil || v.Label != input.Label || v.Host.DNS != "example.com" || v.Identity.DNS != "service.example" || v.Port != 443 || v.Trust != input.Trust || v.Interval != time.Hour || v.Warning != 30*24*time.Hour || v.Critical != 7*24*time.Hour || !v.Enabled {
		t.Fatalf("defaults: %#v %v", v, err)
	}
	input.Interval, input.Warning, input.Critical, input.Enabled = ptr(time.Nanosecond), ptr(10*time.Hour), ptr(time.Hour), ptr(false)
	v, err = NewValues(input)
	if err != nil || v.Interval != 1 || v.Warning != 10*time.Hour || v.Critical != time.Hour || v.Enabled {
		t.Fatalf("explicit: %#v %v", v, err)
	}
	input.Host = "192.0.2.1"
	if v, err = NewValues(input); err != nil || !v.Host.IP.IsValid() || v.Identity.DNS != "service.example" {
		t.Fatalf("distinct IP host and DNS identity: %#v %v", v, err)
	}
	for i := 0; i < 101; i++ {
		if _, err := NewValues(input); err != nil {
			t.Fatalf("duplicate %d: %v", i, err)
		}
	}
}

func TestCreateRejectsInvalid(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*CreateInput)
	}{
		{"blank label", func(v *CreateInput) { v.Label = "\u2003" }}, {"invalid unicode", func(v *CreateInput) { v.Label = "\xff" }},
		{"host", func(v *CreateInput) { v.Host = "" }}, {"identity", func(v *CreateInput) { v.Identity = "" }},
		{"port zero", func(v *CreateInput) { v.Port = 0 }}, {"port high", func(v *CreateInput) { v.Port = 65536 }},
		{"profile", func(v *CreateInput) { v.Trust.Profile = "" }}, {"version", func(v *CreateInput) { v.Trust.Version = "" }},
		{"interval", func(v *CreateInput) { v.Interval = ptr(time.Duration(0)) }}, {"critical zero", func(v *CreateInput) { v.Critical = ptr(time.Duration(0)) }},
		{"equal", func(v *CreateInput) { v.Warning = ptr(7 * 24 * time.Hour) }}, {"reversed", func(v *CreateInput) { v.Warning = ptr(time.Hour) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := exampleInput()
			tc.mutate(&v)
			if _, err := NewValues(v); err == nil {
				t.Fatal("invalid values accepted")
			}
		})
	}
}

func TestPatchDecisions(t *testing.T) {
	base, err := NewValues(exampleInput())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name              string
		patch             Patch
		changed, identity bool
	}{
		{"omitted", Patch{}, false, false},
		{"label", Patch{Label: ptr("different")}, true, false},
		{"host equivalent", Patch{Host: ptr("EXAMPLE.com")}, false, false},
		{"host changed", Patch{Host: ptr("else.example")}, true, true},
		{"port", Patch{Port: ptr(444)}, true, true},
		{"identity equivalent", Patch{Identity: ptr("service.example")}, false, false},
		{"identity", Patch{Identity: ptr("other.example")}, true, true},
		{"trust profile", Patch{Trust: ptr(TrustSelection{"other", "v1", "digest1"})}, true, true},
		{"trust version", Patch{Trust: ptr(TrustSelection{"profile", "v2", "digest1"})}, true, true},
		{"trust material", Patch{Trust: ptr(TrustSelection{"profile", "v1", "digest2"})}, true, true},
		{"interval", Patch{Interval: ptr(2 * time.Hour)}, true, false},
		{"warning", Patch{Warning: ptr(31 * 24 * time.Hour)}, true, false},
		{"critical", Patch{Critical: ptr(6 * 24 * time.Hour)}, true, false},
		{"disable", Patch{Enabled: ptr(false)}, true, false},
		{"already enabled", Patch{Enabled: ptr(true)}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := ApplyPatch(base, tc.patch)
			if err != nil || d.Changed != tc.changed || d.NewMonitoringIdentity != tc.identity {
				t.Fatalf("decision %#v, %v", d, err)
			}
			if !tc.changed && d.Values != base {
				t.Fatal("no-op changed effective values or spelling")
			}
		})
	}
	disabled, err := ApplyPatch(base, Patch{Enabled: ptr(false)})
	if err != nil {
		t.Fatal(err)
	}
	repeat, err := ApplyPatch(disabled.Values, Patch{Enabled: ptr(false)})
	if err != nil || repeat.Changed || repeat.NewMonitoringIdentity {
		t.Fatal("repeated disable changed")
	}
	reenabled, err := ApplyPatch(disabled.Values, Patch{Enabled: ptr(true)})
	if err != nil || !reenabled.Changed || reenabled.NewMonitoringIdentity {
		t.Fatal("reenable decision")
	}
	other, err := ApplyPatch(base, Patch{Host: ptr("else.example")})
	if err != nil {
		t.Fatal(err)
	}
	revert, err := ApplyPatch(other.Values, Patch{Host: ptr("example.com")})
	if err != nil || !revert.Changed || !revert.NewMonitoringIdentity {
		t.Fatal("revert requires a fresh monitoring identity")
	}
}

func TestPatchCanonicalNamesAndScope(t *testing.T) {
	input := exampleInput()
	input.Host = "[fe80::1%eth0]"
	input.Identity = "BÜCHER.example"
	base, err := NewValues(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, patch := range []Patch{{Host: ptr("fe80:0:0:0:0:0:0:1%eth0")}, {Identity: ptr("bu\u0308cher.example.")}} {
		d, err := ApplyPatch(base, patch)
		if err != nil || d.Changed || d.Values != base {
			t.Fatalf("canonical equivalence: %#v %v", d, err)
		}
	}
	d, err := ApplyPatch(base, Patch{Host: ptr("fe80::1%eth1")})
	if err != nil || !d.NewMonitoringIdentity {
		t.Fatal("scope change not recognized")
	}
	input.Host = "::ffff:192.0.2.1"
	input.Identity = "::ffff:192.0.2.1"
	base, err = NewValues(input)
	if err != nil {
		t.Fatal(err)
	}
	d, err = ApplyPatch(base, Patch{Host: ptr("192.0.2.1"), Identity: ptr("192.0.2.1")})
	if err != nil || d.Changed || d.Values != base {
		t.Fatal("mapped equivalent changed")
	}
}

func TestPatchRejectsClearingAndInvalid(t *testing.T) {
	base, err := NewValues(exampleInput())
	if err != nil {
		t.Fatal(err)
	}
	broken := base
	broken.Host = Name{}
	if _, err := ApplyPatch(broken, Patch{}); err == nil {
		t.Fatal("invalid current host accepted")
	}
	broken = base
	broken.Identity = Name{}
	if _, err := ApplyPatch(broken, Patch{}); err == nil {
		t.Fatal("invalid current identity accepted")
	}
	patches := []Patch{{Label: ptr("")}, {Host: ptr("")}, {Identity: ptr("")}, {Port: ptr(0)}, {Trust: ptr(TrustSelection{})}, {Interval: ptr(time.Duration(0))}, {Warning: ptr(base.Critical)}, {Critical: ptr(base.Warning)}, {Critical: ptr(-time.Nanosecond)}}
	for i, p := range patches {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if _, err := ApplyPatch(base, p); err == nil {
				t.Fatal("invalid patch accepted")
			}
		})
	}
}

func TestValuesHaveNoNetworkImports(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "values.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"errors": true, "math/big": true, "strings": true, "time": true, "unicode/utf8": true}
	for _, spec := range file.Imports {
		name, err := strconv.Unquote(spec.Path.Value)
		if err != nil || !allowed[name] {
			t.Fatalf("unexpected import %s", spec.Path.Value)
		}
	}
}
