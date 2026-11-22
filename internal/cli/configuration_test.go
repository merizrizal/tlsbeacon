package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/merizrizal/tlsbeacon/internal/policy"
	"github.com/merizrizal/tlsbeacon/internal/registry"
)

func TestCommandOptionParsing(t *testing.T) {
	options, failure := parseCommandOptions("trust import", []string{"--mode=custom", "--source", "first.pem", "--source=second.pem"})
	if failure != nil {
		t.Fatal("valid repeated source options rejected")
	}
	if got := options["mode"]; len(got) != 1 || got[0] != "custom" {
		t.Fatalf("mode = %#v", got)
	}
	if got := options["source"]; len(got) != 2 || got[0] != "first.pem" || got[1] != "second.pem" {
		t.Fatalf("sources = %#v", got)
	}
	for _, args := range [][]string{{"--unknown", "value"}, {"--mode", "custom", "--mode", "system"}, {"--mode"}, {"positional"}} {
		if _, failure := parseCommandOptions("trust import", args); failure == nil || failure.Code != "invalid_input" {
			t.Fatalf("arguments %q failure = %#v", args, failure)
		}
	}
}

func TestGlobalOptionParsing(t *testing.T) {
	jsonOutput, configPath, args, failure := parseGlobalArguments([]string{"endpoint", "add", "--json", "--config=/protected/local.json", "--label=--json"})
	if failure != nil || !jsonOutput || configPath != "/protected/local.json" || strings.Join(args, " ") != "endpoint add --label=--json" {
		t.Fatalf("parsed json=%v config=%q args=%q failure=%#v", jsonOutput, configPath, args, failure)
	}
	for _, input := range [][]string{{"--config"}, {"--config", "one", "--config", "two"}, {"--config=", "policy", "show"}} {
		if _, _, _, failure := parseGlobalArguments(input); failure == nil || failure.Code != "invalid_input" {
			t.Fatalf("arguments %q failure = %#v", input, failure)
		}
	}
	jsonOutput, configPath, args, failure = parseGlobalArguments([]string{"policy", "show", "--config=--json"})
	if failure != nil || jsonOutput || configPath != "--json" || strings.Join(args, " ") != "policy show" {
		t.Fatalf("config value was reinterpreted as a global option: json=%v config=%q args=%q failure=%#v", jsonOutput, configPath, args, failure)
	}
	jsonOutput, configPath, args, failure = parseGlobalArguments([]string{"policy", "show", "--config", "--json"})
	if failure != nil || jsonOutput || configPath != "--json" || strings.Join(args, " ") != "policy show" {
		t.Fatalf("separate config value was reinterpreted as a global option: json=%v config=%q args=%q failure=%#v", jsonOutput, configPath, args, failure)
	}
}

func TestMalformedConfigStillHonorsLaterJSONOption(t *testing.T) {
	cases := [][]string{
		{"policy", "show", "--config=", "--json"},
		{"policy", "show", "--config", "first", "--config", "second", "--json"},
		{"--json", "policy", "show", "--config="},
		{"policy", "show", "--json", "--config"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(args, &stdout, &stderr); code != 2 || stderr.Len() != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if strings.Count(stdout.String(), "\n") != 1 || !strings.HasSuffix(stdout.String(), "\n") {
				t.Fatalf("expected one JSON response line: %q", stdout.String())
			}
			var result map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatalf("invalid JSON response: %v", err)
			}
			failure, ok := result["error"].(map[string]any)
			if result["command"] != "policy show" || result["outcome"] != "execution_failed" || !ok || failure["code"] != "invalid_input" {
				t.Fatalf("unexpected response: %#v", result)
			}
		})
	}
}

func TestPolicyCLIJSONInput(t *testing.T) {
	parsed, err := parsePolicyInput(`{"version":1,"rules":[{"cidr":"127.7.8.9/8","port":443,"acknowledgements":["loopback"]}],"metadata":[]}`)
	if err != nil {
		t.Fatal("valid policy rejected")
	}
	expected, err := policy.New(&policy.Input{Version: policy.Version, Rules: []policy.Rule{{CIDR: "127.0.0.0/8", Port: 443, Acknowledge: policy.Loopback}}})
	if err != nil || !parsed.Equal(expected) {
		t.Fatal("policy input did not preserve canonical semantics")
	}
	view, err := policyViewFrom(parsed)
	if err != nil || len(view.Rules) != 1 || len(view.Rules[0].Acknowledgements) != 1 || view.Rules[0].Acknowledgements[0] != "loopback" {
		t.Fatalf("policy view = %#v, error %v", view, err)
	}
	for _, raw := range []string{
		`{"version":1,"rules":[],"unexpected":true}`,
		`{"version":1,"rules":[],"classification":"forged"}`,
		`{"version":1,"rules":[],"classification":""}`,
		`{"version":1,"rules":[{"cidr":"127.0.0.0/8","port":443,"acknowledgements":["unknown"]}]}`,
		`{"version":1,"rules":[]} {"version":1,"rules":[]}`,
		`{"rules":[]}`,
	} {
		if _, err := parsePolicyInput(raw); err == nil {
			t.Fatalf("invalid policy accepted: %s", raw)
		}
	}
}

func TestConfigurationJSONAndHumanControlOutput(t *testing.T) {
	const hostile = "operator\n\x1b[31m"
	view := endpointView{RegistrationID: "0123456789abcdef0123456789abcdef", Label: hostile, ConnectionHost: "host.example", Freshness: nil, FreshnessReason: "inspection_history_not_retained"}
	var stdout, stderr bytes.Buffer
	if got := writeConfigurationSuccess("endpoint show", true, &stdout, &stderr, map[string]any{"endpoint": view}, "", false); got != 0 || stderr.Len() != 0 {
		t.Fatalf("JSON output exit=%d stderr=%q", got, stderr.String())
	}
	if strings.Count(stdout.String(), "\n") != 1 || !strings.HasSuffix(stdout.String(), "\n") || strings.Contains(stdout.String(), hostile) {
		t.Fatalf("JSON output was not one escaped envelope: %q", stdout.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	data := envelope["data"].(map[string]any)
	endpointData := data["endpoint"].(map[string]any)
	if endpointData["freshness"] != nil || endpointData["freshness_reason"] != "inspection_history_not_retained" {
		t.Fatalf("registry freshness = %#v", endpointData)
	}

	stdout.Reset()
	human := "label: " + strconv.Quote(hostile) + "\n"
	if got := writeConfigurationSuccess("endpoint show", false, &stdout, &stderr, nil, human, false); got != 0 || strings.Contains(stdout.String(), hostile) || !strings.Contains(stdout.String(), `\n\x1b`) {
		t.Fatalf("human controls not escaped: exit=%d stdout=%q", got, stdout.String())
	}
}

func TestMutationOutputFailureGuidesReadback(t *testing.T) {
	for _, shortWrite := range []bool{false, true} {
		var stderr bytes.Buffer
		if got := writeConfigurationSuccess("endpoint add", true, failingConfigurationWriter{short: shortWrite}, &stderr, map[string]string{"result": "created"}, "", true); got != 2 {
			t.Fatalf("short=%v exit=%d", shortWrite, got)
		}
		if !strings.Contains(stderr.String(), "output_error") || !strings.Contains(stderr.String(), "list and reconcile the relevant records") || strings.Contains(stderr.String(), "secret detail") {
			t.Fatalf("unsafe mutation output diagnostic: %q", stderr.String())
		}
	}
}

type failingConfigurationWriter struct{ short bool }

func (w failingConfigurationWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("secret detail")
}

func TestStructuredCommitUnknownErrorMapping(t *testing.T) {
	failure := failureFromError(&registry.Error{Code: "commit_outcome_unknown", Message: "Commit outcome is unknown.", Action: "Read back the record before retrying."})
	if failure.Code != "commit_outcome_unknown" || !strings.Contains(failure.Action, "Read back") {
		t.Fatalf("unexpected mapped failure: %#v", failure)
	}
	var stderr bytes.Buffer
	if got := writeFailure("policy set", true, failingConfigurationWriter{}, &stderr, failure); got != 2 || !strings.Contains(stderr.String(), "list and reconcile the relevant records") {
		t.Fatalf("unknown-commit output failure lacks read-back guidance: exit=%d stderr=%q", got, stderr.String())
	}
}

func TestMalformedTrustPEMReturnsJSONFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("cannot protect malformed trust fixture directory")
	}
	path := filepath.Join(dir, "malformed.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN CERTIFICATE-----END CERTIFICATE-----"), 0600); err != nil {
		t.Fatal("cannot create malformed trust fixture")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal("cannot protect malformed trust fixture")
	}
	var stdout, stderr bytes.Buffer
	args := []string{"--json", "trust", "import", "--mode", "custom", "--source", path}
	if code := Run(args, &stdout, &stderr); code != 2 || stderr.Len() != 0 || strings.Count(stdout.String(), "\n") != 1 || !strings.HasSuffix(stdout.String(), "\n") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	failure, ok := result["error"].(map[string]any)
	if result["command"] != "trust import" || result["outcome"] != "execution_failed" || !ok || failure["code"] != "trust_configuration_error" || strings.Contains(stdout.String(), "panic") || strings.Contains(stderr.String(), "runtime error") {
		t.Fatalf("malformed trust source did not return a redacted CLI failure: %#v", result)
	}
}

func TestGlobalJSONFlagPreservesSeparateCommandValues(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		option     string
		jsonOutput bool
	}{
		{name: "separate label", args: []string{"endpoint", "add", "--label", "--json"}, option: "label"},
		{name: "inline label", args: []string{"endpoint", "add", "--label=--json"}, option: "label"},
		{name: "separate host", args: []string{"endpoint", "add", "--host", "--json"}, option: "host"},
		{name: "global output and separate label", args: []string{"--json", "endpoint", "add", "--label", "--json"}, option: "label", jsonOutput: true},
	} {
		t.Run(tc.name+" value parse", func(t *testing.T) {
			jsonOutput, configPath, args, failure := parseGlobalArguments(tc.args)
			if failure != nil || configPath != "" || jsonOutput != tc.jsonOutput {
				t.Fatalf("parsed json=%v config=%q args=%q failure=%#v", jsonOutput, configPath, args, failure)
			}
			options, failure := parseCommandOptions("endpoint add", args[2:])
			if failure != nil || len(options[tc.option]) != 1 || options[tc.option][0] != "--json" {
				t.Fatalf("command value %q was not preserved: options=%#v failure=%#v", tc.option, options, failure)
			}
		})
	}

	clearDatabaseEnvironment(t)
	t.Setenv("HOME", protectedDatabaseTestDir(t))
	dir := protectedDatabaseTestDir(t)
	configPath := filepath.Join(dir, "local.json")
	if err := os.WriteFile(configPath, []byte(`{"database_url":"host=localhost port=invalid user=fixture dbname=fixture sslmode=disable"}`), 0600); err != nil {
		t.Fatal("cannot create isolated CLI configuration")
	}
	if err := os.Chmod(configPath, 0600); err != nil {
		t.Fatal("cannot protect isolated CLI configuration")
	}

	base := []string{"endpoint", "add", "--host", "host.example", "--port", "443", "--identity", "host.example", "--trust-profile", "00000000000000000000000000000000", "--trust-version", "00000000000000000000000000000000", "--interval", "1h", "--warning", "1h", "--critical", "2h", "--enabled", "true"}
	cases := []struct {
		name       string
		args       []string
		jsonOutput bool
	}{
		{name: "separate label value", args: append([]string{"--config", configPath, "endpoint", "add", "--label", "--json"}, base[2:]...)},
		{name: "inline label value", args: append([]string{"--config", configPath, "endpoint", "add", "--label=--json"}, base[2:]...)},
		{name: "separate host value", args: append([]string{"--config", configPath, "endpoint", "add", "--label", "label", "--host", "--json"}, base[4:]...)},
		{name: "global JSON before command", args: append([]string{"--json", "--config", configPath, "endpoint", "add", "--label", "--json"}, base[2:]...), jsonOutput: true},
		{name: "global JSON after command", args: append([]string{"--config", configPath, "endpoint", "add", "--label=--json"}, append(base[2:], "--json")...), jsonOutput: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(tc.args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if tc.jsonOutput {
				if stderr.Len() != 0 || strings.Count(stdout.String(), "\n") != 1 || !strings.HasSuffix(stdout.String(), "\n") {
					t.Fatalf("expected one JSON response: stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
				var result map[string]any
				if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
					t.Fatalf("invalid JSON response: %v", err)
				}
				failure, ok := result["error"].(map[string]any)
				if result["command"] != "endpoint add" || result["outcome"] != "execution_failed" || !ok || failure["code"] != "configuration_error" {
					t.Fatalf("command value or global output flag was misparsed: %#v", result)
				}
			} else if stdout.Len() != 0 || !strings.Contains(stderr.String(), "configuration_error") {
				t.Fatalf("command-option value changed output mode or command parsing: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}
