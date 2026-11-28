package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

// requiredCommands is the command surface the CLI must eventually dispatch:
// policy set/show; trust import/refresh/list; endpoint
// add/list/show/edit/enable/disable; inspect by registration ID.
var requiredCommands = []string{
	"policy set", "policy show",
	"trust import", "trust refresh", "trust list",
	"endpoint add", "endpoint list", "endpoint show", "endpoint edit", "endpoint enable", "endpoint disable",
	"inspect",
}

var wantStableCodes = []string{
	"invalid_input", "not_found", "configuration_error", "trust_configuration_error",
	"policy_configuration_error", "storage_error", "commit_outcome_unknown",
	"revision_conflict", "permission_error", "output_error", "internal_error",
}

type runOut struct {
	stdout, stderr string
	exit           int
}

func run(args ...string) runOut {
	var so, se bytes.Buffer
	code := Run(args, &so, &se)
	return runOut{so.String(), se.String(), code}
}

// decoded is a strictly decoded v1 envelope.
type decoded struct {
	SchemaVersion string
	Command       string
	Outcome       string
	Data          map[string]any
	DataIsNull    bool
	Error         map[string]string
	ErrorIsNull   bool
}

// decodeEnvelope requires stdout to be exactly one envelope plus a newline
// with exactly the five required fields, correctly typed.
func decodeEnvelope(t *testing.T, stdout string) decoded {
	t.Helper()
	if !strings.HasSuffix(stdout, "\n") || strings.Count(stdout, "\n") != 1 {
		t.Fatalf("stdout must be one line ending in a single newline, got %q", stdout)
	}
	dec := json.NewDecoder(strings.NewReader(stdout))
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		t.Fatalf("stdout is not one JSON object: %v: %q", err, stdout)
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Fatalf("stdout has data after the envelope: %q", stdout)
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	wantKeys := []string{"command", "data", "error", "outcome", "schema_version"}
	if !slices.Equal(keys, wantKeys) {
		t.Fatalf("envelope keys = %v, want exactly %v", keys, wantKeys)
	}
	var d decoded
	mustString := func(key string, dst *string) {
		if err := json.Unmarshal(raw[key], dst); err != nil {
			t.Fatalf("envelope field %q is not a string: %v", key, err)
		}
	}
	mustString("schema_version", &d.SchemaVersion)
	mustString("command", &d.Command)
	mustString("outcome", &d.Outcome)
	if string(raw["data"]) == "null" {
		d.DataIsNull = true
	} else if err := json.Unmarshal(raw["data"], &d.Data); err != nil || d.Data == nil {
		t.Fatalf("envelope data is neither null nor an object: %q", raw["data"])
	}
	if string(raw["error"]) == "null" {
		d.ErrorIsNull = true
	} else {
		edec := json.NewDecoder(bytes.NewReader(raw["error"]))
		edec.DisallowUnknownFields()
		var eb struct {
			Code    *string `json:"code"`
			Message *string `json:"message"`
			Action  *string `json:"action"`
		}
		if err := edec.Decode(&eb); err != nil || eb.Code == nil || eb.Message == nil || eb.Action == nil {
			t.Fatalf("envelope error must be exactly {code,message,action} strings: %q (%v)", raw["error"], err)
		}
		d.Error = map[string]string{"code": *eb.Code, "message": *eb.Message, "action": *eb.Action}
	}
	return d
}

func TestCommandTableMatchesRequiredSurface(t *testing.T) {
	got := commandNames()
	if !slices.Equal(got, requiredCommands) {
		t.Fatalf("commandNames() = %v, want %v", got, requiredCommands)
	}
	if !slices.Equal(stableErrorCodes, wantStableCodes) {
		t.Fatalf("stableErrorCodes = %v, want %v", stableErrorCodes, wantStableCodes)
	}
}

func TestEveryRequiredCommandFailsClosed(t *testing.T) {
	for _, name := range requiredCommands {
		words := strings.Fields(name)
		// Operands and options after the command are not interpreted yet; they
		// must never turn an unimplemented command into anything but a failure.
		variants := map[string][]string{
			"bare":     words,
			"operands": append(slices.Clone(words), "reg-123", "--label", "x", "--port", "443"),
		}
		for vname, base := range variants {
			for _, jsonPos := range []string{"none", "before", "after"} {
				args := slices.Clone(base)
				switch jsonPos {
				case "before":
					args = append([]string{"--json"}, args...)
				case "after":
					args = append(args, "--json")
				}
				got := run(args...)
				label := name + "/" + vname + "/json=" + jsonPos
				if got.exit != 2 {
					t.Errorf("%s: exit = %d, want 2", label, got.exit)
				}
				if jsonPos == "none" {
					if got.stdout != "" {
						t.Errorf("%s: human failure wrote to stdout: %q", label, got.stdout)
					}
					if !strings.Contains(got.stderr, "[internal_error]") || !strings.Contains(got.stderr, "not implemented") {
						t.Errorf("%s: stderr lacks the failure diagnostic: %q", label, got.stderr)
					}
					continue
				}
				if got.stderr != "" {
					t.Errorf("%s: JSON failure also wrote to stderr: %q", label, got.stderr)
				}
				d := decodeEnvelope(t, got.stdout)
				if d.SchemaVersion != "tlsbeacon.cli.v1" || d.Command != name {
					t.Errorf("%s: schema/command = %q/%q", label, d.SchemaVersion, d.Command)
				}
				if d.Outcome != "execution_failed" || !d.DataIsNull || d.ErrorIsNull {
					t.Errorf("%s: outcome=%q dataNull=%v errorNull=%v; unimplemented must be execution_failed with null data", label, d.Outcome, d.DataIsNull, d.ErrorIsNull)
				}
				if d.Error["code"] != "internal_error" || !slices.Contains(wantStableCodes, d.Error["code"]) {
					t.Errorf("%s: error code %q", label, d.Error["code"])
				}
				if d.Error["message"] == "" || d.Error["action"] == "" {
					t.Errorf("%s: error message/action empty", label)
				}
			}
		}
	}
}

func TestInvalidInputIsReportedAsExecutionFailure(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		command string
	}{
		{"no arguments", nil, ""},
		{"unknown command", []string{"bogus"}, ""},
		{"option before command", []string{"-x"}, ""},
		{"installation selector not supported yet", []string{"--installation", "/abs/path", "endpoint", "list"}, ""},
		{"family without subcommand", []string{"endpoint"}, "endpoint"},
		{"unknown subcommand", []string{"endpoint", "bogus"}, "endpoint"},
		{"option instead of subcommand", []string{"policy", "--label"}, "policy"},
		{"policy missing subcommand", []string{"policy"}, "policy"},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/json", func(t *testing.T) {
			got := run(append(slices.Clone(tc.args), "--json")...)
			if got.exit != 2 || got.stderr != "" {
				t.Fatalf("exit=%d stderr=%q, want 2 and empty stderr", got.exit, got.stderr)
			}
			d := decodeEnvelope(t, got.stdout)
			if d.Outcome != "execution_failed" || !d.DataIsNull || d.Command != tc.command || d.Error["code"] != "invalid_input" {
				t.Fatalf("envelope = %+v, want execution_failed/null data/command %q/invalid_input", d, tc.command)
			}
		})
		t.Run(tc.name+"/human", func(t *testing.T) {
			got := run(tc.args...)
			if got.exit != 2 || got.stdout != "" || !strings.Contains(got.stderr, "[invalid_input]") {
				t.Fatalf("exit=%d stdout=%q stderr=%q", got.exit, got.stdout, got.stderr)
			}
		})
	}
}

func TestHelp(t *testing.T) {
	for _, args := range [][]string{
		{"help"}, {"-h"}, {"--help"}, {"help", "endpoint"},
		{"endpoint", "add", "--help"}, {"bogus", "-h"}, {"--bogus", "--help"},
	} {
		got := run(args...)
		if got.exit != 0 || got.stderr != "" {
			t.Errorf("%v: exit=%d stderr=%q, want 0 and empty stderr", args, got.exit, got.stderr)
		}
		for _, f := range families {
			if !strings.Contains(got.stdout, f.synopsis) {
				t.Errorf("%v: help lacks %q", args, f.synopsis)
			}
		}
		for _, want := range []string{"--json", "Exit status", "Only help is available"} {
			if !strings.Contains(got.stdout, want) {
				t.Errorf("%v: help lacks %q", args, want)
			}
		}

		jsonGot := run(append(slices.Clone(args), "--json")...)
		if jsonGot.exit != 0 || jsonGot.stderr != "" {
			t.Errorf("%v --json: exit=%d stderr=%q", args, jsonGot.exit, jsonGot.stderr)
			continue
		}
		d := decodeEnvelope(t, jsonGot.stdout)
		if d.Command != "help" || d.Outcome != "success" || d.DataIsNull || !d.ErrorIsNull {
			t.Errorf("%v --json: envelope = %+v", args, d)
		}
		cmds, _ := d.Data["commands"].([]any)
		var names []string
		for _, c := range cmds {
			s, _ := c.(string)
			names = append(names, s)
		}
		if !slices.Equal(names, requiredCommands) {
			t.Errorf("%v --json: commands = %v, want %v", args, names, requiredCommands)
		}
	}
}

func TestArgumentsAreNeverEchoed(t *testing.T) {
	const canary = "secret-token-123"
	hostile := "bogus\x1b[31m\n" + canary
	for _, args := range [][]string{
		{hostile},
		{"inspect", hostile},
		{"endpoint", hostile},
		{"endpoint", "add", "--password", canary + "\x1b]0;x\x07"},
	} {
		for _, jsonMode := range []bool{false, true} {
			a := slices.Clone(args)
			if jsonMode {
				a = append(a, "--json")
			}
			got := run(a...)
			for _, out := range []string{got.stdout, got.stderr} {
				if strings.Contains(out, canary) || strings.ContainsRune(out, '\x1b') {
					t.Errorf("args %q (json=%v) were echoed: %q", a, jsonMode, out)
				}
			}
		}
	}
}

type errWriter struct {
	err   error
	calls int
}

func (w *errWriter) Write(p []byte) (int, error) { w.calls++; return 0, w.err }

type shortWriter struct{ calls int }

func (w *shortWriter) Write(p []byte) (int, error) { w.calls++; return len(p) / 2, nil }

type partialThenErrWriter struct {
	calls int
	wrote int
}

func (w *partialThenErrWriter) Write(p []byte) (int, error) {
	w.calls++
	w.wrote = len(p) / 2
	return w.wrote, errors.New("disk full")
}

func TestStdoutWriteFailureIsExit2WithStderrDiagnostic(t *testing.T) {
	commands := map[string][]string{
		"help":          {"help"},
		"unimplemented": {"endpoint", "list"},
	}
	writers := map[string]func() (io.Writer, func() int){
		"error": func() (io.Writer, func() int) {
			w := &errWriter{err: errors.New("no space left on device")}
			return w, func() int { return w.calls }
		},
		"short": func() (io.Writer, func() int) {
			w := &shortWriter{}
			return w, func() int { return w.calls }
		},
		"partial-then-error": func() (io.Writer, func() int) {
			w := &partialThenErrWriter{}
			return w, func() int { return w.calls }
		},
	}
	for cname, cmd := range commands {
		for wname, mk := range writers {
			t.Run(cname+"/"+wname+"/json", func(t *testing.T) {
				w, calls := mk()
				var se bytes.Buffer
				got := Run(append(slices.Clone(cmd), "--json"), w, &se)
				if got != 2 {
					t.Fatalf("exit = %d, want 2", got)
				}
				if calls() != 1 {
					t.Errorf("stdout received %d writes, want exactly 1 (no incremental output)", calls())
				}
				if !strings.Contains(se.String(), "[output_error]") {
					t.Errorf("stderr lacks the output_error diagnostic: %q", se.String())
				}
				if strings.Contains(se.String(), "schema_version") || strings.Contains(se.String(), "{") {
					t.Errorf("stderr must not carry a JSON envelope: %q", se.String())
				}
			})
		}
	}

	t.Run("help human", func(t *testing.T) {
		w := &errWriter{err: errors.New("broken pipe")}
		var se bytes.Buffer
		if got := Run([]string{"help"}, w, &se); got != 2 || !strings.Contains(se.String(), "[output_error]") {
			t.Fatalf("exit=%d stderr=%q", got, se.String())
		}
	})
	t.Run("human failure does not touch stdout", func(t *testing.T) {
		w := &errWriter{err: errors.New("never used")}
		var se bytes.Buffer
		if got := Run([]string{"endpoint", "list"}, w, &se); got != 2 || w.calls != 0 || !strings.Contains(se.String(), "[internal_error]") {
			t.Fatalf("exit=%d stdoutCalls=%d stderr=%q", got, w.calls, se.String())
		}
	})
}

func TestOutputCauseIsEscapedAndBounded(t *testing.T) {
	cause := errors.New("boom\x1b[31m\nINJECTED line " + strings.Repeat("x", 500))
	w := &errWriter{err: cause}
	var se bytes.Buffer
	if got := Run([]string{"help", "--json"}, w, &se); got != 2 {
		t.Fatalf("exit = %d, want 2", got)
	}
	out := se.String()
	if strings.ContainsRune(out, '\x1b') {
		t.Errorf("raw escape character reached stderr: %q", out)
	}
	if strings.Count(out, "\n") != 2 {
		t.Errorf("diagnostic must be exactly a message line and an action line, got %q", out)
	}
	if len(out) > 1200 {
		t.Errorf("diagnostic is not bounded: %d bytes", len(out))
	}
}

func TestStderrFailureDoesNotChangeExitStatus(t *testing.T) {
	for _, args := range [][]string{{"bogus"}, {"endpoint", "list"}} {
		se := &errWriter{err: errors.New("closed")}
		var so bytes.Buffer
		if got := Run(args, &so, se); got != 2 || so.Len() != 0 {
			t.Errorf("%v: exit=%d stdout=%q, want 2 and empty stdout", args, got, so.String())
		}
	}
	// A failing stdout with a failing stderr still exits 2 and does not panic.
	if got := Run([]string{"help"}, &errWriter{err: errors.New("a")}, &errWriter{err: errors.New("b")}); got != 2 {
		t.Errorf("exit = %d, want 2", got)
	}
}

func TestValidateRejectsInconsistentResponses(t *testing.T) {
	okFail := func() result { return failure("endpoint list", codeInternalError, "m", "a") }
	okSuccess := func() result { return helpResult() }

	cases := []struct {
		name   string
		mutate func() result
	}{
		{"wrong schema", func() result { r := okSuccess(); r.env.SchemaVersion = "tlsbeacon.cli.v2"; return r }},
		{"success without data", func() result { r := okSuccess(); r.env.Data = nil; return r }},
		{"success with error", func() result {
			r := okSuccess()
			r.env.Error = &errorBody{Code: codeInternalError, Message: "m", Action: "a"}
			return r
		}},
		{"success with exit 2", func() result { r := okSuccess(); r.exit = 2; return r }},
		{"completed inspection with exit 2", func() result {
			return result{env: envelope{SchemaVersion: schemaVersion, Outcome: outcomeInspectionCompleted, Data: map[string]any{}}, exit: 2}
		}},
		{"failure with data", func() result { r := okFail(); r.env.Data = map[string]any{}; return r }},
		{"failure without error", func() result { r := okFail(); r.env.Error = nil; return r }},
		{"failure with exit 0", func() result { r := okFail(); r.exit = 0; return r }},
		{"failure with exit 1", func() result { r := okFail(); r.exit = 1; return r }},
		{"failure without message", func() result { r := okFail(); r.env.Error.Message = ""; return r }},
		{"failure without action", func() result { r := okFail(); r.env.Error.Action = ""; return r }},
		{"failure with unlisted code", func() result { r := okFail(); r.env.Error.Code = "unimplemented"; return r }},
		{"unknown outcome", func() result { r := okSuccess(); r.env.Outcome = "ok"; return r }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.mutate()
			if err := r.validate(); err == nil {
				t.Fatalf("validate accepted %+v", r)
			}
			var so, se bytes.Buffer
			if got := emit(true, r, &so, &se); got != 2 || so.Len() != 0 || !strings.Contains(se.String(), "[internal_error]") {
				t.Fatalf("emit wrote an inconsistent response: exit=%d stdout=%q stderr=%q", got, so.String(), se.String())
			}
		})
	}

	for _, ok := range []result{
		okSuccess(), okFail(),
		{env: envelope{SchemaVersion: schemaVersion, Command: "inspect", Outcome: outcomeInspectionCompleted, Data: map[string]any{}}, exit: 0},
		{env: envelope{SchemaVersion: schemaVersion, Command: "inspect", Outcome: outcomeInspectionCompleted, Data: map[string]any{}}, exit: 1},
	} {
		if err := ok.validate(); err != nil {
			t.Errorf("validate rejected a consistent response %+v: %v", ok, err)
		}
	}
}

func TestEnvelopeSerializationKeepsAngleBracketsAndNull(t *testing.T) {
	var so, se bytes.Buffer
	res := failure("inspect", codeInvalidInput, "needs <registration-id> & more", "a")
	if got := emit(true, res, &so, &se); got != 2 {
		t.Fatalf("exit = %d", got)
	}
	out := so.String()
	if !strings.Contains(out, `"data":null`) || !strings.Contains(out, "<registration-id> & more") {
		t.Errorf("unexpected serialization: %q", out)
	}
	decodeEnvelope(t, out)
}
