// Package cli implements the tlsbeacon command-line boundary: argument
// dispatch, the versioned JSON response envelope, human rendering and
// output-failure handling.
//
// Commands that are recognized but not implemented fail closed: they exit with
// status 2 and an execution-failure envelope, and perform no operation. They
// never report success or a completed inspection.
package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const schemaVersion = "tlsbeacon.cli.v1"

// Envelope outcomes of schema version tlsbeacon.cli.v1.
const (
	outcomeSuccess             = "success"
	outcomeInspectionCompleted = "inspection_completed"
	outcomeExecutionFailed     = "execution_failed"
)

// Process exit statuses: 0 successful operation, 1 completed adverse
// inspection, 2 execution failure.
const (
	exitSuccess = 0
	exitAdverse = 1
	exitFailure = 2
)

// Stable execution-failure codes that this package currently emits.
const (
	codeInvalidInput  = "invalid_input"
	codeOutputError   = "output_error"
	codeInternalError = "internal_error"
)

// stableErrorCodes is the complete set of stable v1 execution-failure codes.
// An envelope carrying any other code is never written.
var stableErrorCodes = []string{
	codeInvalidInput,
	"not_found",
	"configuration_error",
	"trust_configuration_error",
	"policy_configuration_error",
	"storage_error",
	"commit_outcome_unknown",
	"revision_conflict",
	"permission_error",
	codeOutputError,
	codeInternalError,
}

// maxCauseBytes bounds how much of an underlying error text is reported.
const maxCauseBytes = 200

type envelope struct {
	SchemaVersion string         `json:"schema_version"`
	Command       string         `json:"command"`
	Outcome       string         `json:"outcome"`
	Data          map[string]any `json:"data"`
	Error         *errorBody     `json:"error"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Action  string `json:"action"`
}

// result is one complete response: the envelope, the exit status that goes
// with it, and the human rendering used when the outcome is not a failure.
type result struct {
	env   envelope
	exit  int
	human string
}

// validate rejects any response whose envelope fields, outcome, exit status
// or error code are inconsistent with the v1 contract.
func (r result) validate() error {
	e := r.env
	if e.SchemaVersion != schemaVersion {
		return errors.New("envelope schema_version is not " + schemaVersion)
	}
	switch e.Outcome {
	case outcomeSuccess:
		if e.Data == nil || e.Error != nil {
			return errors.New("success envelope needs object data and null error")
		}
		if r.exit != exitSuccess {
			return errors.New("success envelope needs exit status 0")
		}
	case outcomeInspectionCompleted:
		if e.Data == nil || e.Error != nil {
			return errors.New("inspection_completed envelope needs object data and null error")
		}
		if r.exit != exitSuccess && r.exit != exitAdverse {
			return errors.New("inspection_completed envelope needs exit status 0 or 1")
		}
	case outcomeExecutionFailed:
		if e.Data != nil || e.Error == nil {
			return errors.New("execution_failed envelope needs null data and an error")
		}
		if r.exit != exitFailure {
			return errors.New("execution_failed envelope needs exit status 2")
		}
		if e.Error.Message == "" || e.Error.Action == "" {
			return errors.New("execution_failed error needs a message and an action")
		}
		if !slices.Contains(stableErrorCodes, e.Error.Code) {
			return errors.New("execution_failed error code is not a stable v1 code")
		}
	default:
		return errors.New("envelope outcome is not a v1 outcome")
	}
	return nil
}

// family is one top-level command family and its subcommands.
type family struct {
	name     string
	subs     []string
	synopsis string
}

// families lists the command families the CLI must eventually dispatch.
var families = []family{
	{"policy", []string{"set", "show"}, "policy set | show"},
	{"trust", []string{"import", "refresh", "list"}, "trust import | refresh | list"},
	{"endpoint", []string{"add", "list", "show", "edit", "enable", "disable"}, "endpoint add | list | show | edit | enable | disable"},
	{"inspect", nil, "inspect <registration-id>"},
}

func lookupFamily(name string) (family, bool) {
	for _, f := range families {
		if f.name == name {
			return f, true
		}
	}
	return family{}, false
}

// commandNames returns the canonical command names in help order.
func commandNames() []string {
	var names []string
	for _, f := range families {
		if len(f.subs) == 0 {
			names = append(names, f.name)
			continue
		}
		for _, s := range f.subs {
			names = append(names, f.name+" "+s)
		}
	}
	return names
}

// Run executes one command line (without the program name), writes its
// response to stdout or stderr, and returns the process exit status.
//
// Standard output carries the result: with --json exactly one envelope plus a
// newline and nothing else. Standard error carries human failure diagnostics.
// If the result cannot be written to standard output the status is 2 and a
// diagnostic is written to standard error.
func Run(args []string, stdout, stderr io.Writer) int {
	jsonMode, help, rest := splitArgs(args)
	return emit(jsonMode, dispatch(help, rest), stdout, stderr)
}

// splitArgs separates the global options from the remaining tokens. --json
// and the help options are recognized anywhere in the command line. The
// remaining tokens are not interpreted beyond command selection.
func splitArgs(args []string) (jsonMode, help bool, rest []string) {
	for _, a := range args {
		switch a {
		case "--json":
			jsonMode = true
		case "-h", "--help":
			help = true
		default:
			rest = append(rest, a)
		}
	}
	return jsonMode, help, rest
}

func dispatch(help bool, rest []string) result {
	if help || (len(rest) > 0 && rest[0] == "help") {
		return helpResult()
	}
	if len(rest) == 0 {
		return failure("", codeInvalidInput,
			"no command was given",
			"Run 'tlsbeacon help' to list the supported commands.")
	}
	if strings.HasPrefix(rest[0], "-") {
		return failure("", codeInvalidInput,
			"an option appeared where a command was expected, or it is not supported",
			"Run 'tlsbeacon help' to list the supported commands and options.")
	}
	fam, ok := lookupFamily(rest[0])
	if !ok {
		return failure("", codeInvalidInput,
			"unknown command",
			"Run 'tlsbeacon help' to list the supported commands.")
	}
	if len(fam.subs) == 0 {
		return notImplemented(fam.name)
	}
	if len(rest) < 2 || !slices.Contains(fam.subs, rest[1]) {
		return failure(fam.name, codeInvalidInput,
			"missing or unknown subcommand for '"+fam.name+"'",
			"Run 'tlsbeacon help' to list the subcommands of '"+fam.name+"'.")
	}
	return notImplemented(fam.name + " " + rest[1])
}

func failure(command, code, message, action string) result {
	return result{
		env: envelope{
			SchemaVersion: schemaVersion,
			Command:       command,
			Outcome:       outcomeExecutionFailed,
			Error:         &errorBody{Code: code, Message: message, Action: action},
		},
		exit: exitFailure,
	}
}

// notImplemented is the fail-closed response for a recognized command whose
// behavior does not exist yet. It reads, connects to and changes nothing.
func notImplemented(command string) result {
	return failure(command, codeInternalError,
		"'"+command+"' is not implemented in this build; no operation was performed",
		"Use a build that implements this command. Nothing was read, connected to or changed.")
}

func helpResult() result {
	return result{
		env: envelope{
			SchemaVersion: schemaVersion,
			Command:       "help",
			Outcome:       outcomeSuccess,
			Data:          map[string]any{"commands": commandNames()},
		},
		exit:  exitSuccess,
		human: helpText(),
	}
}

func helpText() string {
	var b strings.Builder
	b.WriteString("Usage: tlsbeacon [--json] <command> [arguments]\n\nCommands:\n")
	for _, f := range families {
		b.WriteString("  " + f.synopsis + "\n")
	}
	b.WriteString("\nOptions:\n")
	b.WriteString("  --json       write one tlsbeacon.cli.v1 JSON envelope to standard output\n")
	b.WriteString("  -h, --help   show this help\n")
	b.WriteString("\nExit status:\n")
	b.WriteString("  0  successful operation\n")
	b.WriteString("  1  completed inspection with adverse findings\n")
	b.WriteString("  2  execution failure\n")
	b.WriteString("\nOnly help is available in this build. Every other command exits with status 2\n")
	b.WriteString("without reading, connecting to or changing anything.\n")
	return b.String()
}

// emit validates a response, writes it, and returns the exit status.
// An inconsistent response is never written. A response that cannot be
// delivered to its destination yields exit status 2.
func emit(jsonMode bool, res result, stdout, stderr io.Writer) int {
	if err := res.validate(); err != nil {
		diagnose(stderr, codeInternalError,
			"the response failed an internal consistency check and was not written: "+err.Error(),
			"No result was produced. This is a defect in the tool; report it.")
		return exitFailure
	}

	var payload []byte
	toStdout := true
	switch {
	case jsonMode:
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(res.env); err != nil {
			diagnose(stderr, codeInternalError,
				"the response could not be encoded and was not written",
				"No result was produced. This is a defect in the tool; report it.")
			return exitFailure
		}
		payload = buf.Bytes()
	case res.env.Error != nil:
		payload = []byte(humanFailure(*res.env.Error))
		toStdout = false
	default:
		payload = []byte(res.human)
	}

	if toStdout {
		if err := writeAll(stdout, payload); err != nil {
			diagnose(stderr, codeOutputError,
				"could not write the result to standard output: "+quoteCause(err),
				"The result was not delivered. Fix the standard output destination and rerun the command. "+
					"If an earlier command may have changed configuration, read the current configuration back before repeating that change.")
			return exitFailure
		}
		return res.exit
	}
	if err := writeAll(stderr, payload); err != nil {
		return exitFailure
	}
	return res.exit
}

// writeAll performs a single write so that a failed delivery never follows
// partial output produced by this package itself.
func writeAll(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

func humanFailure(e errorBody) string {
	return "tlsbeacon: error [" + e.Code + "]: " + e.Message + "\n  action: " + e.Action + "\n"
}

// diagnose writes a human diagnostic to stderr. Its own failure is ignored
// because there is nowhere left to report it; the exit status is unaffected.
func diagnose(stderr io.Writer, code, message, action string) {
	_ = writeAll(stderr, []byte(humanFailure(errorBody{Code: code, Message: message, Action: action})))
}

// quoteCause renders an underlying error text bounded and with control
// characters escaped, so it cannot inject terminal control sequences or extra
// lines into a diagnostic.
func quoteCause(err error) string {
	s := err.Error()
	if len(s) > maxCauseBytes {
		cut := maxCauseBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "..."
	}
	return strconv.QuoteToGraphic(s)
}
