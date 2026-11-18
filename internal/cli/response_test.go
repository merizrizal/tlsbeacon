package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSONFailureEnvelope(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		command string
	}{
		{"known command", []string{"endpoint", "add", "--json", "private-argument"}, "endpoint add"},
		{"inspection", []string{"--json", "inspect", "private-argument"}, "inspect"},
		{"unknown command", []string{"--json", "private-argument"}, "unknown"},
		{"missing command", []string{"--json"}, "tlsbeacon"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := Run(tc.args, &stdout, &stderr); got != 2 {
				t.Fatalf("exit = %d, want 2", got)
			}
			if stderr.Len() != 0 || !strings.HasSuffix(stdout.String(), "\n") || strings.Count(stdout.String(), "\n") != 1 {
				t.Fatalf("unexpected streams: stdout %q stderr %q", stdout.String(), stderr.String())
			}
			if strings.Contains(stdout.String(), "private-argument") {
				t.Fatal("untrusted argument leaked")
			}
			var result map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if len(result) != 5 || result["schema_version"] != "tlsbeacon.cli.v1" || result["command"] != tc.command || result["outcome"] != "execution_failed" || result["data"] != nil {
				t.Fatalf("unexpected envelope: %#v", result)
			}
			failure, ok := result["error"].(map[string]any)
			if !ok || len(failure) != 3 || failure["code"] != "invalid_input" {
				t.Fatalf("unexpected error: %#v", result["error"])
			}
			for _, key := range []string{"message", "action"} {
				if value, ok := failure[key].(string); !ok || value == "" {
					t.Fatalf("missing string %s: %#v", key, failure)
				}
			}
		})
	}
}

func TestHelpStreamsAndJSONSuccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run([]string{"--help"}, &stdout, &stderr); got != 0 || stderr.Len() != 0 || stdout.String() != helpText {
		t.Fatalf("human help: exit %d stdout %q stderr %q", got, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if got := Run([]string{"--json", "help"}, &stdout, &stderr); got != 0 || stderr.Len() != 0 {
		t.Fatalf("JSON help: exit %d stderr %q", got, stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	data, ok := result["data"].(map[string]any)
	if len(result) != 5 || result["schema_version"] != "tlsbeacon.cli.v1" || result["command"] != "help" || result["outcome"] != "success" || result["error"] != nil || !ok || data["help"] != helpText || !strings.HasSuffix(stdout.String(), "\n") || strings.Count(stdout.String(), "\n") != 1 {
		t.Fatalf("unexpected JSON help: %#v", result)
	}
}

func TestHumanFailureUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run([]string{"inspect", "private-argument"}, &stdout, &stderr); got != 2 || stdout.Len() != 0 || !strings.HasSuffix(stderr.String(), "\n") || strings.Contains(stderr.String(), "private-argument") {
		t.Fatalf("exit %d stdout %q stderr %q", got, stdout.String(), stderr.String())
	}
}

func TestExecutableHelpAndUnsupportedCommand(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "tlsbeacon")
	build := exec.Command("go", "build", "-o", binary, "./cmd/tlsbeacon")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, output)
	}

	help := exec.Command(binary, "--help")
	var helpOut, helpErr bytes.Buffer
	help.Stdout, help.Stderr = &helpOut, &helpErr
	if err := help.Run(); err != nil || helpOut.String() != helpText || helpErr.Len() != 0 {
		t.Fatalf("help: %v stdout=%q stderr=%q", err, helpOut.String(), helpErr.String())
	}

	unsupported := exec.Command(binary, "--json", "inspect", "private-argument")
	var stdout, stderr bytes.Buffer
	unsupported.Stdout, unsupported.Stderr = &stdout, &stderr
	err := unsupported.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("unsupported command error = %v, want exit 2", err)
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	failure, ok := result["error"].(map[string]any)
	if result["schema_version"] != "tlsbeacon.cli.v1" || result["command"] != "inspect" || result["outcome"] != "execution_failed" || result["data"] != nil || !ok || failure["code"] != "invalid_input" || stderr.Len() != 0 || strings.Count(stdout.String(), "\n") != 1 || !strings.HasSuffix(stdout.String(), "\n") || strings.Contains(stdout.String(), "private-argument") {
		t.Fatalf("unexpected subprocess streams: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	broken := exec.Command(binary, "--json", "help")
	broken.Stdout = writer
	var brokenErr bytes.Buffer
	broken.Stderr = &brokenErr
	err = broken.Run()
	if closeErr := writer.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 || !strings.Contains(brokenErr.String(), "output_error") {
		t.Fatalf("broken stdout: error=%v stderr=%q", err, brokenErr.String())
	}
}

type failingWriter struct{ short bool }

func (w failingWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("sensitive underlying error")
}

func TestOutputFailure(t *testing.T) {
	for _, short := range []bool{false, true} {
		for _, args := range [][]string{{"--help"}, {"--json", "help"}, {"--json", "inspect"}} {
			var stderr bytes.Buffer
			if got := Run(args, failingWriter{short}, &stderr); got != 2 {
				t.Fatalf("short=%v args=%v exit=%d", short, args, got)
			}
			if !strings.Contains(stderr.String(), "output_error") || strings.Contains(stderr.String(), "sensitive underlying error") {
				t.Fatalf("unexpected diagnostic %q", stderr.String())
			}
		}
	}
	if got := Run([]string{"inspect"}, io.Discard, failingWriter{}); got != 2 {
		t.Fatalf("failed diagnostic exit = %d", got)
	}
}
