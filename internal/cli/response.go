package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const schemaVersion = "tlsbeacon.cli.v1"

const helpText = "Usage: tlsbeacon [--json] --config PATH <command> [options]\nCommands: policy set/show; trust import/refresh/list; endpoint add/list/show/edit/enable/disable\nPolicy set accepts --rules-json JSON; trust import/refresh accept --mode and repeated --source paths.\nEndpoint add/edit use explicit fields and trust profile/version IDs.\nManual inspection is not available yet.\n"

type responseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Action  string `json:"action"`
}

type envelope struct {
	SchemaVersion string         `json:"schema_version"`
	Command       string         `json:"command"`
	Outcome       string         `json:"outcome"`
	Data          any            `json:"data"`
	Error         *responseError `json:"error"`
}

func Run(args []string, stdout, stderr io.Writer) int {
	jsonOutput, configPath, commandArgs, failure := parseGlobalArguments(args)
	command := canonicalCommand(commandArgs)
	if failure != nil {
		return writeFailure(command, jsonOutput, stdout, stderr, failure)
	}
	if len(commandArgs) == 1 && (commandArgs[0] == "help" || commandArgs[0] == "--help" || commandArgs[0] == "-h") {
		if jsonOutput {
			return writeJSON(stdout, stderr, envelope{schemaVersion, "help", "success", map[string]string{"help": helpText}, nil}, 0)
		}
		return writeOutput(stdout, stderr, []byte(helpText), 0)
	}
	if command == "inspect" {
		return writeFailure(command, jsonOutput, stdout, stderr, unavailableInspectFailure())
	}
	if command == "unknown" || command == "tlsbeacon" {
		return writeFailure(command, jsonOutput, stdout, stderr, invalidInputFailure())
	}
	return runConfiguration(command, configPath, commandArgs[2:], jsonOutput, stdout, stderr)
}

func canonicalCommand(args []string) string {
	if len(args) == 0 {
		return "tlsbeacon"
	}
	if args[0] == "inspect" {
		return "inspect"
	}
	commands := map[string][]string{
		"policy":   {"set", "show"},
		"trust":    {"import", "refresh", "list"},
		"endpoint": {"add", "list", "show", "edit", "enable", "disable"},
	}
	if len(args) > 1 {
		for _, subcommand := range commands[args[0]] {
			if args[1] == subcommand {
				return strings.Join(args[:2], " ")
			}
		}
	}
	return "unknown"
}

func writeJSON(stdout, stderr io.Writer, value envelope, exitCode int) int {
	encoded, err := json.Marshal(value)
	if err != nil {
		fmt.Fprintln(stderr, "output_error: could not encode response; check the output and retry safely.")
		return 2
	}
	return writeOutput(stdout, stderr, append(encoded, '\n'), exitCode)
}

func writeOutput(output, stderr io.Writer, content []byte, exitCode int) int {
	n, err := output.Write(content)
	if err != nil || n != len(content) {
		fmt.Fprintln(stderr, "output_error: could not write response; check the output and retry safely.")
		return 2
	}
	return exitCode
}
