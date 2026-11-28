// Command tlsbeacon is the TLSBeacon command-line entry point.
package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/merizrizal/tlsbeacon/internal/cli"
)

func main() {
	// Without this, a write to a closed standard-output pipe terminates the
	// process with SIGPIPE before any diagnostic or exit status can be
	// produced. Ignoring it turns that case into an ordinary write error that
	// the response boundary reports on standard error with exit status 2.
	signal.Ignore(syscall.SIGPIPE)

	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
