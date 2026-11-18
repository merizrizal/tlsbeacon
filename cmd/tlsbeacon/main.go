package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/merizrizal/tlsbeacon/internal/cli"
)

func main() {
	signal.Ignore(syscall.SIGPIPE)
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
