package main

import (
	"context"
	"fmt"
	"os"

	"github.com/misconfig-cloud/agent-runtime/internal/cli"
)

var version = "dev"

func main() {
	app := &cli.App{Version: version}
	if err := app.Run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "misconfig: %v\n", err)
		os.Exit(cli.ExitCode(err))
	}
}
