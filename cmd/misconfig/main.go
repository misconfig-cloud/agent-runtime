package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/misconfig-cloud/agent-runtime/internal/discovery"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Printf("misconfig %s\n", version)
	case "doctor":
		if err := doctor(); err != nil {
			fmt.Fprintf(os.Stderr, "doctor failed: %v\n", err)
			os.Exit(1)
		}
	case "setup", "run", "status", "uninstall":
		fmt.Fprintf(os.Stderr, "%s is not available in this foundation release\n", os.Args[1])
		os.Exit(3)
	default:
		usage()
		os.Exit(2)
	}
}

func doctor() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	result, err := discovery.Scan(filepath.Clean(home), nil)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: misconfig <version|doctor|setup|run|status|uninstall>")
}
