package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/misconfig-cloud/agent-runtime/internal/release"
)

func main() {
	version := flag.String("version", "", "release version")
	commit := flag.String("commit", "unknown", "source commit")
	output := flag.String("output", "dist", "artifact directory")
	overwrite := flag.Bool("overwrite", false, "replace existing release metadata and artifacts")
	verify := flag.String("verify", "", "verify an existing artifact directory")
	flag.Parse()
	if *verify != "" {
		if err := release.Verify(*verify); err != nil {
			fatal(err)
		}
		fmt.Printf("Verified release artifacts in %s.\n", *verify)
		return
	}
	epoch, err := release.SourceDateEpoch(os.Getenv("SOURCE_DATE_EPOCH"))
	if err != nil {
		fatal(err)
	}
	manifest, err := release.Build(context.Background(), ".", release.Options{
		Version: strings.TrimSpace(*version), Commit: strings.TrimSpace(*commit), OutputDir: *output,
		SourceDateEpoch: epoch, Overwrite: *overwrite,
	})
	if err != nil {
		fatal(err)
	}
	fmt.Printf("Built Misconfig %s: %d artifacts in %s.\n", manifest.Version, len(manifest.Artifacts), *output)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "release: %v\n", err)
	os.Exit(1)
}
