package release

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSourceDateEpoch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    int64
		wantErr bool
	}{
		{name: "unset", input: "", want: 0},
		{name: "epoch", input: "0", want: 0},
		{name: "timestamp", input: "1700000000", want: 1700000000},
		{name: "negative", input: "-1", wantErr: true},
		{name: "not a number", input: "tomorrow", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := SourceDateEpoch(test.input)
			if (err != nil) != test.wantErr {
				t.Fatalf("SourceDateEpoch(%q) error = %v, wantErr %v", test.input, err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("SourceDateEpoch(%q) = %d, want %d", test.input, got, test.want)
			}
		})
	}
}

func TestWriteArchiveIsDeterministic(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	firstSource := filepath.Join(root, "first")
	secondSource := filepath.Join(root, "second")
	if err := os.WriteFile(firstSource, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondSource, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	files := []archiveFile{
		{Name: "z-second", Path: secondSource, Mode: 0o755},
		{Name: "a-first", Path: firstSource, Mode: 0o644},
	}
	timestamp := time.Unix(1700000000, 0).UTC()
	firstArchive := filepath.Join(root, "first.tar.gz")
	secondArchive := filepath.Join(root, "second.tar.gz")
	for _, destination := range []string{firstArchive, secondArchive} {
		file, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := writeArchive(destination, append([]archiveFile(nil), files...), timestamp); err != nil {
			t.Fatal(err)
		}
	}
	firstDigest, _, err := digestFile(firstArchive)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, _, err := digestFile(secondArchive)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("identical inputs produced different archives: %s != %s", firstDigest, secondDigest)
	}

	entries := readArchive(t, firstArchive)
	if got, want := entryNames(entries), []string{"a-first", "z-second"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("archive entries = %v, want %v", got, want)
	}
	if entries[0].Mode != 0o644 || entries[1].Mode != 0o755 {
		t.Fatalf("archive modes = %o, %o", entries[0].Mode, entries[1].Mode)
	}
	for _, entry := range entries {
		if !entry.ModTime.Equal(timestamp) {
			t.Fatalf("%s timestamp = %v, want %v", entry.Name, entry.ModTime, timestamp)
		}
	}
}

func TestBuildVerifyInstallAndUninstall(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a release binary")
	}
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	options := Options{
		Version:         "0.1.0-test",
		Commit:          "0123456789abcdef",
		SourceDateEpoch: 1700000000,
		Targets:         []Target{{OS: runtime.GOOS, Arch: runtime.GOARCH}},
	}
	firstOutput := t.TempDir()
	secondOutput := t.TempDir()
	options.OutputDir = firstOutput
	first, err := Build(context.Background(), repository, options)
	if err != nil {
		t.Fatal(err)
	}
	options.OutputDir = secondOutput
	second, err := Build(context.Background(), repository, options)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated build manifests differ:\nfirst: %#v\nsecond: %#v", first, second)
	}
	if err := Verify(firstOutput); err != nil {
		t.Fatalf("Verify(first build): %v", err)
	}
	if err := Verify(secondOutput); err != nil {
		t.Fatalf("Verify(second build): %v", err)
	}
	if first.SchemaVersion != 2 || first.Compatibility.Filename != "compatibility.json" || first.SBOM.Filename != "sbom.spdx.json" {
		t.Fatalf("release metadata contract is incomplete: %#v", first)
	}
	var compatibility CompatibilityManifest
	decodeJSONFile(t, filepath.Join(firstOutput, first.Compatibility.Filename), &compatibility)
	if compatibility.Version != options.Version || compatibility.Commit != options.Commit || len(compatibility.Adapters) != 2 ||
		compatibility.Adapters[0].Agent != "codex" || compatibility.Adapters[1].Agent != "claude" {
		t.Fatalf("compatibility manifest is incomplete: %#v", compatibility)
	}
	var sbom SPDXDocument
	decodeJSONFile(t, filepath.Join(firstOutput, first.SBOM.Filename), &sbom)
	if sbom.SPDXVersion != "SPDX-2.3" || len(sbom.Packages) != 1 || len(sbom.Files) != len(first.Artifacts) {
		t.Fatalf("SPDX release inventory is incomplete: %#v", sbom)
	}

	extracted := t.TempDir()
	extractArchive(t, filepath.Join(firstOutput, first.Artifacts[0].Filename), extracted)
	prefix := filepath.Join(t.TempDir(), "install-root")
	runScript(t, extracted, "install.sh", "--prefix", prefix, "--yes")
	installed := filepath.Join(prefix, "bin", "misconfig")
	output, err := exec.Command(installed, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("run installed binary: %s: %v", output, err)
	}
	if got, want := string(output), "misconfig 0.1.0-test\n"; got != want {
		t.Fatalf("installed version = %q, want %q", got, want)
	}

	upgradeOutput := t.TempDir()
	options.Version = "0.2.0-test"
	options.OutputDir = upgradeOutput
	upgrade, err := Build(context.Background(), repository, options)
	if err != nil {
		t.Fatal(err)
	}
	upgradeExtracted := t.TempDir()
	extractArchive(t, filepath.Join(upgradeOutput, upgrade.Artifacts[0].Filename), upgradeExtracted)
	runScript(t, upgradeExtracted, "install.sh", "--prefix", prefix, "--require-version", "0.2.0-test", "--yes")
	output, err = exec.Command(installed, "version").CombinedOutput()
	if err != nil || string(output) != "misconfig 0.2.0-test\n" {
		t.Fatalf("atomic upgrade did not install the requested release: %s: %v", output, err)
	}

	runScriptExpectFailure(t, extracted, "install.sh", "--prefix", prefix, "--require-version", "9.9.9", "--yes")
	output, err = exec.Command(installed, "version").CombinedOutput()
	if err != nil || string(output) != "misconfig 0.2.0-test\n" {
		t.Fatalf("version pin failure changed the installed runtime: %s: %v", output, err)
	}

	broken := t.TempDir()
	installScript, err := os.ReadFile(filepath.Join(extracted, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "install.sh"), installScript, 0o755); err != nil {
		t.Fatal(err)
	}
	brokenBinary := []byte("#!/bin/sh\ncase \"$0\" in */misconfig) exit 19 ;; esac\necho \"misconfig 0.3.0-broken\"\n")
	if err := os.WriteFile(filepath.Join(broken, "misconfig"), brokenBinary, 0o755); err != nil {
		t.Fatal(err)
	}
	runScriptExpectFailure(t, broken, "install.sh", "--prefix", prefix, "--require-version", "0.3.0-broken", "--yes")
	output, err = exec.Command(installed, "version").CombinedOutput()
	if err != nil || string(output) != "misconfig 0.2.0-test\n" {
		t.Fatalf("failed upgrade did not restore the prior runtime: %s: %v", output, err)
	}
	matches, err := filepath.Glob(filepath.Join(prefix, "bin", ".misconfig.*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("upgrade left temporary files: %v: %v", matches, err)
	}

	runScript(t, extracted, "uninstall.sh", "--prefix", prefix, "--yes", "--keep-state")
	if _, err := os.Stat(installed); !os.IsNotExist(err) {
		t.Fatalf("installed binary remains after uninstall: %v", err)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a release binary")
	}
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	manifest, err := Build(context.Background(), repository, Options{
		Version: "0.1.0-tamper", Commit: "abcdef", OutputDir: output, SourceDateEpoch: 1,
		Targets: []Target{{OS: runtime.GOOS, Arch: runtime.GOARCH}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sbomPath := filepath.Join(output, manifest.SBOM.Filename)
	originalSBOM, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sbomPath, append(append([]byte(nil), originalSBOM...), byte(' ')), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(output); err == nil {
		t.Fatal("Verify accepted tampered release metadata")
	}
	if err := os.WriteFile(sbomPath, originalSBOM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(output); err != nil {
		t.Fatalf("Verify rejected restored release metadata: %v", err)
	}
	artifact := filepath.Join(output, manifest.Artifacts[0].Filename)
	file, err := os.OpenFile(artifact, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("tampered"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Verify(output); err == nil {
		t.Fatal("Verify accepted a tampered artifact")
	}
}

func TestVerifyRejectsIncompleteChecksums(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	compatibility := []byte("{}\n")
	sbom := []byte("{}\n")
	if err := os.WriteFile(filepath.Join(directory, "compatibility.json"), compatibility, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "sbom.spdx.json"), sbom, 0o644); err != nil {
		t.Fatal(err)
	}
	compatibilityDigest := sha256.Sum256(compatibility)
	sbomDigest := sha256.Sum256(sbom)
	manifest := Manifest{
		SchemaVersion: 2,
		Product:       "misconfig-agent-runtime",
		Version:       "1.0.0",
		Commit:        "abc",
		Compatibility: ReleaseFile{Filename: "compatibility.json", SHA256: hex.EncodeToString(compatibilityDigest[:]), Size: int64(len(compatibility))},
		SBOM:          ReleaseFile{Filename: "sbom.spdx.json", SHA256: hex.EncodeToString(sbomDigest[:]), Size: int64(len(sbom))},
	}
	encoded, err := encodeJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "checksums.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(directory); err == nil {
		t.Fatal("Verify accepted checksums that omit manifest.json")
	}
}

func runScript(t *testing.T, directory, name string, arguments ...string) {
	t.Helper()
	command := exec.Command("sh", append([]string{filepath.Join(directory, name)}, arguments...)...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s: %s: %v", name, output, err)
	}
}

func runScriptExpectFailure(t *testing.T, directory, name string, arguments ...string) {
	t.Helper()
	command := exec.Command("sh", append([]string{filepath.Join(directory, name)}, arguments...)...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("%s unexpectedly succeeded: %s", name, output)
	}
}

func decodeJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		t.Fatal(err)
	}
}

func extractArchive(t *testing.T, source, destination string) {
	t.Helper()
	file, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(header.Name) != header.Name {
			t.Fatalf("unsafe archive member %q", header.Name)
		}
		encoded, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, header.Name), encoded, os.FileMode(header.Mode)); err != nil {
			t.Fatal(err)
		}
	}
}

func readArchive(t *testing.T, source string) []*tar.Header {
	t.Helper()
	file, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	var entries []*tar.Header
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return entries
		}
		if err != nil {
			t.Fatal(err)
		}
		copy := *header
		entries = append(entries, &copy)
	}
}

func entryNames(entries []*tar.Header) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names
}

func TestInstallScriptStartsBrowserPairingWithoutEnrollmentSecrets(t *testing.T) {
	t.Parallel()
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(repository, "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(encoded)
	if !strings.Contains(content, "setup --control https://console.misconfig.cloud") {
		t.Fatal("installer does not direct customers to browser pairing")
	}
	if strings.Contains(content, "--token") || strings.Contains(content, "--tenant TENANT") {
		t.Fatal("default installation requires an operator enrollment secret")
	}
}
