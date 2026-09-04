package release

import (
	"archive/tar"
	"compress/gzip"
	"context"
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
	manifest := []byte("{\"schema_version\":1,\"product\":\"misconfig-agent-runtime\",\"version\":\"1.0.0\",\"commit\":\"abc\",\"source_date_epoch\":0,\"artifacts\":[]}\n")
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), manifest, 0o644); err != nil {
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

func TestInstallScriptDoesNotPutEnrollmentSecretOnArgv(t *testing.T) {
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
	if !strings.Contains(content, "--token-file -") {
		t.Fatal("installer does not direct enrollment through stdin")
	}
	if strings.Contains(content, "--token ") {
		t.Fatal("installer documents a secret-bearing argv token")
	}
}
