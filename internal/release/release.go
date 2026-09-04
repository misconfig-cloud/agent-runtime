package release

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Target struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type Artifact struct {
	Target
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

type ReleaseFile struct {
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

type Manifest struct {
	SchemaVersion   int         `json:"schema_version"`
	Product         string      `json:"product"`
	Version         string      `json:"version"`
	Commit          string      `json:"commit"`
	SourceDateEpoch int64       `json:"source_date_epoch"`
	Artifacts       []Artifact  `json:"artifacts"`
	Compatibility   ReleaseFile `json:"compatibility"`
	SBOM            ReleaseFile `json:"sbom"`
}

type CompatibilityManifest struct {
	SchemaVersion int                    `json:"schema_version"`
	Product       string                 `json:"product"`
	Version       string                 `json:"version"`
	Commit        string                 `json:"commit"`
	Adapters      []AdapterCompatibility `json:"adapters"`
}

type AdapterCompatibility struct {
	Agent                string   `json:"agent"`
	AdapterRelease       string   `json:"adapter_release"`
	ClientProduct        string   `json:"client_product"`
	TestedClientVersions []string `json:"tested_client_versions"`
	HookEvents           []string `json:"hook_events"`
	ApprovalProjection   string   `json:"approval_projection"`
	CompletionEvidence   string   `json:"completion_evidence"`
	Acceptance           string   `json:"acceptance"`
	Limitations          []string `json:"limitations,omitempty"`
}

type SPDXDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      SPDXCreationInfo   `json:"creationInfo"`
	Packages          []SPDXPackage      `json:"packages"`
	Files             []SPDXFile         `json:"files"`
	Relationships     []SPDXRelationship `json:"relationships"`
}

type SPDXCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type SPDXPackage struct {
	Name             string `json:"name"`
	SPDXID           string `json:"SPDXID"`
	VersionInfo      string `json:"versionInfo"`
	DownloadLocation string `json:"downloadLocation"`
	FilesAnalyzed    bool   `json:"filesAnalyzed"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
	CopyrightText    string `json:"copyrightText"`
	SourceInfo       string `json:"sourceInfo"`
}

type SPDXChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type SPDXFile struct {
	FileName         string         `json:"fileName"`
	SPDXID           string         `json:"SPDXID"`
	Checksums        []SPDXChecksum `json:"checksums"`
	LicenseConcluded string         `json:"licenseConcluded"`
	CopyrightText    string         `json:"copyrightText"`
}

type SPDXRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

type Options struct {
	Version         string
	Commit          string
	OutputDir       string
	SourceDateEpoch int64
	Targets         []Target
	Overwrite       bool
}

var DefaultTargets = []Target{
	{OS: "darwin", Arch: "amd64"},
	{OS: "darwin", Arch: "arm64"},
	{OS: "linux", Arch: "amd64"},
	{OS: "linux", Arch: "arm64"},
}

var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

func Build(ctx context.Context, repository string, options Options) (Manifest, error) {
	if err := validate(options); err != nil {
		return Manifest{}, err
	}
	repository, err := filepath.Abs(repository)
	if err != nil {
		return Manifest{}, fmt.Errorf("resolve repository: %w", err)
	}
	output, err := filepath.Abs(options.OutputDir)
	if err != nil {
		return Manifest{}, fmt.Errorf("resolve output: %w", err)
	}
	if err := os.MkdirAll(output, 0o755); err != nil {
		return Manifest{}, err
	}
	work, err := os.MkdirTemp("", "misconfig-release-")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(work)

	targets := append([]Target(nil), options.Targets...)
	if len(targets) == 0 {
		targets = append(targets, DefaultTargets...)
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].OS == targets[j].OS {
			return targets[i].Arch < targets[j].Arch
		}
		return targets[i].OS < targets[j].OS
	})
	seenTargets := make(map[Target]struct{}, len(targets))
	for _, target := range targets {
		if err := validateTarget(target); err != nil {
			return Manifest{}, err
		}
		if _, exists := seenTargets[target]; exists {
			return Manifest{}, fmt.Errorf("duplicate release target %s/%s", target.OS, target.Arch)
		}
		seenTargets[target] = struct{}{}
		filename := fmt.Sprintf("misconfig_%s_%s_%s.tar.gz", options.Version, target.OS, target.Arch)
		if err := refuseExisting(filepath.Join(output, filename), options.Overwrite); err != nil {
			return Manifest{}, err
		}
	}
	for _, name := range []string{"manifest.json", "checksums.txt", "compatibility.json", "sbom.spdx.json"} {
		if err := refuseExisting(filepath.Join(output, name), options.Overwrite); err != nil {
			return Manifest{}, err
		}
	}

	manifest := Manifest{
		SchemaVersion: 2, Product: "misconfig-agent-runtime", Version: options.Version,
		Commit: options.Commit, SourceDateEpoch: options.SourceDateEpoch,
	}
	for _, target := range targets {
		binary := filepath.Join(work, target.OS+"-"+target.Arch, "misconfig")
		if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
			return Manifest{}, err
		}
		if err := buildBinary(ctx, repository, binary, options.Version, target); err != nil {
			return Manifest{}, err
		}
		filename := fmt.Sprintf("misconfig_%s_%s_%s.tar.gz", options.Version, target.OS, target.Arch)
		destination := filepath.Join(output, filename)
		files := []archiveFile{
			{Name: "misconfig", Path: binary, Mode: 0o755},
			{Name: "install.sh", Path: filepath.Join(repository, "scripts", "install.sh"), Mode: 0o755},
			{Name: "uninstall.sh", Path: filepath.Join(repository, "scripts", "uninstall.sh"), Mode: 0o755},
			{Name: "LICENSE", Path: filepath.Join(repository, "LICENSE"), Mode: 0o644},
			{Name: "README.md", Path: filepath.Join(repository, "README.md"), Mode: 0o644},
		}
		temporaryFile, err := os.CreateTemp(output, ".misconfig-archive-")
		if err != nil {
			return Manifest{}, err
		}
		temporary := temporaryFile.Name()
		if err := temporaryFile.Close(); err != nil {
			return Manifest{}, err
		}
		if err := writeArchive(temporary, files, time.Unix(options.SourceDateEpoch, 0).UTC()); err != nil {
			_ = os.Remove(temporary)
			return Manifest{}, err
		}
		if err := os.Rename(temporary, destination); err != nil {
			_ = os.Remove(temporary)
			return Manifest{}, err
		}
		digest, size, err := digestFile(destination)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Artifacts = append(manifest.Artifacts, Artifact{Target: target, Filename: filename, SHA256: digest, Size: size})
	}
	compatibility, err := encodeJSON(compatibilityManifest(options))
	if err != nil {
		return Manifest{}, err
	}
	manifest.Compatibility, err = writeReleaseFile(output, "compatibility.json", compatibility, options.Overwrite)
	if err != nil {
		return Manifest{}, err
	}
	sbom, err := encodeJSON(sbomDocument(options, manifest.Artifacts))
	if err != nil {
		return Manifest{}, err
	}
	manifest.SBOM, err = writeReleaseFile(output, "sbom.spdx.json", sbom, options.Overwrite)
	if err != nil {
		return Manifest{}, err
	}
	if err := writeMetadata(output, manifest, options.Overwrite); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func Verify(directory string) error {
	manifestPath := filepath.Join(directory, "manifest.json")
	encoded, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest Manifest
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	if manifest.SchemaVersion != 2 || manifest.Product != "misconfig-agent-runtime" || manifest.Version == "" {
		return errors.New("manifest identity is invalid")
	}
	expected := make(map[string]string, len(manifest.Artifacts)+1)
	manifestSum := sha256.Sum256(encoded)
	expected["manifest.json"] = hex.EncodeToString(manifestSum[:])
	for _, artifact := range manifest.Artifacts {
		if filepath.Base(artifact.Filename) != artifact.Filename {
			return fmt.Errorf("artifact path %q is not local", artifact.Filename)
		}
		if _, exists := expected[artifact.Filename]; exists {
			return fmt.Errorf("duplicate artifact %q", artifact.Filename)
		}
		digest, size, err := digestFile(filepath.Join(directory, artifact.Filename))
		if err != nil {
			return err
		}
		if digest != artifact.SHA256 || size != artifact.Size {
			return fmt.Errorf("artifact %s does not match its manifest", artifact.Filename)
		}
		expected[artifact.Filename] = digest
	}
	for _, metadata := range []ReleaseFile{manifest.Compatibility, manifest.SBOM} {
		if filepath.Base(metadata.Filename) != metadata.Filename || metadata.Filename == "" {
			return fmt.Errorf("release metadata path %q is not local", metadata.Filename)
		}
		if _, exists := expected[metadata.Filename]; exists {
			return fmt.Errorf("duplicate release file %q", metadata.Filename)
		}
		digest, size, err := digestFile(filepath.Join(directory, metadata.Filename))
		if err != nil {
			return err
		}
		if digest != metadata.SHA256 || size != metadata.Size {
			return fmt.Errorf("release file %s does not match its manifest", metadata.Filename)
		}
		expected[metadata.Filename] = digest
	}
	checksums, err := os.ReadFile(filepath.Join(directory, "checksums.txt"))
	if err != nil {
		return err
	}
	actual := make(map[string]string, len(expected))
	for _, line := range strings.Split(strings.TrimSuffix(string(checksums), "\n"), "\n") {
		parts := strings.Split(line, "  ")
		if len(parts) != 2 || len(parts[0]) != sha256.Size*2 || filepath.Base(parts[1]) != parts[1] {
			return fmt.Errorf("invalid checksum line %q", line)
		}
		if _, err := hex.DecodeString(parts[0]); err != nil {
			return fmt.Errorf("invalid checksum for %s", parts[1])
		}
		if _, exists := actual[parts[1]]; exists {
			return fmt.Errorf("duplicate checksum for %s", parts[1])
		}
		actual[parts[1]] = parts[0]
	}
	if len(actual) != len(expected) {
		return errors.New("checksums do not cover exactly the release manifest")
	}
	for filename, digest := range expected {
		if actual[filename] != digest {
			return fmt.Errorf("checksum for %s does not match", filename)
		}
	}
	return nil
}

func validate(options Options) error {
	version := strings.TrimSpace(options.Version)
	if version == "" || version == "dev" || !versionPattern.MatchString(version) {
		return errors.New("release version must be explicit and filesystem-safe")
	}
	if strings.TrimSpace(options.OutputDir) == "" {
		return errors.New("output directory is required")
	}
	if options.SourceDateEpoch < 0 {
		return errors.New("source date epoch cannot be negative")
	}
	return nil
}

func validateTarget(target Target) error {
	if target.OS != "darwin" && target.OS != "linux" {
		return fmt.Errorf("unsupported operating system %q", target.OS)
	}
	if target.Arch != "amd64" && target.Arch != "arm64" {
		return fmt.Errorf("unsupported architecture %q", target.Arch)
	}
	return nil
}

func buildBinary(ctx context.Context, repository, output, version string, target Target) error {
	ldflags := "-s -w -buildid= -X main.version=" + version
	command := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags", ldflags, "-o", output, "./cmd/misconfig")
	command.Dir = repository
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+target.OS, "GOARCH="+target.Arch)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("build %s/%s: %s: %w", target.OS, target.Arch, strings.TrimSpace(string(output)), err)
	}
	return nil
}

type archiveFile struct {
	Name string
	Path string
	Mode int64
}

func writeArchive(destination string, files []archiveFile, timestamp time.Time) (returnErr error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); returnErr == nil && err != nil {
			returnErr = err
		}
	}()
	if err := file.Chmod(0o644); err != nil {
		return err
	}
	gzipWriter, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		return err
	}
	gzipWriter.Header.ModTime = timestamp
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range files {
		encoded, err := os.ReadFile(entry.Path)
		if err != nil {
			return err
		}
		header := &tar.Header{
			Name: entry.Name, Mode: entry.Mode, Size: int64(len(encoded)), ModTime: timestamp,
			AccessTime: timestamp, ChangeTime: timestamp, Typeflag: tar.TypeReg, Format: tar.FormatPAX,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if _, err := tarWriter.Write(encoded); err != nil {
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	return gzipWriter.Close()
}

func writeMetadata(output string, manifest Manifest, overwrite bool) error {
	manifestPath := filepath.Join(output, "manifest.json")
	checksumsPath := filepath.Join(output, "checksums.txt")
	if err := refuseExisting(manifestPath, overwrite); err != nil {
		return err
	}
	if err := refuseExisting(checksumsPath, overwrite); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := atomicWrite(manifestPath, encoded, 0o644); err != nil {
		return err
	}
	manifestSum := sha256.Sum256(encoded)
	lines := make([]string, 0, len(manifest.Artifacts)+1)
	for _, artifact := range manifest.Artifacts {
		lines = append(lines, artifact.SHA256+"  "+artifact.Filename)
	}
	for _, metadata := range []ReleaseFile{manifest.Compatibility, manifest.SBOM} {
		lines = append(lines, metadata.SHA256+"  "+metadata.Filename)
	}
	lines = append(lines, hex.EncodeToString(manifestSum[:])+"  manifest.json")
	sort.Strings(lines)
	return atomicWrite(checksumsPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func writeReleaseFile(output, name string, encoded []byte, overwrite bool) (ReleaseFile, error) {
	path := filepath.Join(output, name)
	if err := refuseExisting(path, overwrite); err != nil {
		return ReleaseFile{}, err
	}
	if err := atomicWrite(path, encoded, 0o644); err != nil {
		return ReleaseFile{}, err
	}
	digest, size, err := digestFile(path)
	if err != nil {
		return ReleaseFile{}, err
	}
	return ReleaseFile{Filename: name, SHA256: digest, Size: size}, nil
}

func encodeJSON(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func compatibilityManifest(options Options) CompatibilityManifest {
	return CompatibilityManifest{
		SchemaVersion: 1,
		Product:       "misconfig-agent-runtime",
		Version:       options.Version,
		Commit:        options.Commit,
		Adapters: []AdapterCompatibility{
			{
				Agent: "codex", AdapterRelease: "codex@" + options.Version,
				ClientProduct: "OpenAI Codex CLI", TestedClientVersions: []string{"0.152.0"},
				HookEvents:         []string{"PreToolUse", "PostToolUse"},
				ApprovalProjection: "require_approval is rendered as a synchronous deny with an external approval reason",
				CompletionEvidence: "opaque shell output is observed, never independently verified",
				Acceptance:         "direct_allow_deny_live_accepted",
				Limitations:        []string{"nested and subagent live acceptance remains open"},
			},
			{
				Agent: "claude", AdapterRelease: "claude@" + options.Version,
				ClientProduct: "Anthropic Claude Code", TestedClientVersions: []string{"2.1.222"},
				HookEvents:         []string{"PreToolUse", "PostToolUse", "PostToolUseFailure"},
				ApprovalProjection: "require_approval is rendered as the native ask decision",
				CompletionEvidence: "success and failure hooks close the logical action as observed",
				Acceptance:         "fixture_tested_live_pending",
				Limitations:        []string{"authenticated direct, nested and subagent live acceptance remains open"},
			},
		},
	}
}

func sbomDocument(options Options, artifacts []Artifact) SPDXDocument {
	files := make([]SPDXFile, 0, len(artifacts))
	relationships := []SPDXRelationship{{
		SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: "SPDXRef-Package-agent-runtime",
	}}
	for index, artifact := range artifacts {
		id := fmt.Sprintf("SPDXRef-File-%d", index+1)
		files = append(files, SPDXFile{
			FileName: "./" + artifact.Filename, SPDXID: id,
			Checksums:        []SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: artifact.SHA256}},
			LicenseConcluded: "Apache-2.0", CopyrightText: "Copyright Misconfig Cloud LLC",
		})
		relationships = append(relationships, SPDXRelationship{
			SPDXElementID: "SPDXRef-Package-agent-runtime", RelationshipType: "CONTAINS", RelatedSPDXElement: id,
		})
	}
	return SPDXDocument{
		SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT",
		Name:              "misconfig-agent-runtime-" + options.Version,
		DocumentNamespace: "https://misconfig.cloud/sbom/agent-runtime/" + options.Version + "/" + options.Commit,
		CreationInfo: SPDXCreationInfo{
			Created:  time.Unix(options.SourceDateEpoch, 0).UTC().Format(time.RFC3339),
			Creators: []string{"Organization: Misconfig Cloud LLC", "Tool: misconfig-release/" + options.Version, "Tool: " + runtime.Version()},
		},
		Packages: []SPDXPackage{{
			Name: "github.com/misconfig-cloud/agent-runtime", SPDXID: "SPDXRef-Package-agent-runtime",
			VersionInfo: options.Version, DownloadLocation: "https://github.com/misconfig-cloud/agent-runtime",
			FilesAnalyzed: true, LicenseConcluded: "Apache-2.0", LicenseDeclared: "Apache-2.0",
			CopyrightText: "Copyright Misconfig Cloud LLC", SourceInfo: "commit " + options.Commit,
		}},
		Files: files, Relationships: relationships,
	}
}

func atomicWrite(path string, encoded []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".misconfig-metadata-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func refuseExisting(path string, overwrite bool) error {
	if overwrite {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("refusing to overwrite %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func digestFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func SourceDateEpoch(environment string) (int64, error) {
	if strings.TrimSpace(environment) == "" {
		return 0, nil
	}
	value, err := strconv.ParseInt(environment, 10, 64)
	if err != nil || value < 0 {
		return 0, errors.New("SOURCE_DATE_EPOCH must be a non-negative Unix timestamp")
	}
	return value, nil
}
