package credentialruntime

import (
	"bytes"
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
	"slices"
	"sort"
	"strings"
	"time"

	provideradapter "github.com/misconfig-cloud/provider-sdk"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
)

const (
	maximumRendererArtifact = 64 << 20
	maximumRendererMessage  = 1 << 20
)

var (
	externalDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	executablePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	environmentPattern    = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
)

type RendererRunner func(context.Context, string, string, []byte) ([]byte, error)

type External struct {
	Provider     controlclient.CredentialProvider
	RendererPath string
	RunRenderer  RendererRunner
}

func (e External) CredentialKind() string { return e.Provider.CredentialKind }

func (e External) SensitiveEnvironment() []string {
	return append([]string(nil), e.Provider.SensitiveEnvironment...)
}

func StageExternalRenderer(provider controlclient.CredentialProvider, lookPath func(string) (string, error), store localstate.Store, sessionID string) (string, error) {
	if err := validateExternalDescriptor(provider); err != nil {
		return "", err
	}
	rendererDigest, err := rendererDigestForPlatform(provider, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return "", err
	}
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	source, err := lookPath(provider.RendererExecutable)
	if err != nil {
		return "", fmt.Errorf("locate admitted credential renderer %q: %w", provider.RendererExecutable, err)
	}
	info, err := os.Stat(source)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumRendererArtifact {
		return "", errors.New("credential renderer artifact is not a bounded regular file")
	}
	encoded, err := os.ReadFile(source)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumRendererArtifact {
		return "", errors.New("read credential renderer artifact")
	}
	if digestBytes(encoded) != rendererDigest {
		return "", errors.New("credential renderer artifact digest does not match the admitted release")
	}
	staged, err := store.SaveRuntimeExecutable(sessionID, "renderer-"+provider.RendererExecutable, encoded)
	if err != nil {
		return "", fmt.Errorf("stage credential renderer: %w", err)
	}
	if err := VerifyExternalRenderer(staged, rendererDigest); err != nil {
		return "", err
	}
	return staged, nil
}

func VerifyExternalRenderer(path, expectedDigest string) error {
	if !externalDigestPattern.MatchString(expectedDigest) {
		return errors.New("credential renderer digest is invalid")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumRendererArtifact {
		return errors.New("staged credential renderer is not a bounded regular file")
	}
	encoded, err := os.ReadFile(path)
	if err != nil || digestBytes(encoded) != expectedDigest {
		return errors.New("staged credential renderer digest changed")
	}
	return nil
}

func (e External) Configure(request ConfigureRequest) ([]string, error) {
	if err := validateExternalDescriptor(e.Provider); err != nil {
		return nil, err
	}
	if err := provideradapter.ValidateResourceSelection(request.Profile.Scope.ResourcePrefixes, request.Profile.Scope.ResourceIDs); err != nil {
		return nil, err
	}
	if request.Profile.Scope.ResourceIDs != nil && !slices.Contains(e.Provider.AuthorizationFeatures, provideradapter.AuthorizationExactResourcesV1) {
		return nil, errors.New("credential release does not enforce the selected exact resources")
	}
	if request.Profile.CredentialBinding == nil || request.Provider.Release != e.Provider.Release ||
		request.Provider.Provider != request.Profile.Scope.Provider || request.Provider.Provider != e.Provider.Provider ||
		request.Provider.ManifestDigest != e.Provider.ManifestDigest ||
		request.Session.ID == "" || request.Executable == "" || request.ActivePath == "" || e.RendererPath == "" {
		return nil, errors.New("external credential renderer does not match the immutable session binding")
	}
	rendererDigest, err := rendererDigestForPlatform(e.Provider, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	if err := VerifyExternalRenderer(e.RendererPath, rendererDigest); err != nil {
		return nil, err
	}
	leaseCommand := []string{
		request.Executable, "credential", "lease", "--active", request.ActivePath,
		"--kind", e.Provider.CredentialKind, "--release", e.Provider.Release,
		"--manifest-digest", e.Provider.ManifestDigest, "--renderer", e.RendererPath,
		"--renderer-digest", rendererDigest,
	}
	payload := provideradapter.ConfigureRequest{
		Protocol: provideradapter.RendererProtocol, Release: e.Provider.Release,
		ManifestDigest: e.Provider.ManifestDigest, Provider: e.Provider.Provider,
		CredentialKind: e.Provider.CredentialKind, SessionID: request.Session.ID,
		AccountRef:       request.Profile.Scope.AccountRef,
		Environments:     append([]string(nil), request.Profile.Scope.Environments...),
		ResourcePrefixes: append([]string(nil), request.Profile.Scope.ResourcePrefixes...),
		ResourceIDs:      request.Profile.Scope.ResourceIDs,
		ActivePath:       request.ActivePath, RuntimeExecutable: request.Executable,
		RendererExecutable: e.RendererPath, RuntimeDirectory: request.Store.RuntimeDirectory(request.Session.ID),
		LeaseCommand: leaseCommand,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	runner := e.RunRenderer
	if runner == nil {
		runner = runRenderer
	}
	response, err := runner(context.Background(), e.RendererPath, "configure", encoded)
	if err != nil {
		return nil, fmt.Errorf("configure external credential renderer: %w", err)
	}
	rendered, err := decodeRenderedEnvironment(response)
	if err != nil {
		return nil, err
	}
	for _, file := range rendered.Files {
		mode := os.FileMode(file.Mode)
		if mode != 0o400 && mode != 0o600 {
			return nil, errors.New("credential renderer file mode must be 0400 or 0600")
		}
		if filepath.Base(file.Name) != file.Name || file.Name == "." || file.Name == "" || strings.ContainsAny(file.Name, `/\\`) {
			return nil, errors.New("credential renderer file name must be a relative basename")
		}
		if _, err := request.Store.SaveRuntimeFile(request.Session.ID, file.Name, []byte(file.Content), mode); err != nil {
			return nil, fmt.Errorf("write rendered credential configuration: %w", err)
		}
	}
	return SetEnvironment(withoutEnvironment(request.BaseEnv, rendered.Remove), rendered.Set), nil
}

func RenderExternalMaterial(ctx context.Context, runner RendererRunner, provider controlclient.CredentialProvider, rendererPath, sessionID, activePath string, material json.RawMessage) ([]byte, error) {
	if err := validateExternalDescriptor(provider); err != nil {
		return nil, err
	}
	if strings.TrimSpace(sessionID) == "" || strings.TrimSpace(activePath) == "" || len(material) == 0 || !json.Valid(material) {
		return nil, errors.New("credential renderer input is invalid")
	}
	rendererDigest, err := rendererDigestForPlatform(provider, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	if err := VerifyExternalRenderer(rendererPath, rendererDigest); err != nil {
		return nil, err
	}
	request := provideradapter.RenderRequest{
		Protocol: provideradapter.RendererProtocol, Release: provider.Release,
		ManifestDigest: provider.ManifestDigest, SessionID: sessionID,
		ActivePath: activePath, RuntimePath: rendererPath, Material: material,
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if runner == nil {
		runner = runRenderer
	}
	response, err := runner(ctx, rendererPath, "render", encoded)
	if err != nil {
		return nil, fmt.Errorf("render external credential material: %w", err)
	}
	var rendered provideradapter.RenderedMaterial
	if err := decodeStrict(response, &rendered); err != nil || rendered.Stdout == "" || strings.ContainsRune(rendered.Stdout, 0) || len(rendered.Stdout) > maximumRendererMessage {
		return nil, errors.New("credential renderer output is invalid")
	}
	return []byte(rendered.Stdout), nil
}

func validateExternalDescriptor(provider controlclient.CredentialProvider) error {
	if !provider.AdmissionRequired || provider.Release == "" || provider.Provider == "" || provider.CredentialKind == "" ||
		provider.RendererProtocol != provideradapter.RendererProtocol || provider.ManifestDigest == "" ||
		filepath.Base(provider.RendererExecutable) != provider.RendererExecutable || !executablePattern.MatchString(provider.RendererExecutable) ||
		!externalDigestPattern.MatchString(provider.ManifestDigest) || len(provider.RendererArtifacts) == 0 {
		return errors.New("external credential provider descriptor is invalid")
	}
	seen := map[string]struct{}{}
	for _, name := range provider.SensitiveEnvironment {
		if !environmentPattern.MatchString(name) {
			return errors.New("external credential provider environment contract is invalid")
		}
		if _, exists := seen[name]; exists {
			return errors.New("external credential provider environment contract is duplicated")
		}
		seen[name] = struct{}{}
	}
	return nil
}

func rendererDigestForPlatform(provider controlclient.CredentialProvider, operatingSystem, architecture string) (string, error) {
	matched := ""
	seen := map[string]struct{}{}
	for _, artifact := range provider.RendererArtifacts {
		identity := artifact.OS + "\x00" + artifact.Arch
		if artifact.OS == "" || artifact.Arch == "" || !externalDigestPattern.MatchString(artifact.Digest) {
			return "", errors.New("external credential provider renderer artifact is invalid")
		}
		if _, exists := seen[identity]; exists {
			return "", errors.New("external credential provider renderer platform is duplicated")
		}
		seen[identity] = struct{}{}
		if artifact.OS == operatingSystem && artifact.Arch == architecture {
			matched = artifact.Digest
		}
	}
	if matched == "" {
		return "", fmt.Errorf("external credential provider has no renderer for %s/%s", operatingSystem, architecture)
	}
	return matched, nil
}

func RendererDigestForCurrentPlatform(provider controlclient.CredentialProvider) (string, error) {
	return rendererDigestForPlatform(provider, runtime.GOOS, runtime.GOARCH)
}

func decodeRenderedEnvironment(encoded []byte) (provideradapter.RenderedEnvironment, error) {
	var rendered provideradapter.RenderedEnvironment
	if len(encoded) == 0 || len(encoded) > maximumRendererMessage || decodeStrict(encoded, &rendered) != nil {
		return rendered, errors.New("credential renderer configuration output is invalid")
	}
	seenRemove := map[string]struct{}{}
	for _, name := range rendered.Remove {
		if !environmentPattern.MatchString(name) {
			return rendered, errors.New("credential renderer removal environment is invalid")
		}
		if _, exists := seenRemove[name]; exists {
			return rendered, errors.New("credential renderer removal environment is duplicated")
		}
		seenRemove[name] = struct{}{}
	}
	for name, value := range rendered.Set {
		if !environmentPattern.MatchString(name) || strings.ContainsRune(value, 0) {
			return rendered, errors.New("credential renderer environment is invalid")
		}
	}
	names := make([]string, 0, len(rendered.Files))
	for _, file := range rendered.Files {
		names = append(names, file.Name)
	}
	sort.Strings(names)
	for index := 1; index < len(names); index++ {
		if names[index] == names[index-1] {
			return rendered, errors.New("credential renderer file is duplicated")
		}
	}
	return rendered, nil
}

func decodeStrict(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing renderer output")
	}
	return nil
}

func runRenderer(ctx context.Context, path, operation string, input []byte) ([]byte, error) {
	if len(input) > maximumRendererMessage {
		return nil, errors.New("credential renderer input exceeds the protocol limit")
	}
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(runCtx, path, operation)
	command.Stdin = bytes.NewReader(input)
	stdout := &boundedBuffer{remaining: maximumRendererMessage}
	stderr := &boundedBuffer{remaining: 64 << 10}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		return nil, errors.New("credential renderer process failed")
	}
	return stdout.Bytes(), nil
}

type boundedBuffer struct {
	bytes.Buffer
	remaining int
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	if len(value) > b.remaining {
		return 0, errors.New("renderer output exceeds the protocol limit")
	}
	b.remaining -= len(value)
	return b.Buffer.Write(value)
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
