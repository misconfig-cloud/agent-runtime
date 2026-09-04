package credentialruntime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	provideradapter "github.com/misconfig-cloud/provider-sdk"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
)

func externalFixtureProvider(artifact []byte) controlclient.CredentialProvider {
	return controlclient.CredentialProvider{
		Release: "orbital-fabric.session@3.7.1", Provider: "orbital-fabric",
		CredentialKind: "orbital.exec-token.v9", MaximumTTLSeconds: 300,
		RevocationSemantics: "renewal-stops-immediately",
		ManifestDigest:      "sha256:" + strings.Repeat("a", 64), PublisherID: "fixture-labs",
		RendererProtocol: provideradapter.RendererProtocol, RendererExecutable: "orbital-renderer",
		RendererArtifacts:    []controlclient.RendererArtifact{{OS: runtime.GOOS, Arch: runtime.GOARCH, Digest: digestBytes(artifact)}},
		SensitiveEnvironment: []string{"ORBITAL_TOKEN", "ORBITAL_CONFIG"},
		AdmissionRequired:    true,
	}
}

func TestExternalRendererStagesExactArtifactAndConfiguresUnknownProvider(t *testing.T) {
	artifact := []byte("unfamiliar-renderer-bytes")
	provider := externalFixtureProvider(artifact)
	rendererDigest, _ := RendererDigestForCurrentPlatform(provider)
	source := filepath.Join(t.TempDir(), provider.RendererExecutable)
	if err := os.WriteFile(source, artifact, 0o700); err != nil {
		t.Fatal(err)
	}
	store := localstate.Store{Root: t.TempDir(), FileTokens: true}
	staged, err := StageExternalRenderer(provider, func(string) (string, error) { return source, nil }, store, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	if staged == source || filepath.Dir(staged) != store.RuntimeDirectory("session-1") {
		t.Fatalf("renderer was not staged into the session boundary: %q", staged)
	}

	var configure provideradapter.ConfigureRequest
	runner := func(_ context.Context, path, operation string, input []byte) ([]byte, error) {
		if path != staged || operation != "configure" {
			t.Fatalf("unexpected renderer invocation: %s %s", path, operation)
		}
		if err := json.Unmarshal(input, &configure); err != nil {
			t.Fatal(err)
		}
		return json.Marshal(provideradapter.RenderedEnvironment{
			Remove: []string{"ORBITAL_TOKEN"}, Set: map[string]string{"ORBITAL_CONFIG": store.RuntimeDirectory("session-1") + "/native.json"},
			Files: []provideradapter.RenderedFile{{Name: "native.json", Content: "{}\n", Mode: 0o600}},
		})
	}
	profile := domain.SessionProfile{
		Scope:             domain.Scope{Provider: "orbital-fabric", AccountRef: "station-9", Environments: []string{"production"}, ResourcePrefixes: []string{"orbital://station/9"}},
		CredentialBinding: &domain.CredentialBinding{ConnectionID: "connection-1", ProviderRelease: provider.Release},
	}
	environment, err := (External{Provider: provider, RendererPath: staged, RunRenderer: runner}).Configure(ConfigureRequest{
		Store: store, Executable: "/usr/local/bin/misconfig", ActivePath: "/tmp/active.json",
		Profile: profile, Session: domain.AgentSession{ID: "session-1"}, Provider: provider,
		BaseEnv: []string{"PATH=/bin", "ORBITAL_TOKEN=ambient"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if configure.Provider != "orbital-fabric" || configure.AccountRef != "station-9" || configure.ManifestDigest != provider.ManifestDigest || configure.RendererExecutable != staged {
		t.Fatalf("immutable renderer coordinates changed: %#v", configure)
	}
	wantCommand := []string{"/usr/local/bin/misconfig", "credential", "lease", "--active", "/tmp/active.json", "--kind", provider.CredentialKind, "--release", provider.Release, "--manifest-digest", provider.ManifestDigest, "--renderer", staged, "--renderer-digest", rendererDigest}
	if !reflect.DeepEqual(configure.LeaseCommand, wantCommand) {
		t.Fatalf("unexpected lease command: %#v", configure.LeaseCommand)
	}
	joined := strings.Join(environment, "\n")
	if strings.Contains(joined, "ORBITAL_TOKEN=") || !strings.Contains(joined, "ORBITAL_CONFIG=") {
		t.Fatalf("ambient credential escaped or native config missing: %#v", environment)
	}
	if encoded, err := os.ReadFile(filepath.Join(store.RuntimeDirectory("session-1"), "native.json")); err != nil || string(encoded) != "{}\n" {
		t.Fatalf("native file was not rendered: %q %v", encoded, err)
	}

	if err := os.Chmod(staged, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("tampered"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := VerifyExternalRenderer(staged, rendererDigest); err == nil {
		t.Fatal("tampered staged renderer was accepted")
	}
}

func TestExternalRendererRendersOpaqueMaterialAndRejectsMalformedOutput(t *testing.T) {
	artifact := []byte("renderer")
	provider := externalFixtureProvider(artifact)
	path := filepath.Join(t.TempDir(), "renderer")
	if err := os.WriteFile(path, artifact, 0o500); err != nil {
		t.Fatal(err)
	}
	material := json.RawMessage(`{"opaque":{"token":"secret"}}`)
	runner := func(_ context.Context, gotPath, operation string, input []byte) ([]byte, error) {
		if gotPath != path || operation != "render" {
			t.Fatalf("unexpected renderer invocation: %s %s", gotPath, operation)
		}
		var request provideradapter.RenderRequest
		if err := json.Unmarshal(input, &request); err != nil || request.SessionID != "session-1" || !reflect.DeepEqual(request.Material, material) {
			t.Fatalf("unexpected render request: %#v %v", request, err)
		}
		return json.Marshal(provideradapter.RenderedMaterial{Stdout: "native-ephemeral\n"})
	}
	output, err := RenderExternalMaterial(context.Background(), runner, provider, path, "session-1", "/tmp/active", material)
	if err != nil || string(output) != "native-ephemeral\n" {
		t.Fatalf("render opaque material: %q %v", output, err)
	}
	bad := func(context.Context, string, string, []byte) ([]byte, error) {
		return []byte(`{"stdout":"ok"} {"trailing":true}`), nil
	}
	if _, err := RenderExternalMaterial(context.Background(), bad, provider, path, "session-1", "/tmp/active", material); err == nil {
		t.Fatal("trailing renderer output was accepted")
	}
}

func TestExternalRendererSelectsExactPlatformAndRejectsUnsupportedOrDuplicateTargets(t *testing.T) {
	provider := externalFixtureProvider([]byte("renderer"))
	digest, err := rendererDigestForPlatform(provider, runtime.GOOS, runtime.GOARCH)
	if err != nil || digest == "" {
		t.Fatalf("current platform was not selected: %q %v", digest, err)
	}
	if _, err := rendererDigestForPlatform(provider, "plan9", "mips"); err == nil {
		t.Fatal("unsupported renderer platform was accepted")
	}
	provider.RendererArtifacts = append(provider.RendererArtifacts, provider.RendererArtifacts[0])
	if _, err := rendererDigestForPlatform(provider, runtime.GOOS, runtime.GOARCH); err == nil {
		t.Fatal("duplicate renderer platform was accepted")
	}
}
