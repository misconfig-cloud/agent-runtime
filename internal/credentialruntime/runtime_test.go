package credentialruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
)

func TestAWSRuntimeRemovesAmbientCredentialsAndInstallsCredentialProcess(t *testing.T) {
	store := localstate.Store{Root: t.TempDir(), FileTokens: true}
	binding := &domain.CredentialBinding{ConnectionID: "connection-a", ProviderRelease: "aws.sts-session@1.0.0"}
	profile := domain.SessionProfile{CredentialBinding: binding, Scope: domain.Scope{Provider: "aws"}}
	session := domain.AgentSession{ID: "session-a", StartedAt: time.Now()}
	registry, err := NewRegistry(AWS{})
	if err != nil {
		t.Fatal(err)
	}
	environment, err := registry.Configure(AWSCredentialKind, ConfigureRequest{
		Store: store, Executable: "/opt/misconfig/bin/misconfig", ActivePath: "/tmp/session-a.json",
		Profile: profile, Session: session,
		Provider: controlclient.CredentialProvider{Release: binding.ProviderRelease, Provider: "aws", CredentialKind: AWSCredentialKind},
		BaseEnv:  []string{"PATH=/bin", "AWS_ACCESS_KEY_ID=ambient", "AWS_SECRET_ACCESS_KEY=ambient-secret", "AWS_PROFILE=owner"},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(environment, "\n")
	if strings.Contains(joined, "ambient") || !strings.Contains(joined, "AWS_PROFILE=misconfig-session") || !strings.Contains(joined, "AWS_EC2_METADATA_DISABLED=true") {
		t.Fatalf("credential environment was not isolated: %s", joined)
	}
	encoded, err := os.ReadFile(filepath.Join(store.Root, "runtime", "session-a", "aws-config"))
	if err != nil {
		t.Fatal(err)
	}
	config := string(encoded)
	if !strings.Contains(config, "credential_process = \"/opt/misconfig/bin/misconfig\" credential lease") || strings.Contains(config, "ambient") {
		t.Fatalf("unexpected aws config: %s", config)
	}
}

func TestAWSRuntimeRejectsAnotherProviderUsingTheAWSMaterialKind(t *testing.T) {
	binding := &domain.CredentialBinding{ConnectionID: "connection-a", ProviderRelease: "orbital.session@1.0.0"}
	registry, err := NewRegistry(AWS{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.Configure(AWSCredentialKind, ConfigureRequest{
		Store: localstate.Store{Root: t.TempDir(), FileTokens: true}, Executable: "/opt/misconfig",
		ActivePath: "/tmp/session.json", Session: domain.AgentSession{ID: "session-a"},
		Profile: domain.SessionProfile{CredentialBinding: binding, Scope: domain.Scope{Provider: "orbital-fabric"}},
		Provider: controlclient.CredentialProvider{
			Release: binding.ProviderRelease, Provider: "orbital-fabric", CredentialKind: AWSCredentialKind,
		},
	})
	if err == nil {
		t.Fatal("aws adapter accepted an unfamiliar provider contract")
	}
}

type unfamiliarAdapter struct{}

func (unfamiliarAdapter) CredentialKind() string         { return "orbital.exec-token.v9" }
func (unfamiliarAdapter) SensitiveEnvironment() []string { return []string{"ORBITAL_TOKEN"} }
func (unfamiliarAdapter) Configure(request ConfigureRequest) ([]string, error) {
	return SetEnvironment(request.BaseEnv, map[string]string{"ORBITAL_SESSION": request.Session.ID}), nil
}

func TestUnfamiliarRuntimeAdapterRequiresNoRegistryCoreChange(t *testing.T) {
	registry, err := NewRegistry(AWS{}, unfamiliarAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	environment, err := registry.Configure("orbital.exec-token.v9", ConfigureRequest{Session: domain.AgentSession{ID: "session-z"}, BaseEnv: []string{"ORBITAL_TOKEN=ambient", "PATH=/bin"}})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(environment, "\n")
	if strings.Contains(joined, "ORBITAL_TOKEN") || !strings.Contains(joined, "ORBITAL_SESSION=session-z") {
		t.Fatalf("unfamiliar adapter did not isolate its environment: %s", joined)
	}
}

func TestUnregisteredRuntimeAdapterFailsClosed(t *testing.T) {
	registry, err := NewRegistry(AWS{})
	if err != nil {
		t.Fatal(err)
	}
	environment, err := registry.Configure("orbital.exec-token.v9", ConfigureRequest{
		Session: domain.AgentSession{ID: "session-z"},
		BaseEnv: []string{
			"ORBITAL_TOKEN=ambient",
			"PATH=/bin",
		},
	})
	if err == nil {
		t.Fatal("unregistered adapter was accepted")
	}
	if environment != nil {
		t.Fatalf("unregistered adapter returned an environment: %#v", environment)
	}
}
