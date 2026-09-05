package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAttachModeCannotClaimBrokeredEnforcement(t *testing.T) {
	profile := validProfile()
	profile.Enforcement = EnforcementBrokered
	if err := profile.Validate(); err == nil {
		t.Fatal("expected attach-mode enforcement claim to fail")
	}
}

func TestBrokeredProfileRequiresProviderNeutralImmutableBinding(t *testing.T) {
	profile := validProfile()
	profile.CredentialMode = CredentialBrokered
	profile.Enforcement = EnforcementBrokered
	if err := profile.Validate(); err == nil {
		t.Fatal("brokered profile without a provider binding was accepted")
	}
	profile.CredentialBinding = &CredentialBinding{
		ConnectionID: "con-1", ProviderRelease: "unfamiliar.session@1",
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("provider-neutral brokered profile rejected: %v", err)
	}
}

func TestAttachModeRejectsCredentialBinding(t *testing.T) {
	profile := validProfile()
	profile.CredentialBinding = &CredentialBinding{
		ConnectionID: "con-1", ProviderRelease: "unfamiliar.session@1",
	}
	if err := profile.Validate(); err == nil {
		t.Fatal("attach mode accepted a credential provider binding")
	}
}

func TestActionOnlyProfileRequiresTypedProviderBinding(t *testing.T) {
	profile := validProfile()
	profile.CredentialMode = CredentialAction
	profile.Enforcement = EnforcementTyped
	profile.ProviderBinding = &ProviderBinding{ConnectionID: "connection-edge", ProviderRelease: "edge.actions@1"}
	if err := profile.Validate(); err != nil {
		t.Fatalf("action-only profile rejected: %v", err)
	}
	profile.CredentialBinding = &CredentialBinding{ConnectionID: "connection-edge", ProviderRelease: "edge.actions@1"}
	if err := profile.Validate(); err == nil {
		t.Fatal("action-only profile accepted a credential binding")
	}
	profile.CredentialBinding = nil
	profile.Enforcement = EnforcementHook
	if err := profile.Validate(); err == nil {
		t.Fatal("action-only profile accepted hook-only enforcement")
	}
}

func TestProfileCanonicalOrderMatchesControlPlaneDigestContract(t *testing.T) {
	encoded, err := json.Marshal(validProfile())
	if err != nil {
		t.Fatal(err)
	}
	value := string(encoded)
	adapter := strings.Index(value, `"adapter_release"`)
	policy := strings.Index(value, `"policy_release"`)
	if adapter < 0 || policy < 0 || adapter > policy {
		t.Fatalf("profile digest field order drifted from the control plane: %s", value)
	}
}

func TestDigestIsStableAcrossMapOrder(t *testing.T) {
	left, err := Digest(map[string]interface{}{"b": 2, "a": 1})
	if err != nil {
		t.Fatal(err)
	}
	right, err := Digest(map[string]interface{}{"a": 1, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("digest changed with map order: %s != %s", left, right)
	}
}

func validProfile() SessionProfile {
	return SessionProfile{
		ID: "profile-1", TenantID: "tenant-1", Name: "Production AWS",
		Agent: AgentCodex, Workspace: "/tmp/project",
		Scope:       Scope{Provider: "aws", AccountRef: "123456789012", Environments: []string{"production"}},
		Enforcement: EnforcementHook, CredentialMode: CredentialAttach,
		PolicyRelease: "policy@1.0.0", AdapterRelease: "codex@1.0.0", CreatedAt: time.Now().UTC(),
	}
}
