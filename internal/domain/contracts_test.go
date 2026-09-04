package domain

import (
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
