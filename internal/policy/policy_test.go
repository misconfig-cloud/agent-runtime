package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
)

func TestEvaluatorDeniesOutsideScopeBeforeAllowRule(t *testing.T) {
	profile, session, action, bundle := fixture(t)
	action.Destination.AccountRef = "999999999999"
	decision := (Evaluator{Bundle: bundle}).Evaluate(profile, session, action, time.Now().UTC())
	if decision.Effect != EffectDeny || decision.RuleID != "misconfig.boundary" {
		t.Fatalf("unexpected decision: %#v", decision)
	}
}

func TestEvaluatorDenyOverridesAllow(t *testing.T) {
	profile, session, action, bundle := fixture(t)
	bundle.Rules = []Rule{
		{ID: "allow-aws", Effect: EffectAllow, Providers: []string{"aws"}, Reason: "reads are allowed"},
		{ID: "deny-delete", Effect: EffectDeny, Operations: []string{"DeleteBucket"}, Reason: "destructive action denied"},
	}
	action.Operation = "DeleteBucket"
	decision := (Evaluator{Bundle: bundle}).Evaluate(profile, session, action, time.Now().UTC())
	if decision.Effect != EffectDeny || decision.RuleID != "deny-delete" {
		t.Fatalf("unexpected decision: %#v", decision)
	}
}

func TestSignedCacheRejectsTamperingAndExpiry(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, bundle := fixture(t)
	signed, err := Sign(bundle, "staging-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	cache := Cache{Path: t.TempDir() + "/policy.json", PublicKey: publicKey}
	if err := cache.Store(signed); err != nil {
		t.Fatal(err)
	}
	loaded, err := cache.Load()
	if err != nil || loaded.Bundle.Release != bundle.Release {
		t.Fatalf("load signed policy: %v %#v", err, loaded)
	}

	signed.Bundle.Release = "policy@tampered"
	if err := cache.Store(signed); err == nil {
		t.Fatal("expected tampered bundle to be rejected")
	}

	cache.Now = func() time.Time { return bundle.ExpiresAt.Add(time.Second) }
	if _, err := cache.Load(); err == nil {
		t.Fatal("expected expired cached bundle to be rejected")
	}
}

func fixture(t *testing.T) (domain.SessionProfile, domain.AgentSession, domain.ActionEnvelope, Bundle) {
	t.Helper()
	now := time.Now().UTC()
	profile := domain.SessionProfile{
		ID: "profile-1", TenantID: "tenant-1", Name: "AWS production", Agent: domain.AgentCodex,
		Workspace: "/tmp/repo", Scope: domain.Scope{Provider: "aws", AccountRef: "123456789012", Environments: []string{"production"}, ResourcePrefixes: []string{"arn:aws:"}},
		Enforcement: domain.EnforcementHook, CredentialMode: domain.CredentialAttach,
		PolicyRelease: "policy@1.0.0", AdapterRelease: "codex@1.0.0", CreatedAt: now,
	}
	digest, err := domain.Digest(profile)
	if err != nil {
		t.Fatal(err)
	}
	session := domain.AgentSession{
		ID: "session-1", TenantID: profile.TenantID, ProfileID: profile.ID, ProfileDigest: digest,
		ActorID: "user-1", DeviceID: "device-1", State: domain.SessionRunning, StartedAt: now,
	}
	action := domain.ActionEnvelope{
		ID: "action-1", TenantID: profile.TenantID, ActorID: session.ActorID, DeviceID: session.DeviceID,
		SessionID: session.ID, Agent: profile.Agent, AdapterRelease: profile.AdapterRelease,
		Tool: "aws", Operation: "DescribeInstances", Resource: "arn:aws:ec2:eu-central-1:123456789012:instance/*",
		Destination: domain.Destination{Provider: "aws", AccountRef: profile.Scope.AccountRef, Environment: "production", Location: "eu-central-1"},
		RequestedAt: now,
	}
	bundle := Bundle{
		Release: profile.PolicyRelease, TenantID: profile.TenantID, ProfileID: profile.ID,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Rules: []Rule{{ID: "allow-read", Effect: EffectAllow, Providers: []string{"aws"}, Operations: []string{"DescribeInstances"}, Reason: "inventory read is within scope"}},
	}
	return profile, session, action, bundle
}
