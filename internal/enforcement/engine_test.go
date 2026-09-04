package enforcement

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/hook"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
	"github.com/misconfig-cloud/agent-runtime/internal/spool"
)

type fakeControl struct {
	session      domain.AgentSession
	signed       policy.SignedBundle
	sessionErr   error
	policyErr    error
	receipts     []spool.Receipt
	stopped      bool
	sessionCalls int
	policyCalls  int
}

func (f *fakeControl) Session(context.Context, string) (domain.AgentSession, error) {
	f.sessionCalls++
	return f.session, f.sessionErr
}
func (f *fakeControl) Policy(context.Context, string) (policy.SignedBundle, error) {
	f.policyCalls++
	return f.signed, f.policyErr
}
func (f *fakeControl) PutReceipt(_ context.Context, receipt spool.Receipt) error {
	f.receipts = append(f.receipts, receipt)
	return nil
}
func (f *fakeControl) Stop(context.Context, string, string) error {
	f.stopped = true
	return nil
}

func TestPreAndPostProduceDurableBoundReceipts(t *testing.T) {
	engine, control, activePath, now := fixture(t, policy.EffectAllow)
	input := hook.Input{
		SessionID: "native-session", HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "tool-1",
		ToolInput: map[string]any{"command": "aws ec2 describe-instances --region eu-central-1"},
	}
	result, err := engine.Pre(context.Background(), activePath, input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision.Effect != policy.EffectAllow || len(control.receipts) != 0 {
		t.Fatalf("unexpected pre result: %#v receipts=%#v", result, control.receipts)
	}
	if err := engine.Replay(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(control.receipts) != 1 || control.receipts[0].Outcome != spool.OutcomeApproved {
		t.Fatalf("local receipt did not replay: %#v", control.receipts)
	}
	if control.receipts[0].Action.Operation != "aws.ec2.DescribeInstances" {
		t.Fatalf("action was not preserved in receipt: %#v", control.receipts[0])
	}
	input.HookEventName = "PostToolUse"
	input.ToolResponse = map[string]any{"status": "ok", "secret": "must-not-be-stored"}
	if err := engine.Post(context.Background(), activePath, input); err != nil {
		t.Fatal(err)
	}
	if err := engine.Replay(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(control.receipts) != 2 || control.receipts[1].Outcome != spool.OutcomeSucceeded {
		t.Fatalf("unexpected post receipts: %#v", control.receipts)
	}
	if control.receipts[1].ProviderReceipt == "" || control.receipts[1].ProviderReceipt == "must-not-be-stored" {
		t.Fatal("provider output must be represented only by a digest")
	}
	if !control.receipts[1].RecordedAt.Equal(now) {
		t.Fatalf("receipt clock changed: %s", control.receipts[1].RecordedAt)
	}
}

func TestRemoteStopOverridesLocallyCachedAllow(t *testing.T) {
	engine, control, activePath, _ := fixture(t, policy.EffectAllow)
	control.session.State = domain.SessionStopped
	if err := engine.Refresh(context.Background(), activePath); err != nil {
		t.Fatal(err)
	}
	result, err := engine.Pre(context.Background(), activePath, hook.Input{
		HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "tool-2",
		ToolInput: map[string]any{"command": "aws ec2 describe-instances"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision.Effect != policy.EffectDeny || result.Decision.RuleID != "misconfig.boundary" {
		t.Fatalf("stopped session was not denied: %#v", result.Decision)
	}
}

func TestPreNeverCallsTheControlPlane(t *testing.T) {
	engine, control, activePath, _ := fixture(t, policy.EffectAllow)
	if _, err := engine.Pre(context.Background(), activePath, hook.Input{
		HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "local-only",
		ToolInput: map[string]any{"command": "aws ec2 describe-instances"},
	}); err != nil {
		t.Fatal(err)
	}
	if control.sessionCalls != 0 || control.policyCalls != 0 {
		t.Fatalf("pre hook reached the network: session=%d policy=%d", control.sessionCalls, control.policyCalls)
	}
}

func TestRefreshRejectsRemoteIdentitySubstitution(t *testing.T) {
	engine, control, activePath, _ := fixture(t, policy.EffectAllow)
	control.session.TenantID = "tenant-attacker"
	if err := engine.Refresh(context.Background(), activePath); err == nil {
		t.Fatal("remote tenant substitution was accepted")
	}
	active, err := localstate.LoadActive(activePath)
	if err != nil {
		t.Fatal(err)
	}
	if active.Session.TenantID != "tenant-1" || active.Session.State != domain.SessionRunning {
		t.Fatalf("invalid remote state replaced the local binding: %#v", active.Session)
	}
}

func TestRefreshDoesNotReplaceCacheWithTheWrongSigningKey(t *testing.T) {
	engine, control, activePath, _ := fixture(t, policy.EffectAllow)
	before, err := os.ReadFile(engine.Store.PolicyPath(control.session.ID))
	if err != nil {
		t.Fatal(err)
	}
	control.signed.KeyID = "attacker-key"
	if err := engine.Refresh(context.Background(), activePath); err == nil {
		t.Fatal("policy signed by an unexpected key was accepted")
	}
	after, err := os.ReadFile(engine.Store.PolicyPath(control.session.ID))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("rejected policy changed the verified local cache")
	}
}

func TestPostDoesNotClaimSuccessForOpaqueCodexResponse(t *testing.T) {
	engine, control, activePath, _ := fixture(t, policy.EffectAllow)
	input := hook.Input{
		SessionID: "native-session", HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "opaque-response",
		ToolInput: map[string]any{"command": "aws ec2 describe-instances --region eu-central-1"},
	}
	if _, err := engine.Pre(context.Background(), activePath, input); err != nil {
		t.Fatal(err)
	}
	input.HookEventName = "PostToolUse"
	input.ToolResponse = "command output without a stable exit status"
	if err := engine.Post(context.Background(), activePath, input); err != nil {
		t.Fatal(err)
	}
	for _, receipt := range control.receipts {
		if receipt.Outcome == spool.OutcomeSucceeded {
			t.Fatalf("opaque response was incorrectly recorded as success: %#v", receipt)
		}
	}
}

func TestEvaluationUsesOnlyVerifiedUnexpiredCache(t *testing.T) {
	engine, control, activePath, now := fixture(t, policy.EffectAllow)
	control.sessionErr = errors.New("offline")
	control.policyErr = errors.New("offline")
	control.receipts = nil
	result, err := engine.Pre(context.Background(), activePath, hook.Input{
		HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "offline",
		ToolInput: map[string]any{"command": "aws ec2 describe-instances"},
	})
	if err != nil || result.Decision.Effect != policy.EffectAllow {
		t.Fatalf("valid offline cache was not honored: %#v %v", result.Decision, err)
	}
	engine.Now = func() time.Time { return now.Add(2 * time.Hour) }
	result, err = engine.Pre(context.Background(), activePath, hook.Input{
		HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "expired",
		ToolInput: map[string]any{"command": "aws ec2 describe-instances"},
	})
	if err != nil || result.Decision.RuleID != "misconfig.policy.unavailable" {
		t.Fatalf("expired offline cache did not fail closed: %#v %v", result.Decision, err)
	}
}

func fixture(t *testing.T, effect policy.Effect) (Engine, *fakeControl, string, time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 4, 15, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store := localstate.Store{Root: root}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	profile := domain.SessionProfile{
		ID: "profile-1", TenantID: "tenant-1", Name: "AWS production", Agent: domain.AgentCodex,
		Workspace: root, Scope: domain.Scope{Provider: "aws", AccountRef: "123456789012", Environments: []string{"production"}},
		Enforcement: domain.EnforcementHook, CredentialMode: domain.CredentialAttach,
		PolicyRelease: "policy@1", AdapterRelease: "codex@1", CreatedAt: now,
	}
	digest, err := domain.Digest(profile)
	if err != nil {
		t.Fatal(err)
	}
	session := domain.AgentSession{
		ID: "session-1", TenantID: profile.TenantID, ProfileID: profile.ID, ProfileDigest: digest,
		ActorID: "actor-1", DeviceID: "device-1", State: domain.SessionRunning, StartedAt: now,
	}
	bundle := policy.Bundle{
		Release: profile.PolicyRelease, TenantID: profile.TenantID, ProfileID: profile.ID,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Rules: []policy.Rule{{ID: "decision", Effect: effect, Providers: []string{"aws"}, Operations: []string{"aws.ec2.DescribeInstances"}, Reason: "bounded test rule"}},
	}
	signed, err := policy.Sign(bundle, "key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveConfig(localstate.Config{
		ControlURL: "https://sessions.example.test", TenantID: profile.TenantID, ActorID: session.ActorID,
		DeviceID: session.DeviceID, DeviceName: "laptop", PolicyKeyID: "key-1",
		PolicyPublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
	}); err != nil {
		t.Fatal(err)
	}
	activePath, err := store.SaveActive(localstate.ActiveSession{Profile: profile, Session: session})
	if err != nil {
		t.Fatal(err)
	}
	control := &fakeControl{session: session, signed: signed}
	cache := policy.Cache{Path: store.PolicyPath(session.ID), PublicKey: publicKey, Now: func() time.Time { return now }}
	if err := cache.Store(signed); err != nil {
		t.Fatal(err)
	}
	return Engine{Store: store, Control: control, Now: func() time.Time { return now }}, control, activePath, now
}
