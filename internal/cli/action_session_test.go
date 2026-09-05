package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	provideradapter "github.com/misconfig-cloud/provider-sdk"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
)

func seedActionPolicy(t *testing.T, root string, control *stubControl, active localstate.ActiveSession, now time.Time, modify func(*policy.Bundle)) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seedEnrollmentWithKey(t, root, control, base64.RawURLEncoding.EncodeToString(public))
	bundle := policy.Bundle{
		Release: active.Profile.PolicyRelease, TenantID: active.Profile.TenantID, ProfileID: active.Profile.ID,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Rules: []policy.Rule{{ID: "task", Effect: policy.EffectTyped, Providers: []string{active.Profile.Scope.Provider},
			Operations: []string{"ShiftVector"}, ResourcePrefixes: active.Profile.Scope.ResourcePrefixes, ResourceIDs: active.Profile.Scope.ResourceIDs, Reason: "selected work"}},
	}
	if modify != nil {
		modify(&bundle)
	}
	control.signed, err = policy.Sign(bundle, "key-1", private)
	if err != nil {
		t.Fatal(err)
	}
	control.remote = active.Session
}

type actionFixture struct {
	app     *App
	control *stubControl
	active  localstate.ActiveSession
	store   localstate.Store
	output  bytes.Buffer
	now     time.Time
}

func newActionFixture(t *testing.T) *actionFixture {
	t.Helper()
	f := &actionFixture{control: enrolledStub(), now: time.Now().UTC().Truncate(time.Second)}
	f.store = localstate.Store{Root: t.TempDir(), FileTokens: true}
	f.active = localstate.ActiveSession{
		Profile: domain.SessionProfile{ID: "profile-a", TenantID: "tenant-1", Name: "Test task", Agent: domain.AgentCodex, Workspace: "/workspace",
			Scope:       domain.Scope{Provider: "fixture", AccountRef: "system-1", Environments: []string{"test"}, ResourceIDs: []string{"fixture://system-1/selected"}},
			Enforcement: domain.EnforcementTyped, CredentialMode: domain.CredentialAction,
			ProviderBinding: &domain.ProviderBinding{ConnectionID: "connection-a", ProviderRelease: "fixture.session@1"},
			AdapterRelease:  "codex@1", PolicyRelease: "policy@1", CreatedAt: f.now},
		Session: domain.AgentSession{ID: "session-a", TenantID: "tenant-1", ProfileID: "profile-a", ActorID: "actor-1", DeviceID: "device-1", State: domain.SessionRunning, StartedAt: f.now},
	}
	f.active.Session.ProfileDigest, _ = domain.Digest(f.active.Profile)
	path, err := f.store.SaveActive(f.active)
	if err != nil {
		t.Fatal(err)
	}
	seedActionPolicy(t, f.store.Root, f.control, f.active, f.now, nil)
	f.control.typedActions = []controlclient.TypedAction{{ID: "action-a", TenantID: "tenant-1", SessionID: "session-a", Provider: "fixture", AccountRef: "system-1",
		ProviderRelease: "fixture.session@1",
		Environment:     "test", Operation: "ShiftVector", CapabilityRef: "fixture.shift@1", Resource: "fixture://system-1/selected", Parameters: json.RawMessage(`{"bearing":17}`), PolicyRelease: "policy@1"}}
	f.app = &App{In: strings.NewReader(`{"bearing":17}`), Out: &f.output, Err: io.Discard, StateRoot: f.store.Root, FileTokens: true,
		Now: func() time.Time { return f.now }, Getenv: func(key string) string {
			if key == "MISCONFIG_ACTIVE_SESSION" {
				return path
			}
			return ""
		},
		NewControl: func(_, _, _ string) Control { return f.control }}
	return f
}

func TestTypedActionsRejectSessionAndPolicySubstitutionBeforeExecution(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *actionFixture)
	}{
		{"missing active session", func(t *testing.T, f *actionFixture) { f.app.Getenv = func(string) string { return "" } }},
		{"local stop", func(t *testing.T, f *actionFixture) {
			if err := f.store.MarkStopped(f.active.Session.ID); err != nil {
				t.Fatal(err)
			}
		}},
		{"local profile tamper", func(t *testing.T, f *actionFixture) {
			f.active.Profile.Scope.ResourceIDs = []string{"fixture://system-1/other"}
			if _, err := f.store.SaveActive(f.active); err != nil {
				t.Fatal(err)
			}
		}},
		{"remote missing", func(t *testing.T, f *actionFixture) { f.control.remote = domain.AgentSession{} }},
		{"remote stopped", func(t *testing.T, f *actionFixture) { f.control.remote.State = domain.SessionStopped }},
		{"remote session", func(t *testing.T, f *actionFixture) { f.control.remote.ID = "other" }},
		{"remote tenant", func(t *testing.T, f *actionFixture) { f.control.remote.TenantID = "other" }},
		{"remote device", func(t *testing.T, f *actionFixture) { f.control.remote.DeviceID = "other" }},
		{"remote actor", func(t *testing.T, f *actionFixture) { f.control.remote.ActorID = "other" }},
		{"remote digest", func(t *testing.T, f *actionFixture) { f.control.remote.ProfileDigest = "other" }},
		{"policy unavailable", func(t *testing.T, f *actionFixture) { f.control.signed = policy.SignedBundle{} }},
		{"policy signature", func(t *testing.T, f *actionFixture) { f.control.signed.Signature = "invalid" }},
		{"policy expired", func(t *testing.T, f *actionFixture) { f.now = f.now.Add(2 * time.Hour) }},
		{"policy signing key", func(t *testing.T, f *actionFixture) { f.control.signed.KeyID = "other" }},
		{"signed wrong policy profile", func(t *testing.T, f *actionFixture) {
			seedActionPolicy(t, f.store.Root, f.control, f.active, f.now, func(b *policy.Bundle) { b.ProfileID = "other" })
		}},
		{"signed wrong policy tenant", func(t *testing.T, f *actionFixture) {
			seedActionPolicy(t, f.store.Root, f.control, f.active, f.now, func(b *policy.Bundle) { b.TenantID = "other" })
		}},
		{"signed wrong policy release", func(t *testing.T, f *actionFixture) {
			seedActionPolicy(t, f.store.Root, f.control, f.active, f.now, func(b *policy.Bundle) { b.Release = "other" })
		}},
		{"action from other session", func(t *testing.T, f *actionFixture) { f.control.typedActions[0].SessionID = "other" }},
		{"action from other tenant", func(t *testing.T, f *actionFixture) { f.control.typedActions[0].TenantID = "other" }},
		{"action from other provider", func(t *testing.T, f *actionFixture) { f.control.typedActions[0].Provider = "other" }},
		{"action from other account", func(t *testing.T, f *actionFixture) { f.control.typedActions[0].AccountRef = "other" }},
		{"action from other policy", func(t *testing.T, f *actionFixture) { f.control.typedActions[0].PolicyRelease = "other" }},
		{"action outside exact resources", func(t *testing.T, f *actionFixture) { f.control.typedActions[0].Resource += "-other" }},
		{"action outside environment", func(t *testing.T, f *actionFixture) { f.control.typedActions[0].Environment = "production" }},
		{"action not found", func(t *testing.T, f *actionFixture) { f.control.typedActions = nil }},
		{"native allow is not typed authority", func(t *testing.T, f *actionFixture) {
			seedActionPolicy(t, f.store.Root, f.control, f.active, f.now, func(b *policy.Bundle) { b.Rules[0].Effect = policy.EffectAllow })
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newActionFixture(t)
			test.mutate(t, f)
			if err := f.app.Run(context.Background(), []string{"action", "execute", "action-a"}); err == nil {
				t.Fatal("unsafe execution accepted")
			}
			if f.control.executedTypedActionID != "" || f.output.Len() != 0 {
				t.Fatal("execution or action output escaped rejection")
			}
		})
	}
}

func TestActionListCannotEscapeCurrentSession(t *testing.T) {
	f := newActionFixture(t)
	if err := f.app.Run(context.Background(), []string{"action", "list", "--session", "other"}); err == nil {
		t.Fatal("cross-session list allowed")
	}
	if f.control.listedActionSessionID != "" || f.output.Len() != 0 {
		t.Fatal("cross-session list reached control plane")
	}
	if err := f.app.Run(context.Background(), []string{"action", "list", "--session", f.active.Session.ID}); err != nil {
		t.Fatal(err)
	}
	f.output.Reset()
	f.control.typedActions[0].SessionID = "other"
	if err := f.app.Run(context.Background(), []string{"action", "list"}); err == nil || f.output.Len() != 0 {
		t.Fatal("unrelated action disclosed")
	}
}

func TestActionProposalRejectsWrongResourceBeforeBroker(t *testing.T) {
	f := newActionFixture(t)
	if err := f.app.Run(context.Background(), []string{"action", "propose", "--capability", "fixture.shift@1", "--operation", "ShiftVector", "--resource", "fixture://system-1/unselected", "--parameters-file", "-"}); err == nil {
		t.Fatal("unselected resource accepted")
	}
	if f.control.typedActionRequest.SessionID != "" {
		t.Fatal("denied proposal reached broker")
	}
}

func TestTypedActionParameterLimitsApplyBeforeProposalAndExecution(t *testing.T) {
	for _, test := range []struct {
		name, parameters string
		denied           bool
	}{
		{"allowed", `{"bearing":17}`, false},
		{"boundary", `{"bearing":20}`, false},
		{"too large", `{"bearing":21}`, true},
		{"missing required", `{}`, true},
		{"unknown field", `{"bearing":17,"delete":true}`, true},
		{"duplicate field", `{"bearing":21,"bearing":17}`, true},
		{"wrong type", `{"bearing":"17"}`, true},
		{"precision above bound", `{"bearing":20.000000000000000001}`, true},
	} {
		for _, command := range []string{"propose", "execute"} {
			t.Run(test.name+"/"+command, func(t *testing.T) {
				f := newActionFixture(t)
				seedActionPolicy(t, f.store.Root, f.control, f.active, f.now, func(b *policy.Bundle) {
					maximum := json.Number("20")
					b.Rules[0].ParameterLimits = &provideradapter.ParameterLimits{Fields: map[string]provideradapter.ParameterLimit{"bearing": {Type: "integer", Maximum: &maximum}}}
				})
				f.app.In = strings.NewReader(test.parameters)
				f.control.typedActions[0].Parameters = json.RawMessage(test.parameters)
				args := []string{"action", "execute", "action-a"}
				if command == "propose" {
					args = []string{"action", "propose", "--capability", "fixture.shift@1", "--operation", "ShiftVector", "--resource", "fixture://system-1/selected", "--parameters-file", "-"}
				}
				err := f.app.Run(context.Background(), args)
				if (err != nil) != test.denied {
					t.Fatalf("unexpected decision: %v", err)
				}
				if test.denied && (f.control.executedTypedActionID != "" || f.control.typedActionRequest.SessionID != "" || f.output.Len() != 0) {
					t.Fatal("denied parameters reached the broker")
				}
			})
		}
	}
}

func TestTypedActionPreservesLargeIntegerPolicyPrecision(t *testing.T) {
	f := newActionFixture(t)
	seedActionPolicy(t, f.store.Root, f.control, f.active, f.now, func(b *policy.Bundle) {
		b.Rules[0].ParameterLimits = &provideradapter.ParameterLimits{Fields: map[string]provideradapter.ParameterLimit{"bearing": {Type: "integer", AllowedValues: []json.RawMessage{json.RawMessage(`9007199254740993`)}}}}
	})
	f.control.typedActions[0].Parameters = json.RawMessage(`{"bearing":9007199254740993}`)
	if err := f.app.Run(context.Background(), []string{"action", "execute", "action-a"}); err != nil {
		t.Fatal(err)
	}
	f.control.executedTypedActionID = ""
	f.control.typedActions[0].Parameters = json.RawMessage(`{"bearing":9007199254740992}`)
	if err := f.app.Run(context.Background(), []string{"action", "execute", "action-a"}); err == nil || f.control.executedTypedActionID != "" {
		t.Fatal("rounded integer gained authority")
	}
}
