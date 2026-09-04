package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
	"github.com/misconfig-cloud/agent-runtime/internal/spool"
)

type stubControl struct {
	enrollToken string
	enrollment  controlclient.Enrollment
	profiles    []domain.SessionProfile
	sessions    []domain.AgentSession
	started     domain.AgentSession
	remote      domain.AgentSession
	signed      policy.SignedBundle
	created     controlclient.CreateProfileRequest
	stopped     []string
	receipts    []spool.Receipt
}

func (s *stubControl) Enroll(_ context.Context, token, _, _, _, _ string) (controlclient.Enrollment, error) {
	s.enrollToken = token
	return s.enrollment, nil
}
func (s *stubControl) CreateProfile(_ context.Context, request controlclient.CreateProfileRequest) (domain.SessionProfile, string, error) {
	s.created = request
	return s.profiles[0], "sha256:profile", nil
}
func (s *stubControl) Profiles(context.Context) ([]domain.SessionProfile, error) {
	return s.profiles, nil
}
func (s *stubControl) StartSession(context.Context, domain.SessionProfile) (domain.AgentSession, error) {
	if s.started.ID == "" {
		return domain.AgentSession{}, errors.New("not implemented in stub")
	}
	return s.started, nil
}
func (s *stubControl) Session(context.Context, string) (domain.AgentSession, error) {
	if s.remote.ID == "" {
		return domain.AgentSession{}, errors.New("not implemented in stub")
	}
	return s.remote, nil
}
func (s *stubControl) Sessions(context.Context) ([]domain.AgentSession, error) {
	return s.sessions, nil
}
func (s *stubControl) Policy(context.Context, string) (policy.SignedBundle, error) {
	if s.signed.KeyID == "" {
		return policy.SignedBundle{}, errors.New("not implemented in stub")
	}
	return s.signed, nil
}
func (s *stubControl) Stop(_ context.Context, sessionID, _ string) error {
	s.stopped = append(s.stopped, sessionID)
	return nil
}
func (s *stubControl) PutReceipt(_ context.Context, receipt spool.Receipt) error {
	s.receipts = append(s.receipts, receipt)
	return nil
}

func TestSetupAcceptsSecretSourcesButNeverArgv(t *testing.T) {
	tests := []struct {
		name string
		args []string
		in   string
		env  string
		file bool
	}{
		{name: "environment", env: "enroll-from-env"},
		{name: "stdin", args: []string{"--token-file", "-"}, in: "enroll-from-stdin\n"},
		{name: "file", file: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			secret := "enroll-from-file"
			args := append([]string{}, test.args...)
			if test.file {
				path := filepath.Join(root, "enrollment-token")
				if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				args = []string{"--token-file", path}
			} else if test.env != "" {
				secret = test.env
			} else {
				secret = "enroll-from-stdin"
			}
			control := enrolledStub()
			var out bytes.Buffer
			app := &App{
				In: strings.NewReader(test.in), Out: &out, Err: io.Discard, StateRoot: root, FileTokens: true,
				Getenv: func(key string) string {
					if key == "MISCONFIG_ENROLLMENT_TOKEN" {
						return test.env
					}
					return ""
				},
				Hostname:   func() (string, error) { return "test-device", nil },
				NewControl: func(_, _, _ string) Control { return control },
			}
			args = append(args, "--tenant", "tenant-1", "--actor", "actor-1")
			if err := app.Run(context.Background(), append([]string{"setup"}, args...)); err != nil {
				t.Fatal(err)
			}
			if control.enrollToken != secret {
				t.Fatalf("wrong enrollment secret: %q", control.enrollToken)
			}
			if strings.Contains(out.String(), secret) || strings.Contains(out.String(), control.enrollment.DeviceToken) {
				t.Fatal("setup leaked a secret to stdout")
			}
			stored, err := (localstate.Store{Root: root, FileTokens: true}).DeviceToken("device-1")
			if err != nil || stored != control.enrollment.DeviceToken {
				t.Fatalf("device credential was not stored: %q %v", stored, err)
			}
		})
	}
	control := enrolledStub()
	app := &App{In: strings.NewReader(""), Out: io.Discard, Err: io.Discard, StateRoot: t.TempDir(), FileTokens: true, NewControl: func(_, _, _ string) Control { return control }}
	err := app.Run(context.Background(), []string{"setup", "--tenant", "tenant-1", "--actor", "actor-1", "--token", "argv-secret"})
	if err == nil || ExitCode(err) != 2 || control.enrollToken != "" {
		t.Fatalf("argv secret was not rejected before enrollment: %v", err)
	}
}

func TestNativeDecisionContracts(t *testing.T) {
	tests := []struct {
		name, agent string
		effect      policy.Effect
		wantOutput  bool
		permission  string
	}{
		{name: "codex allow is silent", agent: "codex", effect: policy.EffectAllow},
		{name: "codex ask becomes deny", agent: "codex", effect: policy.EffectApproval, wantOutput: true, permission: "deny"},
		{name: "claude ask remains ask", agent: "claude", effect: policy.EffectApproval, wantOutput: true, permission: "ask"},
		{name: "claude allow is explicit", agent: "claude", effect: policy.EffectAllow, wantOutput: true, permission: "allow"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var out bytes.Buffer
			app := &App{Out: &out, Err: io.Discard}
			app.defaults()
			if err := app.nativeDecision(test.agent, policy.Decision{Effect: test.effect, Reason: "bounded by policy"}); err != nil {
				t.Fatal(err)
			}
			if !test.wantOutput {
				if out.Len() != 0 {
					t.Fatalf("allow wrote stdout: %q", out.String())
				}
				return
			}
			var response struct {
				HookSpecificOutput struct {
					Permission string `json:"permissionDecision"`
					Reason     string `json:"permissionDecisionReason"`
				} `json:"hookSpecificOutput"`
			}
			if err := json.Unmarshal(out.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.HookSpecificOutput.Permission != test.permission || response.HookSpecificOutput.Reason == "" {
				t.Fatalf("unexpected native decision: %s", out.String())
			}
		})
	}
}

func TestMalformedPreHookFailsClosed(t *testing.T) {
	var out bytes.Buffer
	app := &App{In: strings.NewReader("not-json"), Out: &out, Err: io.Discard, Getenv: func(key string) string {
		if key == "MISCONFIG_ACTIVE_SESSION" {
			return "/missing"
		}
		return ""
	}}
	err := app.Run(context.Background(), []string{"hook", "pre", "--agent", "codex"})
	if err != nil {
		t.Fatalf("valid native deny should exit zero, got %v", err)
	}
	var response map[string]any
	if json.Unmarshal(out.Bytes(), &response) != nil || !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("malformed input did not emit a valid deny: %q", out.String())
	}

	app = &App{In: strings.NewReader("not-json"), Out: failingWriter{}, Err: io.Discard, Getenv: func(key string) string {
		if key == "MISCONFIG_ACTIVE_SESSION" {
			return "/missing"
		}
		return ""
	}}
	err = app.Run(context.Background(), []string{"hook", "pre", "--agent", "codex"})
	if err == nil || ExitCode(err) != 2 {
		t.Fatalf("deny output failure must exit 2, got %v", err)
	}
}

func TestNativeLaunchConfigurationIsSessionScoped(t *testing.T) {
	root := t.TempDir()
	store := localstate.Store{Root: root, FileTokens: true}
	profile := domain.SessionProfile{ID: "profile-1", Agent: domain.AgentCodex, Workspace: "/workspace"}
	app := &App{}
	name, args, err := app.nativeCommand(store, "/opt/Misconfig Runtime/bin/misconfig", "session-1", profile, []string{"exec", "-c", "approval_policy=never", "probe"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if name != "codex" || !strings.Contains(joined, "hooks.PreToolUse") || !strings.Contains(joined, "hooks.PostToolUse") || !strings.Contains(joined, "hook pre --agent codex") {
		t.Fatalf("invalid Codex launch contract: %s %v", name, args)
	}
	if strings.LastIndex(joined, "hooks.PreToolUse") < strings.LastIndex(joined, "approval_policy=never") || strings.LastIndex(joined, "hooks.PostToolUse") < strings.LastIndex(joined, "approval_policy=never") {
		t.Fatalf("authoritative Codex hooks must follow user configuration overrides: %v", args)
	}

	profile.Agent = domain.AgentClaude
	name, args, err = app.nativeCommand(store, "/opt/misconfig", "session-2", profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if name != "claude" || len(args) != 2 || args[0] != "--settings" || !strings.Contains(args[1], filepath.Join("runtime", "session-2")) {
		t.Fatalf("invalid Claude launch contract: %s %v", name, args)
	}
	encoded, err := os.ReadFile(args[1])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"PreToolUse"`)) || !bytes.Contains(encoded, []byte(`"PostToolUse"`)) ||
		!bytes.Contains(encoded, []byte(`"PostToolUseFailure"`)) || bytes.Count(encoded, []byte("post --agent claude")) != 2 {
		t.Fatalf("Claude settings omitted hooks: %s", encoded)
	}
}

func TestCreateProfileUsesSafeApprovalDefault(t *testing.T) {
	root := t.TempDir()
	workspace := t.TempDir()
	control := enrolledStub()
	control.profiles = []domain.SessionProfile{{ID: "profile-1", Name: "production", Agent: domain.AgentCodex}}
	seedEnrollment(t, root, control)
	app := &App{Out: io.Discard, Err: io.Discard, StateRoot: root, FileTokens: true, Version: "1.2.3", NewControl: func(_, _, _ string) Control { return control }}
	err := app.Run(context.Background(), []string{"profile", "create", "--name", "production", "--workspace", workspace, "--provider", "aws", "--account", "123456789012", "--environment", "production"})
	if err != nil {
		t.Fatal(err)
	}
	if len(control.created.Rules) != 1 || control.created.Rules[0].Effect != policy.EffectApproval || control.created.AdapterRelease != "codex@1.2.3" {
		t.Fatalf("unsafe profile default: %#v", control.created)
	}
}

func TestRunLaunchesNativeAgentWithVerifiedPolicyAndStopsSession(t *testing.T) {
	root := t.TempDir()
	workspace := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	profile := domain.SessionProfile{
		ID: "profile-1", TenantID: "tenant-1", Name: "production", Agent: domain.AgentCodex,
		Workspace: workspace, Scope: domain.Scope{Provider: "aws", AccountRef: "123456789012", Environments: []string{"production"}},
		Enforcement: domain.EnforcementHook, CredentialMode: domain.CredentialAttach,
		AdapterRelease: "codex@1", PolicyRelease: "policy@1", CreatedAt: now,
	}
	digest, err := domain.Digest(profile)
	if err != nil {
		t.Fatal(err)
	}
	session := domain.AgentSession{
		ID: "session-1", TenantID: "tenant-1", ProfileID: profile.ID, ProfileDigest: digest,
		ActorID: "actor-1", DeviceID: "device-1", State: domain.SessionRunning, StartedAt: now,
	}
	signed, err := policy.Sign(policy.Bundle{
		Release: "policy@1", TenantID: "tenant-1", ProfileID: profile.ID,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Rules: []policy.Rule{{ID: "allow-read", Effect: policy.EffectAllow, Reason: "test"}},
	}, "key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	control := enrolledStub()
	control.profiles = []domain.SessionProfile{profile}
	control.started = session
	control.signed = signed
	seedEnrollmentWithKey(t, root, control, base64.RawURLEncoding.EncodeToString(publicKey))

	var launchedName, launchedDir string
	var launchedArgs, launchedEnv []string
	app := &App{
		In: strings.NewReader(""), Out: io.Discard, Err: io.Discard, StateRoot: root, FileTokens: true,
		Now: func() time.Time { return now }, NewControl: func(_, _, _ string) Control { return control },
		LookPath:   func(name string) (string, error) { return "/usr/bin/" + name, nil },
		Executable: func() (string, error) { return "/opt/misconfig", nil },
		RunCommand: func(_ context.Context, name string, args []string, directory string, environment []string, _ io.Reader, _, _ io.Writer) error {
			launchedName, launchedDir = name, directory
			launchedArgs, launchedEnv = append([]string{}, args...), append([]string{}, environment...)
			return nil
		},
	}
	if err := app.Run(context.Background(), []string{"run", "--profile", "production", "--", "resume"}); err != nil {
		t.Fatal(err)
	}
	if launchedName != "codex" || launchedDir != workspace || !strings.Contains(strings.Join(launchedArgs, " "), "hooks.PreToolUse") {
		t.Fatalf("native agent was not launched with hooks: %s %s %v", launchedName, launchedDir, launchedArgs)
	}
	if !containsEnv(launchedEnv, "MISCONFIG_ACTIVE_SESSION=") || !containsEnv(launchedEnv, "MISCONFIG_HOME="+root) {
		t.Fatalf("session environment is incomplete: %v", launchedEnv)
	}
	if len(control.stopped) != 1 || control.stopped[0] != session.ID {
		t.Fatalf("session was not stopped after agent exit: %v", control.stopped)
	}
	if _, err := os.Stat(filepath.Join(root, "policies", session.ID+".json")); err != nil {
		t.Fatalf("verified policy was not cached: %v", err)
	}
}

func TestRunCancelsTheNativeAgentAfterRemoteStop(t *testing.T) {
	root := t.TempDir()
	workspace := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	profile := domain.SessionProfile{
		ID: "profile-1", TenantID: "tenant-1", Name: "production", Agent: domain.AgentCodex,
		Workspace: workspace, Scope: domain.Scope{Provider: "aws", AccountRef: "123456789012", Environments: []string{"production"}},
		Enforcement: domain.EnforcementHook, CredentialMode: domain.CredentialAttach,
		AdapterRelease: "codex@1", PolicyRelease: "policy@1", CreatedAt: now,
	}
	digest, err := domain.Digest(profile)
	if err != nil {
		t.Fatal(err)
	}
	running := domain.AgentSession{
		ID: "session-1", TenantID: "tenant-1", ProfileID: profile.ID, ProfileDigest: digest,
		ActorID: "actor-1", DeviceID: "device-1", State: domain.SessionRunning, StartedAt: now,
	}
	stopped := running
	stopped.State = domain.SessionStopped
	stoppedAt := now.Add(time.Minute)
	stopped.StoppedAt = &stoppedAt
	signed, err := policy.Sign(policy.Bundle{
		Release: "policy@1", TenantID: "tenant-1", ProfileID: profile.ID,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Rules: []policy.Rule{{ID: "allow-read", Effect: policy.EffectAllow, Reason: "test"}},
	}, "key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	control := enrolledStub()
	control.profiles = []domain.SessionProfile{profile}
	control.started = running
	control.remote = stopped
	control.signed = signed
	seedEnrollmentWithKey(t, root, control, base64.RawURLEncoding.EncodeToString(publicKey))

	var out bytes.Buffer
	app := &App{
		In: strings.NewReader(""), Out: &out, Err: io.Discard, StateRoot: root, FileTokens: true,
		Now: func() time.Time { return now }, NewControl: func(_, _, _ string) Control { return control },
		LookPath:        func(name string) (string, error) { return "/usr/bin/" + name, nil },
		Executable:      func() (string, error) { return "/opt/misconfig", nil },
		RefreshInterval: time.Millisecond,
		RunCommand: func(ctx context.Context, _ string, _ []string, _ string, _ []string, _ io.Reader, _, _ io.Writer) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	if err := app.Run(context.Background(), []string{"run", "--profile", "production"}); err != nil {
		t.Fatal(err)
	}
	if len(control.stopped) != 0 {
		t.Fatalf("already stopped remote session was stopped again: %v", control.stopped)
	}
	if !strings.Contains(out.String(), "was stopped remotely") {
		t.Fatalf("remote stop was not explained: %s", out.String())
	}
	active, err := localstate.LoadActive(filepath.Join(root, "sessions", running.ID+".json"))
	if err != nil || active.Session.State != domain.SessionStopped {
		t.Fatalf("remote stop was not persisted: %#v %v", active.Session, err)
	}
}

func TestStatusAndUninstallAreLimitedToThisDevice(t *testing.T) {
	root := t.TempDir()
	control := enrolledStub()
	control.sessions = []domain.AgentSession{
		{ID: "own-running", TenantID: "tenant-1", DeviceID: "device-1", State: domain.SessionRunning},
		{ID: "own-stopped", TenantID: "tenant-1", DeviceID: "device-1", State: domain.SessionStopped},
		{ID: "other-running", TenantID: "tenant-1", DeviceID: "device-2", State: domain.SessionRunning},
	}
	seedEnrollment(t, root, control)
	var out bytes.Buffer
	app := &App{Out: &out, Err: io.Discard, StateRoot: root, FileTokens: true, NewControl: func(_, _, _ string) Control { return control }}
	if err := app.Run(context.Background(), []string{"status", "--json"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "other-running") || !strings.Contains(out.String(), "own-running") || !strings.Contains(out.String(), "own-stopped") {
		t.Fatalf("status crossed the device boundary: %s", out.String())
	}
	if err := app.Run(context.Background(), []string{"uninstall", "--yes"}); err != nil {
		t.Fatal(err)
	}
	if len(control.stopped) != 1 || control.stopped[0] != "own-running" {
		t.Fatalf("uninstall stopped the wrong sessions: %v", control.stopped)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("local state still exists after uninstall: %v", err)
	}
}

func TestSyncReplaysDurableReceiptsWithoutStartingAnAgent(t *testing.T) {
	root := t.TempDir()
	control := enrolledStub()
	seedEnrollment(t, root, control)
	now := time.Date(2026, 9, 4, 17, 0, 0, 0, time.UTC)
	action := domain.ActionEnvelope{
		ID: "action-sync", TenantID: "tenant-1", ActorID: "actor-1", DeviceID: "device-1",
		SessionID: "session-sync", Agent: domain.AgentCodex, AdapterRelease: "codex@1",
		Tool: "Bash", Operation: "aws.sts.GetCallerIdentity", Resource: "aws://123456789012",
		Destination: domain.Destination{Provider: "aws", AccountRef: "123456789012", Environment: "production"},
		RequestedAt: now,
	}
	receipt, err := spool.NewReceipt(action, policy.Decision{
		Effect: policy.EffectAllow, RuleID: "allow-sts", PolicyRelease: "policy@1",
	}, spool.OutcomeApproved, "", now)
	if err != nil {
		t.Fatal(err)
	}
	store := localstate.Store{Root: root, FileTokens: true}
	if err := (spool.Store{Root: store.ReceiptRoot()}).Put(receipt); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	app := &App{Out: &out, Err: io.Discard, StateRoot: root, FileTokens: true, NewControl: func(_, _, _ string) Control { return control }}
	if err := app.Run(context.Background(), []string{"sync"}); err != nil {
		t.Fatal(err)
	}
	if len(control.receipts) != 1 || control.receipts[0].ID != receipt.ID {
		t.Fatalf("sync did not upload the durable receipt once: %#v", control.receipts)
	}
	pending, err := (spool.Store{Root: store.ReceiptRoot()}).Pending()
	if err != nil || len(pending) != 0 {
		t.Fatalf("sync left pending receipts: %#v %v", pending, err)
	}
	if !strings.Contains(out.String(), "1 pending receipt(s) synchronized") {
		t.Fatalf("sync result was not explained: %s", out.String())
	}
}

func enrolledStub() *stubControl {
	control := &stubControl{}
	control.enrollment.Device.ID = "device-1"
	control.enrollment.Device.TenantID = "tenant-1"
	control.enrollment.Device.ActorID = "actor-1"
	control.enrollment.DeviceToken = "device-secret"
	control.enrollment.PolicyKeyID = "key-1"
	control.enrollment.PolicyPublicKey = "public-key"
	return control
}

func seedEnrollment(t *testing.T, root string, control *stubControl) {
	seedEnrollmentWithKey(t, root, control, "public-key")
}

func seedEnrollmentWithKey(t *testing.T, root string, control *stubControl, publicKey string) {
	t.Helper()
	store := localstate.Store{Root: root, FileTokens: true}
	if err := store.PutDeviceToken("device-1", control.enrollment.DeviceToken); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveConfig(localstate.Config{ControlURL: "https://control.test", TenantID: "tenant-1", ActorID: "actor-1", DeviceID: "device-1", PolicyKeyID: "key-1", PolicyPublicKey: publicKey}); err != nil {
		t.Fatal(err)
	}
}

func containsEnv(environment []string, prefix string) bool {
	for _, value := range environment {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed pipe") }
