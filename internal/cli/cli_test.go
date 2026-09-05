package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	provideradapter "github.com/misconfig-cloud/provider-sdk"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/credentialruntime"
	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
	"github.com/misconfig-cloud/agent-runtime/internal/spool"
)

type stubControl struct {
	enrollToken            string
	enrollment             controlclient.Enrollment
	profiles               []domain.SessionProfile
	sessions               []domain.AgentSession
	started                domain.AgentSession
	remote                 domain.AgentSession
	signed                 policy.SignedBundle
	created                controlclient.CreateProfileRequest
	successor              controlclient.ProfileSuccessor
	successorOf            string
	successorIn            controlclient.CreateProfileSuccessorRequest
	stopped                []string
	receipts               []spool.Receipt
	credentialProviders    []controlclient.CredentialProvider
	credentialConnections  []controlclient.CredentialConnection
	preparedConnection     controlclient.PreparedCredentialConnection
	connectionRequest      controlclient.CreateCredentialConnectionRequest
	verifiedConnectionID   string
	revokedConnectionID    string
	credentialMaterial     controlclient.CredentialMaterial
	credentialSessionID    string
	credentialRequestID    string
	typedActions           []controlclient.TypedAction
	typedActionRequest     controlclient.CreateTypedActionRequest
	executedTypedActionID  string
	listedActionSessionID  string
	authorizationStart     controlclient.DeviceAuthorizationStart
	authorizationExchanges []controlclient.DeviceAuthorizationExchange
	authorizationPolls     int
}

func (s *stubControl) Enroll(_ context.Context, token, _, _, _, _ string) (controlclient.Enrollment, error) {
	s.enrollToken = token
	return s.enrollment, nil
}
func (s *stubControl) CreateDeviceAuthorization(_ context.Context, deviceName string) (controlclient.DeviceAuthorizationStart, error) {
	if s.authorizationStart.DeviceCode == "" {
		return controlclient.DeviceAuthorizationStart{}, errors.New("not implemented in stub")
	}
	return s.authorizationStart, nil
}
func (s *stubControl) ExchangeDeviceAuthorization(context.Context, string) (controlclient.DeviceAuthorizationExchange, error) {
	if s.authorizationPolls >= len(s.authorizationExchanges) {
		return controlclient.DeviceAuthorizationExchange{}, errors.New("unexpected authorization poll")
	}
	result := s.authorizationExchanges[s.authorizationPolls]
	s.authorizationPolls++
	return result, nil
}
func (s *stubControl) CreateProfile(_ context.Context, request controlclient.CreateProfileRequest) (domain.SessionProfile, string, error) {
	s.created = request
	return s.profiles[0], "sha256:profile", nil
}
func (s *stubControl) CreateProfileSuccessor(_ context.Context, profileID string, request controlclient.CreateProfileSuccessorRequest) (controlclient.ProfileSuccessor, error) {
	s.successorOf, s.successorIn = profileID, request
	if s.successor.Profile.ID == "" {
		return controlclient.ProfileSuccessor{}, errors.New("not implemented in stub")
	}
	return s.successor, nil
}
func (s *stubControl) Profiles(context.Context) ([]domain.SessionProfile, error) {
	return s.profiles, nil
}
func (s *stubControl) CredentialProviders(context.Context) ([]controlclient.CredentialProvider, error) {
	return s.credentialProviders, nil
}
func (s *stubControl) CreateCredentialConnection(_ context.Context, request controlclient.CreateCredentialConnectionRequest) (controlclient.PreparedCredentialConnection, error) {
	s.connectionRequest = request
	return s.preparedConnection, nil
}
func (s *stubControl) CredentialConnections(context.Context) ([]controlclient.CredentialConnection, error) {
	return s.credentialConnections, nil
}
func (s *stubControl) VerifyCredentialConnection(_ context.Context, connectionID string) (controlclient.CredentialConnection, error) {
	s.verifiedConnectionID = connectionID
	for _, connection := range s.credentialConnections {
		if connection.ID == connectionID {
			connection.State = "verified"
			return connection, nil
		}
	}
	return controlclient.CredentialConnection{}, errors.New("not implemented in stub")
}
func (s *stubControl) RevokeCredentialConnection(_ context.Context, connectionID string) error {
	s.revokedConnectionID = connectionID
	return nil
}
func (s *stubControl) CredentialLease(_ context.Context, sessionID, requestID string) (controlclient.CredentialMaterial, error) {
	s.credentialSessionID = sessionID
	s.credentialRequestID = requestID
	if s.credentialMaterial.Kind == "" {
		return controlclient.CredentialMaterial{}, errors.New("not implemented in stub")
	}
	return s.credentialMaterial, nil
}
func (s *stubControl) CreateTypedAction(_ context.Context, request controlclient.CreateTypedActionRequest) (controlclient.TypedAction, error) {
	s.typedActionRequest = request
	if len(s.typedActions) == 0 {
		return controlclient.TypedAction{}, errors.New("not implemented in stub")
	}
	return s.typedActions[0], nil
}
func (s *stubControl) TypedActions(_ context.Context, sessionID string) ([]controlclient.TypedAction, error) {
	s.listedActionSessionID = sessionID
	return s.typedActions, nil
}
func (s *stubControl) ExecuteTypedAction(_ context.Context, actionID string) (controlclient.TypedAction, error) {
	s.executedTypedActionID = actionID
	for _, action := range s.typedActions {
		if action.ID == actionID {
			return action, nil
		}
	}
	return controlclient.TypedAction{}, errors.New("not implemented in stub")
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
			args = append(args, "--tenant", "tenant-1", "--actor", "actor-1", "--yes")
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

func TestSetupUsesBrowserPairingAndPreviewsEveryLocalChange(t *testing.T) {
	root := t.TempDir()
	control := enrolledStub()
	control.authorizationStart = controlclient.DeviceAuthorizationStart{
		DeviceCode: "device-code", UserCode: "ABCD-EFGH-JKLM",
		VerificationURI:         "https://console.test/device",
		VerificationURIComplete: "https://console.test/device?user_code=ABCD-EFGH-JKLM",
		ExpiresIn:               600, Interval: 3,
	}
	control.authorizationExchanges = []controlclient.DeviceAuthorizationExchange{
		{State: "pending"},
		{State: "authorized", Enrollment: control.enrollment},
	}
	var out bytes.Buffer
	opened := ""
	app := &App{
		In: strings.NewReader(""), Out: &out, Err: io.Discard, StateRoot: root, FileTokens: true,
		Hostname:        func() (string, error) { return "founder-laptop", nil },
		OpenURL:         func(target string) error { opened = target; return nil },
		RefreshInterval: time.Millisecond,
		NewControl:      func(_, _, _ string) Control { return control },
	}
	if err := app.Run(context.Background(), []string{"setup", "--control", "https://control.test", "--yes"}); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Setup preview", "https://control.test", "founder-laptop", filepath.Join(root, "config.json"),
		filepath.Join(root, "secrets", "<device-id>"), "authenticated browser approval",
		"Codex configuration: unchanged", "Claude configuration: unchanged",
		"AWS and Kubernetes credentials: not read, copied, or uploaded", "ABCD-EFGH-JKLM",
	} {
		if !strings.Contains(out.String(), expected) {
			t.Fatalf("setup preview omitted %q:\n%s", expected, out.String())
		}
	}
	if opened != control.authorizationStart.VerificationURIComplete || control.authorizationPolls != 2 {
		t.Fatalf("browser pairing was not completed: opened=%q polls=%d", opened, control.authorizationPolls)
	}
	config, err := (localstate.Store{Root: root, FileTokens: true}).LoadConfig()
	if err != nil || config.TenantID != "tenant-1" || config.ActorID != "actor-1" || config.DeviceID != "device-1" {
		t.Fatalf("paired identity was not stored: %#v %v", config, err)
	}
	if strings.Contains(out.String(), control.enrollment.DeviceToken) || strings.Contains(out.String(), "device-code") {
		t.Fatal("setup leaked a device credential")
	}
}

func TestSetupCancellationMakesNoChangesAndNoNetworkRequest(t *testing.T) {
	root := t.TempDir()
	control := enrolledStub()
	var out bytes.Buffer
	app := &App{
		In: strings.NewReader("no\n"), Out: &out, Err: io.Discard, StateRoot: root, FileTokens: true,
		Hostname:   func() (string, error) { return "cancelled-laptop", nil },
		NewControl: func(_, _, _ string) Control { return control },
	}
	if err := app.Run(context.Background(), []string{"setup", "--control", "https://control.test"}); err != nil {
		t.Fatal(err)
	}
	if control.enrollToken != "" || control.authorizationPolls != 0 || control.authorizationStart.DeviceCode != "" {
		t.Fatal("cancelled setup reached the control plane")
	}
	if _, err := os.Stat(filepath.Join(root, "config.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled setup wrote local state: %v", err)
	}
	if !strings.Contains(out.String(), "No files, credentials, or agent configuration were changed") {
		t.Fatalf("cancellation was not explicit: %s", out.String())
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
		{name: "codex deny remains deny", agent: "codex", effect: policy.EffectDeny, wantOutput: true, permission: "deny"},
		{name: "codex ask becomes deny", agent: "codex", effect: policy.EffectApproval, wantOutput: true, permission: "deny"},
		{name: "claude ask remains ask", agent: "claude", effect: policy.EffectApproval, wantOutput: true, permission: "ask"},
		{name: "claude allow is explicit", agent: "claude", effect: policy.EffectAllow, wantOutput: true, permission: "allow"},
		{name: "claude deny remains deny", agent: "claude", effect: policy.EffectDeny, wantOutput: true, permission: "deny"},
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

func TestCreateActionOnlyProfileBindsProviderWithoutCredentials(t *testing.T) {
	root := t.TempDir()
	workspace := t.TempDir()
	control := enrolledStub()
	control.profiles = []domain.SessionProfile{{ID: "profile-action", Name: "edge actions", Agent: domain.AgentClaude}}
	seedEnrollment(t, root, control)
	app := &App{Out: io.Discard, Err: io.Discard, StateRoot: root, FileTokens: true, Version: "1.2.3", NewControl: func(_, _, _ string) Control { return control }}
	err := app.Run(context.Background(), []string{
		"profile", "create", "--name", "edge actions", "--agent", "claude", "--workspace", workspace,
		"--provider", "unfamiliar-edge", "--account", "target-7", "--environment", "production",
		"--credential-mode", "action_only", "--provider-connection", "connection-edge", "--provider-release", "edge.actions@1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if control.created.CredentialBinding != nil || control.created.ProviderBinding == nil ||
		control.created.ProviderBinding.ConnectionID != "connection-edge" || control.created.ProviderBinding.ProviderRelease != "edge.actions@1" ||
		control.created.Enforcement != domain.EnforcementTyped {
		t.Fatalf("action-only provider binding was not preserved: %#v", control.created)
	}
}

func TestProfileMigrationExplicitlyCreatesANewRuntimeSuccessor(t *testing.T) {
	root := t.TempDir()
	legacy := domain.SessionProfile{ID: "profile-legacy", Name: "production", Agent: domain.AgentCodex}
	control := enrolledStub()
	control.profiles = []domain.SessionProfile{legacy}
	control.successor.Profile = domain.SessionProfile{ID: "profile-successor", Name: "production (successor)", Agent: domain.AgentCodex}
	seedEnrollment(t, root, control)
	var out bytes.Buffer
	app := &App{
		Out: &out, Err: io.Discard, StateRoot: root, FileTokens: true, Version: "2.4.0",
		NewControl: func(_, _, _ string) Control { return control },
	}
	if err := app.Run(context.Background(), []string{"profile", "migrate", "--profile", legacy.ID, "--policy-ttl", "600"}); err != nil {
		t.Fatal(err)
	}
	if control.successorOf != legacy.ID || control.successorIn.AdapterRelease != "codex@2.4.0" || control.successorIn.PolicyTTLSeconds != 600 {
		t.Fatalf("successor request is not bound to the legacy profile and current runtime: %q %#v", control.successorOf, control.successorIn)
	}
	if !strings.Contains(out.String(), "profile-successor") || !strings.Contains(out.String(), "immutable profile profile-legacy") {
		t.Fatalf("migration output does not guide the next launch: %q", out.String())
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

type orbitalCredentialAdapter struct{}

func (orbitalCredentialAdapter) CredentialKind() string { return "orbital.exec-token.v9" }
func (orbitalCredentialAdapter) SensitiveEnvironment() []string {
	return []string{"ORBITAL_TOKEN", "ORBITAL_PROFILE"}
}
func (orbitalCredentialAdapter) Configure(request credentialruntime.ConfigureRequest) ([]string, error) {
	if request.Provider.Provider != "orbital-fabric" || request.Profile.Scope.Provider != "orbital-fabric" {
		return nil, errors.New("orbital adapter received the wrong provider")
	}
	return credentialruntime.SetEnvironment(request.BaseEnv, map[string]string{
		"ORBITAL_SESSION": request.Session.ID,
	}), nil
}

func TestRunSupportsACompiledUnfamiliarCredentialAdapter(t *testing.T) {
	t.Setenv("ORBITAL_TOKEN", "ambient-secret")
	root := t.TempDir()
	workspace := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	profile := domain.SessionProfile{
		ID: "profile-orbital", TenantID: "tenant-1", Name: "Orbital production", Agent: domain.AgentCodex,
		Workspace: workspace,
		Scope: domain.Scope{
			Provider: "orbital-fabric", AccountRef: "station-9", Environments: []string{"production"},
			ResourcePrefixes: []string{"orbital://station-9/"},
		},
		Enforcement: domain.EnforcementBrokered, CredentialMode: domain.CredentialBrokered,
		CredentialBinding: &domain.CredentialBinding{
			ConnectionID: "connection-orbital", ProviderRelease: "orbital.session@3.7.1",
		},
		AdapterRelease: "codex@1", PolicyRelease: "policy@1", CreatedAt: now,
	}
	digest, err := domain.Digest(profile)
	if err != nil {
		t.Fatal(err)
	}
	session := domain.AgentSession{
		ID: "session-orbital", TenantID: "tenant-1", ProfileID: profile.ID, ProfileDigest: digest,
		ActorID: "actor-1", DeviceID: "device-1", State: domain.SessionRunning, StartedAt: now,
	}
	signed, err := policy.Sign(policy.Bundle{
		Release: "policy@1", TenantID: "tenant-1", ProfileID: profile.ID,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Rules: []policy.Rule{{
			ID: "allow-orbital-read", Effect: policy.EffectAllow, Providers: []string{"orbital-fabric"},
			Operations: []string{"tool.OrbitalRead"}, ResourcePrefixes: []string{"orbital://station-9/"}, Reason: "bounded read",
		}},
	}, "key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	control := enrolledStub()
	control.profiles = []domain.SessionProfile{profile}
	control.started = session
	control.signed = signed
	control.credentialProviders = []controlclient.CredentialProvider{{
		Release: "orbital.session@3.7.1", Provider: "orbital-fabric", CredentialKind: "orbital.exec-token.v9",
		MaximumTTLSeconds: 300, RevocationSemantics: "renewal-stops-token-expires",
	}}
	seedEnrollmentWithKey(t, root, control, base64.RawURLEncoding.EncodeToString(publicKey))

	var launchedEnv []string
	app := &App{
		In: strings.NewReader(""), Out: io.Discard, Err: io.Discard, StateRoot: root, FileTokens: true,
		Now: func() time.Time { return now }, NewControl: func(_, _, _ string) Control { return control },
		LookPath:   func(name string) (string, error) { return "/usr/bin/" + name, nil },
		Executable: func() (string, error) { return "/opt/misconfig", nil },
		CredentialAdapters: []credentialruntime.Adapter{
			credentialruntime.AWS{}, orbitalCredentialAdapter{},
		},
		RunCommand: func(_ context.Context, _ string, _ []string, _ string, environment []string, _ io.Reader, _, _ io.Writer) error {
			launchedEnv = append([]string{}, environment...)
			return nil
		},
	}
	if err := app.Run(context.Background(), []string{"run", "--profile", profile.ID}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(launchedEnv, "\n")
	if strings.Contains(joined, "ambient-secret") || !strings.Contains(joined, "ORBITAL_SESSION="+session.ID) {
		t.Fatalf("unfamiliar provider runtime boundary was not applied: %s", joined)
	}
	if len(control.stopped) != 1 || control.stopped[0] != session.ID {
		t.Fatalf("unfamiliar provider session was not stopped: %v", control.stopped)
	}
}

func TestRunDiscoversAndStagesAnAdmittedUnfamiliarCredentialRenderer(t *testing.T) {
	t.Setenv("ORBITAL_TOKEN", "ambient-secret")
	root := t.TempDir()
	workspace := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	profile := domain.SessionProfile{
		ID: "profile-orbital-external", TenantID: "tenant-1", Name: "Orbital production", Agent: domain.AgentCodex,
		Workspace: workspace,
		Scope: domain.Scope{
			Provider: "orbital-fabric", AccountRef: "station-9", Environments: []string{"production"},
			ResourcePrefixes: []string{"orbital://station-9/"},
		},
		Enforcement: domain.EnforcementBrokered, CredentialMode: domain.CredentialBrokered,
		CredentialBinding: &domain.CredentialBinding{ConnectionID: "connection-orbital", ProviderRelease: "orbital-fabric.session@3.7.1"},
		AdapterRelease:    "codex@1", PolicyRelease: "policy@1", CreatedAt: now,
	}
	profileDigest, err := domain.Digest(profile)
	if err != nil {
		t.Fatal(err)
	}
	session := domain.AgentSession{
		ID: "session-orbital-external", TenantID: "tenant-1", ProfileID: profile.ID, ProfileDigest: profileDigest,
		ActorID: "actor-1", DeviceID: "device-1", State: domain.SessionRunning, StartedAt: now,
	}
	signed, err := policy.Sign(policy.Bundle{
		Release: "policy@1", TenantID: "tenant-1", ProfileID: profile.ID,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Rules: []policy.Rule{{ID: "allow-orbital-read", Effect: policy.EffectAllow, Providers: []string{"orbital-fabric"}, Reason: "bounded read"}},
	}, "key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("signed-unfamiliar-renderer")
	source := filepath.Join(t.TempDir(), "orbital-renderer")
	if err := os.WriteFile(source, artifact, 0o700); err != nil {
		t.Fatal(err)
	}
	artifactDigest := sha256.Sum256(artifact)
	provider := controlclient.CredentialProvider{
		Release: "orbital-fabric.session@3.7.1", Provider: "orbital-fabric", CredentialKind: "orbital.exec-token.v9",
		MaximumTTLSeconds: 300, RevocationSemantics: "renewal-stops-token-expires",
		ManifestDigest: "sha256:" + strings.Repeat("a", 64), PublisherID: "fixture-labs",
		RendererProtocol: provideradapter.RendererProtocol, RendererExecutable: "orbital-renderer",
		RendererArtifacts:    []controlclient.RendererArtifact{{OS: runtime.GOOS, Arch: runtime.GOARCH, Digest: "sha256:" + fmt.Sprintf("%x", artifactDigest)}},
		SensitiveEnvironment: []string{"ORBITAL_TOKEN", "ORBITAL_CONFIG"},
		AdmissionRequired:    true,
	}
	control := enrolledStub()
	control.profiles = []domain.SessionProfile{profile}
	control.started = session
	control.signed = signed
	control.credentialProviders = []controlclient.CredentialProvider{provider}
	seedEnrollmentWithKey(t, root, control, base64.RawURLEncoding.EncodeToString(publicKey))

	var configured provideradapter.ConfigureRequest
	var launchedEnv []string
	app := &App{
		In: strings.NewReader(""), Out: io.Discard, Err: io.Discard, StateRoot: root, FileTokens: true,
		Now: func() time.Time { return now }, NewControl: func(_, _, _ string) Control { return control },
		LookPath: func(name string) (string, error) {
			if name == provider.RendererExecutable {
				return source, nil
			}
			return "/usr/bin/" + name, nil
		},
		Executable: func() (string, error) { return "/opt/misconfig", nil },
		RunRenderer: func(_ context.Context, path, operation string, input []byte) ([]byte, error) {
			if operation != "configure" || filepath.Dir(path) != (localstate.Store{Root: root, FileTokens: true}).RuntimeDirectory(session.ID) {
				t.Fatalf("renderer was not invoked from the session boundary: %q %q", path, operation)
			}
			if err := json.Unmarshal(input, &configured); err != nil {
				t.Fatal(err)
			}
			return json.Marshal(provideradapter.RenderedEnvironment{
				Remove: []string{"ORBITAL_TOKEN"}, Set: map[string]string{"ORBITAL_SESSION": session.ID},
			})
		},
		RunCommand: func(_ context.Context, _ string, _ []string, _ string, environment []string, _ io.Reader, _, _ io.Writer) error {
			launchedEnv = append([]string{}, environment...)
			return nil
		},
	}
	if err := app.Run(context.Background(), []string{"run", "--profile", profile.ID}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(launchedEnv, "\n")
	if strings.Contains(joined, "ambient-secret") || !strings.Contains(joined, "ORBITAL_SESSION="+session.ID) {
		t.Fatalf("external provider boundary was not applied: %s", joined)
	}
	if configured.Provider != provider.Provider || configured.Release != provider.Release || configured.ManifestDigest != provider.ManifestDigest || configured.SessionID != session.ID {
		t.Fatalf("renderer coordinates drifted: %#v", configured)
	}
	if len(control.stopped) != 1 || control.stopped[0] != session.ID {
		t.Fatalf("external provider session was not stopped: %v", control.stopped)
	}
	if _, err := os.Stat((localstate.Store{Root: root, FileTokens: true}).RuntimeDirectory(session.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ephemeral renderer directory remains after session stop: %v", err)
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

func TestUninstallWithoutEnrollmentIsIdempotent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-created")
	var out bytes.Buffer
	app := &App{Out: &out, Err: io.Discard, StateRoot: root, FileTokens: true}
	if err := app.Run(context.Background(), []string{"uninstall", "--yes"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No enrollment found") {
		t.Fatalf("unenrolled removal was not explained: %s", out.String())
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unenrolled state root exists after uninstall: %v", err)
	}
	if err := app.Run(context.Background(), []string{"uninstall", "--yes"}); err != nil {
		t.Fatalf("repeated uninstall failed: %v", err)
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

func TestCredentialCommandsDiscoverAndManageProviderNeutralConnections(t *testing.T) {
	root := t.TempDir()
	control := enrolledStub()
	seedEnrollment(t, root, control)
	control.credentialProviders = []controlclient.CredentialProvider{{
		Release: "orbital.session@3.7.1", Provider: "orbital-fabric", CredentialKind: "orbital.exec-token.v9",
	}}
	control.credentialConnections = []controlclient.CredentialConnection{{
		ID: "connection-a", TenantID: "tenant-1", Provider: "orbital-fabric", AccountRef: "station-9",
		ProviderRelease: "orbital.session@3.7.1", Name: "Station", State: "pending",
	}}
	control.preparedConnection = controlclient.PreparedCredentialConnection{
		Connection: control.credentialConnections[0],
		Onboarding: json.RawMessage(`{"kind":"orbital_station","instruction":"configure the edge"}`),
	}
	newApp := func(in io.Reader, out io.Writer) *App {
		return &App{In: in, Out: out, Err: io.Discard, StateRoot: root, FileTokens: true, NewControl: func(_, _, _ string) Control { return control }}
	}

	var output bytes.Buffer
	if err := newApp(strings.NewReader(""), &output).Run(context.Background(), []string{"credential", "providers"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "orbital.exec-token.v9") {
		t.Fatalf("provider discovery output = %s", output.String())
	}

	output.Reset()
	input := `{"audience":"edge"}`
	if err := newApp(strings.NewReader(input), &output).Run(context.Background(), []string{
		"credential", "connection", "create", "--provider", "orbital-fabric",
		"--release", "orbital.session@3.7.1", "--account", "station-9", "--name", "Station", "--input-file", "-",
	}); err != nil {
		t.Fatal(err)
	}
	if control.connectionRequest.Provider != "orbital-fabric" || control.connectionRequest.AccountRef != "station-9" || string(control.connectionRequest.Input) != input {
		t.Fatalf("provider-neutral connection request changed: %#v", control.connectionRequest)
	}
	if !strings.Contains(output.String(), "configure the edge") {
		t.Fatalf("onboarding was not returned: %s", output.String())
	}

	output.Reset()
	if err := newApp(strings.NewReader(""), &output).Run(context.Background(), []string{"credential", "connection", "list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "connection-a") {
		t.Fatalf("connection list output = %s", output.String())
	}

	output.Reset()
	if err := newApp(strings.NewReader(""), &output).Run(context.Background(), []string{"credential", "connection", "verify", "--id", "connection-a"}); err != nil {
		t.Fatal(err)
	}
	if control.verifiedConnectionID != "connection-a" || !strings.Contains(output.String(), "verified") {
		t.Fatalf("connection verification = %q output=%s", control.verifiedConnectionID, output.String())
	}

	output.Reset()
	if err := newApp(strings.NewReader(""), &output).Run(context.Background(), []string{"credential", "connection", "revoke", "--id", "connection-a"}); err != nil {
		t.Fatal(err)
	}
	if control.revokedConnectionID != "connection-a" || !strings.Contains(output.String(), "New leases are blocked") {
		t.Fatalf("connection revoke = %q output=%s", control.revokedConnectionID, output.String())
	}
}

func TestActionCommandsRemainProviderNeutralAndBindTheActiveSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := t.TempDir()
	control := enrolledStub()
	seedEnrollment(t, root, control)
	active := localstate.ActiveSession{
		Profile: domain.SessionProfile{
			ID: "profile-edge", TenantID: "tenant-1", Name: "Orbital production", Agent: domain.AgentCodex,
			Workspace: "/workspace", Scope: domain.Scope{
				Provider: "orbital-fabric", AccountRef: "station-9", Environments: []string{"production"},
				ResourcePrefixes: []string{"orbital://station-9/"},
			},
			Enforcement: domain.EnforcementTyped, CredentialMode: domain.CredentialAction,
			ProviderBinding: &domain.ProviderBinding{ConnectionID: "connection-edge", ProviderRelease: "fixture.session@1"},
			AdapterRelease:  "codex@1", PolicyRelease: "policy@1", CreatedAt: now,
		},
		Session: domain.AgentSession{
			ID: "session-edge", TenantID: "tenant-1", ProfileID: "profile-edge", ActorID: "actor-1",
			DeviceID: "device-1", State: domain.SessionRunning, StartedAt: now,
		},
	}
	digest, err := domain.Digest(active.Profile)
	if err != nil {
		t.Fatal(err)
	}
	active.Session.ProfileDigest = digest
	seedActionPolicy(t, root, control, active, now, nil)
	activePath, err := (localstate.Store{Root: root, FileTokens: true}).SaveActive(active)
	if err != nil {
		t.Fatal(err)
	}
	control.typedActions = []controlclient.TypedAction{{
		ID: "typed-action-1", TenantID: "tenant-1", SessionID: active.Session.ID,
		ProviderRelease: "fixture.session@1",
		Provider:        "orbital-fabric", AccountRef: "station-9", Environment: "production",
		CapabilityRef: "orbital.fabric.vector-shift@3.4.1", Operation: "ShiftVector",
		Resource: "orbital://station-9/vector/red", Parameters: json.RawMessage(`{"bearing":17}`), State: "pending_approval", PolicyRelease: active.Profile.PolicyRelease,
	}}
	newApp := func(in io.Reader, out io.Writer) *App {
		return &App{
			In: in, Out: out, Err: io.Discard, StateRoot: root, FileTokens: true,
			Getenv: func(key string) string {
				if key == "MISCONFIG_ACTIVE_SESSION" {
					return activePath
				}
				return ""
			},
			NewControl: func(_, _, _ string) Control { return control },
		}
	}

	var output bytes.Buffer
	if err := newApp(strings.NewReader(`{"bearing":17}`), &output).Run(context.Background(), []string{
		"action", "propose", "--capability", "orbital.fabric.vector-shift@3.4.1",
		"--operation", "ShiftVector", "--resource", "orbital://station-9/vector/red", "--parameters-file", "-",
	}); err != nil {
		t.Fatal(err)
	}
	request := control.typedActionRequest
	if request.SessionID != active.Session.ID || request.CapabilityRef != "orbital.fabric.vector-shift@3.4.1" ||
		request.Operation != "ShiftVector" || request.Resource != "orbital://station-9/vector/red" ||
		request.Environment != "production" || string(request.Parameters) != `{"bearing":17}` {
		t.Fatalf("typed action lost its provider-neutral identity: %#v", request)
	}
	if !strings.Contains(output.String(), "typed-action-1") || !strings.Contains(output.String(), "pending_approval") {
		t.Fatalf("proposed action output = %s", output.String())
	}

	output.Reset()
	if err := newApp(strings.NewReader(""), &output).Run(context.Background(), []string{"action", "list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "orbital.fabric.vector-shift@3.4.1") {
		t.Fatalf("action list output = %s", output.String())
	}

	output.Reset()
	if err := newApp(strings.NewReader(""), &output).Run(context.Background(), []string{"action", "execute", "typed-action-1"}); err != nil {
		t.Fatal(err)
	}
	if control.executedTypedActionID != "typed-action-1" || !strings.Contains(output.String(), "typed-action-1") {
		t.Fatalf("approved action was not selected exactly: id=%q output=%s", control.executedTypedActionID, output.String())
	}
}

func TestActionParametersRejectAnythingExceptABoundedJSONObject(t *testing.T) {
	app := &App{In: strings.NewReader(`["not","an","object"]`)}
	app.defaults()
	if _, err := app.readActionParameters("-"); err == nil || !strings.Contains(err.Error(), "JSON object") {
		t.Fatalf("array parameters were accepted: %v", err)
	}
	app.In = strings.NewReader(strings.Repeat("x", maximumActionParametersSize+1))
	if _, err := app.readActionParameters("-"); err == nil || !strings.Contains(err.Error(), "64 KiB") {
		t.Fatalf("oversized parameters were accepted: %v", err)
	}
}

func TestCredentialLeaseValidatesPublishedProviderContract(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := t.TempDir()
	control := enrolledStub()
	control.credentialProviders = []controlclient.CredentialProvider{{
		Release: "orbital.session@3.7.1", Provider: "orbital-fabric", CredentialKind: "orbital.exec-token.v9",
		MaximumTTLSeconds: 300, RevocationSemantics: "renewal-stops-token-expires",
	}}
	active := localstate.ActiveSession{
		Profile: domain.SessionProfile{
			ID: "profile-a", TenantID: "tenant-1", Name: "Orbital production", Agent: domain.AgentCodex,
			Workspace: "/workspace", Scope: domain.Scope{Provider: "orbital-fabric", AccountRef: "station-9", Environments: []string{"production"}},
			Enforcement: domain.EnforcementBrokered, CredentialMode: domain.CredentialBrokered,
			CredentialBinding: &domain.CredentialBinding{ConnectionID: "connection-a", ProviderRelease: "orbital.session@3.7.1"},
			AdapterRelease:    "codex@1", PolicyRelease: "policy@1", CreatedAt: now,
		},
		Session: domain.AgentSession{
			ID: "session-a", TenantID: "tenant-1", ProfileID: "profile-a", ProfileDigest: "sha256:profile",
			ActorID: "actor-1", DeviceID: "device-1", State: domain.SessionRunning, StartedAt: now,
		},
	}
	profileDigest, err := domain.Digest(active.Profile)
	if err != nil {
		t.Fatal(err)
	}
	active.Session.ProfileDigest = profileDigest
	activePath, err := (localstate.Store{Root: root, FileTokens: true}).SaveActive(active)
	if err != nil {
		t.Fatal(err)
	}
	authorizationDigest := seedBrokeredAuthorization(t, root, control, active, now)
	valid := controlclient.CredentialMaterial{
		Kind: "orbital.exec-token.v9", Payload: json.RawMessage(`{"token":"opaque-provider-material"}`),
		ExpiresAt: now.Add(4 * time.Minute), TargetIdentity: "orbital://station-9",
		RevocationSemantics: "renewal-stops-token-expires", AuthorizationDigest: authorizationDigest,
	}
	control.credentialMaterial = valid
	var output bytes.Buffer
	app := &App{Out: &output, Err: io.Discard, StateRoot: root, FileTokens: true, Now: func() time.Time { return now }, NewControl: func(_, _, _ string) Control { return control }}
	if err := app.Run(context.Background(), []string{"credential", "lease", "--active", activePath, "--kind", valid.Kind}); err != nil {
		t.Fatal(err)
	}
	if output.String() != string(valid.Payload)+"\n" {
		t.Fatalf("credential_process output was changed: %q", output.String())
	}
	if control.credentialSessionID != "session-a" || !strings.HasPrefix(control.credentialRequestID, "lease_") {
		t.Fatalf("lease identity was not session-bound: session=%q request=%q", control.credentialSessionID, control.credentialRequestID)
	}

	invalid := []struct {
		name   string
		mutate func(*controlclient.CredentialMaterial)
	}{
		{name: "wrong kind", mutate: func(material *controlclient.CredentialMaterial) { material.Kind = "other" }},
		{name: "expired", mutate: func(material *controlclient.CredentialMaterial) { material.ExpiresAt = now.Add(-time.Second) }},
		{name: "ttl widened", mutate: func(material *controlclient.CredentialMaterial) { material.ExpiresAt = now.Add(10 * time.Minute) }},
		{name: "revocation drift", mutate: func(material *controlclient.CredentialMaterial) { material.RevocationSemantics = "never" }},
		{name: "missing target", mutate: func(material *controlclient.CredentialMaterial) { material.TargetIdentity = "" }},
		{name: "authorization substitution", mutate: func(material *controlclient.CredentialMaterial) {
			material.AuthorizationDigest = "sha256:" + strings.Repeat("f", 64)
		}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			material := valid
			test.mutate(&material)
			control.credentialMaterial = material
			var rejected bytes.Buffer
			app := &App{Out: &rejected, Err: io.Discard, StateRoot: root, FileTokens: true, Now: func() time.Time { return now }, NewControl: func(_, _, _ string) Control { return control }}
			if err := app.Run(context.Background(), []string{"credential", "lease", "--active", activePath, "--kind", valid.Kind}); err == nil {
				t.Fatal("invalid provider material was accepted")
			}
			if rejected.Len() != 0 {
				t.Fatalf("invalid provider material reached credential_process stdout: %q", rejected.String())
			}
		})
	}
}

func TestCredentialLeaseRendersAdmittedExternalMaterialAndRejectsIdentityDrift(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := t.TempDir()
	control := enrolledStub()
	artifact := []byte("admitted-renderer")
	artifactDigest := sha256.Sum256(artifact)
	provider := controlclient.CredentialProvider{
		Release: "unfamiliar-edge.session@9.1.4", Provider: "unfamiliar-edge", CredentialKind: "edge.ephemeral.v4",
		MaximumTTLSeconds: 180, RevocationSemantics: "renewal-stops-token-expires",
		ManifestDigest: "sha256:" + strings.Repeat("b", 64), PublisherID: "external-fixture",
		RendererProtocol: provideradapter.RendererProtocol, RendererExecutable: "edge-renderer",
		RendererArtifacts:    []controlclient.RendererArtifact{{OS: runtime.GOOS, Arch: runtime.GOARCH, Digest: "sha256:" + fmt.Sprintf("%x", artifactDigest)}},
		SensitiveEnvironment: []string{"EDGE_TOKEN"}, AdmissionRequired: true,
	}
	rendererDigest := provider.RendererArtifacts[0].Digest
	control.credentialProviders = []controlclient.CredentialProvider{provider}
	active := localstate.ActiveSession{
		Profile: domain.SessionProfile{
			ID: "profile-edge", TenantID: "tenant-1", Name: "Edge production", Agent: domain.AgentCodex,
			Workspace: "/workspace", Scope: domain.Scope{Provider: provider.Provider, AccountRef: "fabric-42", Environments: []string{"production"}},
			Enforcement: domain.EnforcementBrokered, CredentialMode: domain.CredentialBrokered,
			CredentialBinding: &domain.CredentialBinding{ConnectionID: "connection-edge", ProviderRelease: provider.Release},
			AdapterRelease:    "codex@1", PolicyRelease: "policy@1", CreatedAt: now,
		},
		Session: domain.AgentSession{ID: "session-edge", TenantID: "tenant-1", ProfileID: "profile-edge", ProfileDigest: "sha256:profile", ActorID: "actor-1", DeviceID: "device-1", State: domain.SessionRunning, StartedAt: now},
	}
	profileDigest, err := domain.Digest(active.Profile)
	if err != nil {
		t.Fatal(err)
	}
	active.Session.ProfileDigest = profileDigest
	store := localstate.Store{Root: root, FileTokens: true}
	activePath, err := store.SaveActive(active)
	if err != nil {
		t.Fatal(err)
	}
	authorizationDigest := seedBrokeredAuthorization(t, root, control, active, now)
	rendererPath, err := store.SaveRuntimeExecutable(active.Session.ID, "renderer-edge", artifact)
	if err != nil {
		t.Fatal(err)
	}
	control.credentialMaterial = controlclient.CredentialMaterial{
		Kind: provider.CredentialKind, Payload: json.RawMessage(`{"opaque":"never-print-this"}`), ExpiresAt: now.Add(2 * time.Minute),
		TargetIdentity: "unfamiliar-edge://fabric-42", RevocationSemantics: provider.RevocationSemantics, AuthorizationDigest: authorizationDigest,
	}
	var rendered provideradapter.RenderRequest
	var output bytes.Buffer
	app := &App{
		Out: &output, Err: io.Discard, StateRoot: root, FileTokens: true, Now: func() time.Time { return now },
		NewControl: func(_, _, _ string) Control { return control },
		RunRenderer: func(_ context.Context, path, operation string, input []byte) ([]byte, error) {
			if path != rendererPath || operation != "render" {
				t.Fatalf("unexpected renderer invocation: %q %q", path, operation)
			}
			if err := json.Unmarshal(input, &rendered); err != nil {
				t.Fatal(err)
			}
			return json.Marshal(provideradapter.RenderedMaterial{Stdout: `{"Version":4,"Access":"native-edge-token"}`})
		},
	}
	args := []string{"credential", "lease", "--active", activePath, "--kind", provider.CredentialKind, "--release", provider.Release, "--manifest-digest", provider.ManifestDigest, "--renderer", rendererPath, "--renderer-digest", rendererDigest}
	if err := app.Run(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	wantOutput := `{"Version":4,"Access":"native-edge-token"}`
	if output.String() != wantOutput {
		t.Fatalf("external renderer output changed: got %q want %q", output.String(), wantOutput)
	}
	if strings.Contains(output.String(), "never-print-this") {
		t.Fatalf("opaque material escaped or native material missing: %q", output.String())
	}
	if rendered.Release != provider.Release || rendered.ManifestDigest != provider.ManifestDigest || rendered.SessionID != active.Session.ID || !strings.Contains(string(rendered.Material), "never-print-this") {
		t.Fatalf("render request was not bound to the admitted identity: %#v", rendered)
	}

	control.credentialSessionID = ""
	badArgs := append([]string(nil), args...)
	badArgs[9] = "sha256:" + strings.Repeat("c", 64)
	var rejected bytes.Buffer
	app.Out = &rejected
	if err := app.Run(context.Background(), badArgs); err == nil {
		t.Fatal("manifest identity drift was accepted")
	}
	if control.credentialSessionID != "" || rejected.Len() != 0 {
		t.Fatalf("credential was issued before identity rejection: session=%q output=%q", control.credentialSessionID, rejected.String())
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

func seedBrokeredAuthorization(t *testing.T, root string, control *stubControl, active localstate.ActiveSession, now time.Time) string {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seedEnrollmentWithKey(t, root, control, base64.RawURLEncoding.EncodeToString(publicKey))
	signed, err := policy.Sign(policy.Bundle{
		Release: active.Profile.PolicyRelease, TenantID: active.Profile.TenantID, ProfileID: active.Profile.ID,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Rules: []policy.Rule{{
			ID: "allow-brokered-read", Effect: policy.EffectAllow, Providers: []string{active.Profile.Scope.Provider},
			Operations: []string{"tool.Inspect"}, ResourcePrefixes: active.Profile.Scope.ResourcePrefixes, Reason: "bounded provider read",
		}},
	}, "key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	store := localstate.Store{Root: root, FileTokens: true}
	if err := (policy.Cache{Path: store.PolicyPath(active.Session.ID), PublicKey: publicKey, Now: func() time.Time { return now }}).Store(signed); err != nil {
		t.Fatal(err)
	}
	rules := []provideradapter.AuthorizationRule{{
		ID: "allow-brokered-read", Effect: string(policy.EffectAllow), Providers: []string{active.Profile.Scope.Provider},
		Operations: []string{"tool.Inspect"}, ResourcePrefixes: active.Profile.Scope.ResourcePrefixes,
	}}
	digest, err := provideradapter.AuthorizationDigest(provideradapter.Authorization{
		ProfileDigest: active.Session.ProfileDigest, PolicyRelease: active.Profile.PolicyRelease,
		Provider: active.Profile.Scope.Provider, AccountRef: active.Profile.Scope.AccountRef,
		Environments: active.Profile.Scope.Environments, ResourcePrefixes: active.Profile.Scope.ResourcePrefixes, Rules: rules,
	})
	if err != nil {
		t.Fatal(err)
	}
	return digest
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
