package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/domain"
)

// Opt-in: uses the installed authenticated Codex and model quota. The control
// API and provider are fixtures, so this proves native tool integration, not
// deployed-control-plane or real-provider acceptance.
func TestLiveCodexTaskProposal(t *testing.T) {
	runLiveCodexTask(t, false)
}

func TestLiveCodexApprovedTaskTransport(t *testing.T) {
	runLiveCodexTask(t, true)
}

func runLiveCodexTask(t *testing.T, execute bool) {
	t.Helper()
	if os.Getenv("MISCONFIG_NATIVE_TASK_ACCEPTANCE") != "1" {
		t.Skip("set MISCONFIG_NATIVE_TASK_ACCEPTANCE=1 to use installed Codex")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("this test isolates macOS Keychain through a fixture executable")
	}
	codex, err := exec.LookPath("codex")
	if err != nil {
		t.Fatal(err)
	}
	f := newActionFixture(t)
	f.control.typedActions[0].State = "pending_approval"
	if execute {
		f.control.typedActions[0].State = "approved"
	}
	workspace := t.TempDir()
	f.active.Profile.Workspace = workspace
	f.active.Session.ProfileDigest, _ = domain.Digest(f.active.Profile)
	seedActionPolicy(t, f.store.Root, f.control, f.active, f.now, nil)
	provider := controlclient.CredentialProvider{Release: "fixture.session@1", Provider: "fixture", Actions: []controlclient.ActionDescriptor{{Ref: "fixture.shift@1", Operation: "ShiftVector", Title: "Adjust test bearing", CapabilityDigest: "sha256:fixture", ParametersSchema: json.RawMessage(`{"type":"object","properties":{"bearing":{"type":"integer"}},"required":["bearing"],"additionalProperties":false}`)}}}
	var mu sync.Mutex
	var proposals []controlclient.CreateTypedActionRequest
	var receipts []map[string]any
	stopped := false
	executions := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer device-secret" {
			w.WriteHeader(401)
			return
		}
		var result any
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/session-profiles":
			result = map[string]any{"profiles": []domain.SessionProfile{f.active.Profile}}
		case "GET /v1/session-profiles/profile-a":
			result = map[string]any{"profile": f.active.Profile, "profile_digest": f.active.Session.ProfileDigest}
		case "POST /v1/sessions":
			result = f.active.Session
		case "GET /v1/sessions/session-a":
			result = map[string]any{"session": f.active.Session}
		case "GET /v1/sessions/session-a/policy":
			result = f.control.signed
		case "GET /v1/credential-providers":
			result = map[string]any{"providers": []controlclient.CredentialProvider{provider}}
		case "POST /v1/actions":
			var proposal controlclient.CreateTypedActionRequest
			if json.NewDecoder(r.Body).Decode(&proposal) != nil {
				w.WriteHeader(400)
				return
			}
			proposals = append(proposals, proposal)
			result = f.control.typedActions[0]
		case "GET /v1/actions":
			result = map[string]any{"actions": f.control.typedActions}
		case "POST /v1/actions/action-a/execute":
			if !execute || f.control.typedActions[0].State != "approved" || executions != 0 {
				w.WriteHeader(http.StatusConflict)
				return
			}
			executions++
			// Simulated response only. This test never executes a real provider.
			f.control.typedActions[0].State = "verified"
			result = f.control.typedActions[0]
		case "POST /v1/sessions/session-a/stop":
			stopped = true
			result = map[string]any{"stopped": true}
		case "POST /v1/receipts":
			var receipt map[string]any
			if json.NewDecoder(r.Body).Decode(&receipt) != nil {
				w.WriteHeader(400)
				return
			}
			receipts = append(receipts, receipt)
			result = map[string]any{"accepted": true}
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()
	config, err := f.store.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	config.ControlURL = server.URL
	if err := f.store.SaveConfig(config); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	binary := filepath.Join(bin, "misconfig")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/misconfig")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %s %v", output, err)
	}
	// The source binary is unchanged. Only this disposable process tree uses
	// a credential-reader fixture; no real Keychain entry is read or modified.
	keychain := []byte("#!/bin/sh\nif [ \"$1\" = find-generic-password ]; then printf '%s' device-secret; else exit 1; fi\n")
	if err := os.WriteFile(filepath.Join(bin, "security"), keychain, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	prompt := "This is a disposable Misconfig integration acceptance test. Call the Misconfig task_context tool. Propose exactly one action for the available work, resource fixture://system-1/selected, bearing 17. Do not execute it or approve it. Use only Misconfig MCP tools, not shell, web, files, or other integrations. Report the proposed action ID and that console approval is required, then finish."
	if execute {
		prompt = "This is a disposable Misconfig tool-transport test, not real infrastructure. Call task_context, then list_actions. The fixture contains one already-approved action. Execute exactly that action through execute_action, then inspect it with list_actions. Do not propose or approve anything. Use only Misconfig MCP tools, not shell, web, files, or other integrations. Report the simulated outcome and finish."
	}
	command := exec.CommandContext(ctx, binary, "run", "--profile", "profile-a", "--", "exec", "--ignore-user-config", "--skip-git-repo-check", "--ephemeral", "--sandbox", "read-only", "--json", "-c", "features.plugins=false", prompt)
	command.Dir = workspace
	// Preserve only the local agent login/config location and basic process
	// settings. Provider environment variables are not inherited by this test.
	for _, key := range []string{"HOME", "CODEX_HOME", "TMPDIR", "LANG", "TERM"} {
		if value, ok := os.LookupEnv(key); ok {
			command.Env = append(command.Env, key+"="+value)
		}
	}
	command.Env = append(command.Env, "PATH="+bin+":"+filepath.Dir(codex)+":/usr/bin:/bin", "MISCONFIG_HOME="+f.store.Root)
	output, runErr := command.CombinedOutput()
	if runErr != nil {
		t.Fatalf("native agent: %v\n%s", runErr, output)
	}
	mu.Lock()
	defer mu.Unlock()
	if execute && (len(proposals) != 0 || executions != 1) {
		t.Fatalf("agent did not execute the approved fixture action: proposals=%d executions=%d\n%s", len(proposals), executions, output)
	}
	if !execute && (len(proposals) != 1 || proposals[0].SessionID != "session-a" || proposals[0].CapabilityRef != "fixture.shift@1" || proposals[0].Operation != "ShiftVector" || proposals[0].Resource != "fixture://system-1/selected" || string(proposals[0].Parameters) != `{"bearing":17}`) {
		t.Fatalf("agent did not submit the exact task: %#v\n%s", proposals, output)
	}
	transportSeen := false
	for _, receipt := range receipts {
		if operation, ok := receipt["operation"].(string); ok && strings.HasPrefix(operation, "misconfig.task_transport.") {
			transportSeen = true
		}
	}
	if !transportSeen || !stopped {
		t.Fatalf("missing native transport receipt or stop: receipts=%d stopped=%v\n%s", len(receipts), stopped, output)
	}
	t.Logf("Real Codex task tools: proposals=%d simulated executions=%d native transport receipts=%d; session stopped. No real provider execution.", len(proposals), executions, len(receipts))
}
