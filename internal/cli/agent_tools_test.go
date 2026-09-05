package cli

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/tasktransport"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func taskServerFixture(t *testing.T) (*actionFixture, *mcp.ClientSession) {
	t.Helper()
	f := newActionFixture(t)
	f.control.typedActions[0].State = "approved"
	f.app.defaults()
	f.control.credentialProviders = []controlclient.CredentialProvider{{Release: "fixture.session@1", Provider: "fixture", Actions: []controlclient.ActionDescriptor{{Ref: "fixture.shift@1", Operation: "ShiftVector", Title: "Adjust the selected object", CapabilityDigest: "sha256:test", ParametersSchema: json.RawMessage(`{"type":"object","properties":{"bearing":{"type":"integer"}},"required":["bearing"],"additionalProperties":false}`)}}}}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := tasktransport.ExecutableDigest(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.SaveTaskBridge(tasktransport.Binding{SessionID: f.active.Session.ID, ProfileDigest: f.active.Session.ProfileDigest, ServerName: "misconfig_12345678901234567890", Executable: executable, ExecutableDigest: digest}); err != nil {
		t.Fatal(err)
	}
	server, err := f.app.newTaskServer(context.Background(), f.active.Session.ID)
	if err != nil {
		t.Fatal(err)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	connection, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	client, err := mcp.NewClient(&mcp.Implementation{Name: "acceptance-client", Version: "1"}, nil).Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return f, client
}

func TestTaskExecutionRequiresCurrentApproval(t *testing.T) {
	for _, state := range []string{"pending_approval", "verified", "executing", "failed", "revoked", ""} {
		t.Run(state, func(t *testing.T) {
			f, client := taskServerFixture(t)
			f.control.typedActions[0].State = state
			result, err := client.CallTool(context.Background(), &mcp.CallToolParams{Name: "execute_action", Arguments: map[string]any{"action_id": "action-a"}})
			if err == nil && !result.IsError {
				t.Fatal("execution accepted without live approval")
			}
			if f.control.executedTypedActionID != "" {
				t.Fatal("unapproved execution reached the broker")
			}
		})
	}
}

func TestTaskToolsExposeOnlyBoundWorkflow(t *testing.T) {
	f, client := taskServerFixture(t)
	tools, err := client.ListTools(context.Background(), nil)
	if err != nil || len(tools.Tools) != 4 {
		t.Fatalf("tools: %#v %v", tools, err)
	}
	for _, tool := range tools.Tools {
		if strings.Contains(tool.Name, "approve") || strings.Contains(tool.Name, "shell") {
			t.Fatalf("unexpected authority: %s", tool.Name)
		}
		if tool.Name == "execute_action" && (tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint != nil && !*tool.Annotations.DestructiveHint) {
			t.Fatal("execution falsely annotated as read-only or non-destructive")
		}
	}
	result, err := client.CallTool(context.Background(), &mcp.CallToolParams{Name: "task_context", Arguments: map[string]any{}})
	if err != nil || result.IsError {
		t.Fatalf("context: %#v %v", result, err)
	}
	encoded, _ := json.Marshal(result)
	if !strings.Contains(string(encoded), "fixture.shift@1") || !strings.Contains(string(encoded), "fixture://system-1/selected") {
		t.Fatalf("missing task context: %s", encoded)
	}
	for _, call := range []mcp.CallToolParams{
		{Name: "propose_action", Arguments: map[string]any{"capability_ref": "fixture.shift@1", "resource": "fixture://system-1/selected", "parameters": map[string]any{"bearing": 17}}},
		{Name: "list_actions", Arguments: map[string]any{}},
		{Name: "execute_action", Arguments: map[string]any{"action_id": "action-a"}},
	} {
		result, err := client.CallTool(context.Background(), &call)
		if err != nil || result.IsError {
			t.Fatalf("%s: %#v %v", call.Name, result, err)
		}
	}
	if f.control.typedActionRequest.SessionID != f.active.Session.ID || f.control.typedActionRequest.Operation != "ShiftVector" || f.control.executedTypedActionID != "action-a" {
		t.Fatal("task tools lost the selected scope")
	}
}

func TestTaskToolsRejectAuthorityOverridesAndStop(t *testing.T) {
	f, client := taskServerFixture(t)
	for _, call := range []mcp.CallToolParams{
		{Name: "task_context", Arguments: map[string]any{"session_id": "other"}},
		{Name: "list_actions", Arguments: map[string]any{"session_id": "other"}},
		{Name: "execute_action", Arguments: map[string]any{"action_id": "other"}},
		{Name: "propose_action", Arguments: map[string]any{"capability_ref": "fixture.shift@1", "resource": "fixture://system-1/selected", "parameters": map[string]any{}, "operation": "Delete"}},
		{Name: "propose_action", Arguments: map[string]any{"capability_ref": "unselected@1", "resource": "fixture://system-1/selected", "parameters": map[string]any{}}},
		{Name: "propose_action", Arguments: map[string]any{"capability_ref": "fixture.shift@1", "resource": "fixture://system-1/other", "parameters": map[string]any{}}},
	} {
		result, err := client.CallTool(context.Background(), &call)
		if err == nil && !result.IsError {
			t.Fatalf("override accepted: %#v", call)
		}
	}
	if f.control.executedTypedActionID != "" || f.control.typedActionRequest.SessionID != "" {
		t.Fatal("denied request reached the broker")
	}
	if err := f.store.MarkStopped(f.active.Session.ID); err != nil {
		t.Fatal(err)
	}
	result, err := client.CallTool(context.Background(), &mcp.CallToolParams{Name: "task_context", Arguments: map[string]any{}})
	if err == nil && !result.IsError {
		t.Fatal("stopped session exposed tools")
	}
}

func TestTaskTransportPinsSessionEvenIfLocalActiveFileIsReplaced(t *testing.T) {
	f, client := taskServerFixture(t)
	replacement := f.active
	replacement.Session.ID = "other-session"
	// Write to the original active path rather than selecting a different file.
	path := f.app.Getenv("MISCONFIG_ACTIVE_SESSION")
	encoded, _ := json.Marshal(replacement)
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	f.control.remote = replacement.Session
	result, err := client.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_actions", Arguments: map[string]any{}})
	if err == nil && !result.IsError {
		t.Fatal("transport switched to another session")
	}
	if f.control.listedActionSessionID != "" {
		t.Fatal("foreign session reached action list")
	}
}

func TestTaskArgumentDuplicateSelectorsRejected(t *testing.T) {
	var output any
	if err := decodeTaskArguments(json.RawMessage(`{"action_id":"other","action_id":"action-a"}`), map[string]bool{"action_id": true}, &output); err == nil {
		t.Fatal("duplicate selector accepted")
	}
}

func TestNativeTaskConfigurationIsSessionLocalAndRequiredForCodex(t *testing.T) {
	f, _ := taskServerFixture(t)
	bridge, err := f.store.LoadTaskBridge(f.active.Session.ID)
	if err != nil {
		t.Fatal(err)
	}
	name, args, err := f.app.nativeCommand(f.store, bridge.Executable, f.active.Session.ID, f.active.Profile, []string{"exec", "test prompt", "-c", "mcp_servers.unrelated={command=\"unrelated\"}"})
	if err != nil || name != "codex" {
		t.Fatalf("launch config: %s %v", name, err)
	}
	last := args[len(args)-1]
	if !strings.Contains(last, "required=true") || !strings.Contains(last, bridge.ServerName) || !strings.Contains(last, "agent-tools") || !strings.Contains(last, f.active.Session.ID) || !strings.Contains(last, `tools={execute_action={approval_mode="approve"}}`) {
		t.Fatalf("missing authoritative final override: %s", last)
	}
	if !strings.Contains(strings.Join(args, " "), "hooks.PreToolUse") {
		t.Fatal("native hooks were removed")
	}
	if err := f.store.RemoveRuntime(f.active.Session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.LoadTaskBridge(f.active.Session.ID); err == nil {
		t.Fatal("bridge survived session cleanup")
	}
}
