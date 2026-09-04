package hook

import (
	"testing"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
)

func TestDecodeNativeHookFixtures(t *testing.T) {
	tests := []struct {
		name       string
		encoded    string
		sessionID  string
		turnID     string
		transcript string
		model      string
		permission string
		agentID    string
		agentType  string
		event      string
		errorText  string
		interrupt  bool
		durationMS int64
	}{
		{
			name: "codex",
			encoded: `{
                "session_id":"codex-session","turn_id":"turn-42","transcript_path":"/tmp/codex.jsonl",
                "cwd":"/work","hook_event_name":"PreToolUse","model":"gpt-5.6-codex",
                "permission_mode":"on-request","agent_id":"subagent-7","agent_type":"worker",
                "tool_name":"shell","tool_input":{"command":"aws sts get-caller-identity"},"tool_use_id":"call-9"
            }`,
			sessionID: "codex-session", turnID: "turn-42", transcript: "/tmp/codex.jsonl",
			model: "gpt-5.6-codex", permission: "on-request", agentID: "subagent-7", agentType: "worker",
			event: "PreToolUse",
		},
		{
			name: "claude",
			encoded: `{
                "session_id":"claude-session","turn_id":"turn-8","transcript_path":"/tmp/claude.jsonl",
                "cwd":"/work","hook_event_name":"PreToolUse","model":"claude-opus-4-1",
                "permission_mode":"default","agent_id":"agent-3","agent_type":"Explore",
                "tool_name":"Bash","tool_input":{"command":"kubectl get pods"},"tool_use_id":"toolu_1"
            }`,
			sessionID: "claude-session", turnID: "turn-8", transcript: "/tmp/claude.jsonl",
			model: "claude-opus-4-1", permission: "default", agentID: "agent-3", agentType: "Explore",
			event: "PreToolUse",
		},
		{
			name: "claude-post-tool-use-failure",
			encoded: `{
                "session_id":"claude-session","transcript_path":"/tmp/claude.jsonl",
                "cwd":"/work","hook_event_name":"PostToolUseFailure","permission_mode":"default",
                "tool_name":"Bash","tool_input":{"command":"npm test","description":"Run test suite"},
                "tool_use_id":"toolu_01ABC123","error":"Exit code 1\nError: Cannot find module 'express'",
                "is_interrupt":false,"duration_ms":4187
            }`,
			sessionID: "claude-session", transcript: "/tmp/claude.jsonl", permission: "default",
			event: "PostToolUseFailure", errorText: "Exit code 1\nError: Cannot find module 'express'", durationMS: 4187,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, err := Decode([]byte(test.encoded))
			if err != nil {
				t.Fatal(err)
			}
			if input.SessionID != test.sessionID || input.TurnID != test.turnID || input.TranscriptPath != test.transcript ||
				input.Model != test.model || input.PermissionMode != test.permission || input.AgentID != test.agentID || input.AgentType != test.agentType {
				t.Fatalf("native correlation fields were not preserved: %#v", input)
			}
			if input.HookEventName != test.event || input.Error != test.errorText || input.IsInterrupt != test.interrupt || input.DurationMS != test.durationMS {
				t.Fatalf("native event fields were not preserved: %#v", input)
			}
			if input.ToolUseID == "" || input.ToolName == "" || input.CWD != "/work" {
				t.Fatalf("native tool fields were not preserved: %#v", input)
			}
		})
	}
}

func TestCodexSubagentOrchestrationUsesLiveNativeOperations(t *testing.T) {
	profile := domain.SessionProfile{Scope: domain.Scope{
		Provider: "aws", AccountRef: "123456789012", Environments: []string{"production"}, ResourcePrefixes: []string{"arn:aws:"},
	}}
	session := domain.AgentSession{ID: "session-1", TenantID: "tenant-1", ActorID: "actor-1", DeviceID: "device-1"}
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		tool      string
		operation string
	}{
		{tool: "collaborationspawn_agent", operation: "tool.CollaborationspawnAgent"},
		{tool: "collaborationwait_agent", operation: "tool.CollaborationwaitAgent"},
		{tool: "collaborationlist_agents", operation: "tool.CollaborationlistAgents"},
	}
	for _, test := range tests {
		t.Run(test.tool, func(t *testing.T) {
			action, err := Action(profile, session, Input{
				HookEventName: "PreToolUse", ToolName: test.tool, ToolInput: map[string]any{}, ToolUseID: "call-1", CWD: "/work",
			}, now)
			if err != nil {
				t.Fatal(err)
			}
			if action.Operation != test.operation {
				t.Fatalf("operation = %q, want %q", action.Operation, test.operation)
			}
		})
	}
}
