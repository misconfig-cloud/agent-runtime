package hook

import "testing"

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
			if input.ToolUseID == "" || input.ToolName == "" || input.CWD != "/work" {
				t.Fatalf("native tool fields were not preserved: %#v", input)
			}
		})
	}
}
