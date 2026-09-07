package semantics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeToolEffects(t *testing.T) {
	root := workspace(t)
	cases := []struct {
		name  string
		input map[string]any
		want  Classification
	}{
		{"Bash", map[string]any{"command": "touch new.txt"}, Ordinary},
		{"exec_command", map[string]any{"cmd": "rm -- empty.txt"}, Ordinary},
		{"shell_command", map[string]any{"command": "cat important.txt"}, Ordinary},
		{"exec_command", map[string]any{"cmd": "touch new.txt", "workdir": "/etc"}, Unknown},
		{"exec_command", map[string]any{"cmd": "touch new.txt", "shell": "/usr/bin/python3"}, Unknown},
		{"exec_command", map[string]any{"cmd": []any{"touch", "new.txt"}}, Unknown},
		{"Read", map[string]any{"file_path": "important.txt"}, Ordinary},
		{"Write", map[string]any{"file_path": "new.txt", "content": "hello"}, Ordinary},
		{"Write", map[string]any{"file_path": "important.txt", "content": "replacement"}, Risky},
		{"Edit", map[string]any{"file_path": "important.txt", "old_string": "work", "new_string": "code"}, Risky},
		{"Edit", map[string]any{"file_path": "important.txt", "new_string": "code"}, Unknown},
		{"Write", map[string]any{"file_path": "new.txt"}, Unknown},
		{"Read", map[string]any{"file_path": ".env"}, CredentialExposure},
		{"Write", map[string]any{"file_path": ".git/config", "content": "rewrite"}, Dangerous},
		{"Write", map[string]any{"file_path": "/etc/passwd", "content": "rewrite"}, Dangerous},
		{"mcp__untrusted__Read", map[string]any{"file_path": "important.txt"}, Unknown},
		{"WebFetch", map[string]any{"url": "https://example.invalid"}, Unknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := (Engine{}).AnalyzeTool(ToolRequest{Workspace: root, Name: tc.name, Input: tc.input})
			if r.Classification != tc.want {
				t.Fatalf("got %s want %s: %+v", r.Classification, tc.want, r)
			}
		})
	}
}

func TestCredentialLiteralNeverEntersReport(t *testing.T) {
	root := workspace(t)
	credential := "ghp_" + strings.Repeat("x", 30) // synthetic format fixture
	r := (Engine{}).AnalyzeTool(ToolRequest{Workspace: root, Name: "Write", Input: map[string]any{"file_path": "new.txt", "content": credential}})
	if r.Classification != CredentialExposure {
		t.Fatalf("literal not detected: %+v", r)
	}
	encoded, err := json.Marshal(r)
	if err != nil || strings.Contains(string(encoded), credential) {
		t.Fatal("report exposed literal or could not be encoded")
	}
}

func TestAnalysisDoesNotExecuteCommands(t *testing.T) {
	root := workspace(t)
	(Engine{}).Analyze(Request{Workspace: root, Command: "printf '%s' \"$(touch sentinel.txt)\" > new.txt"})
	for _, name := range []string{"sentinel.txt", "new.txt"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("analysis executed a write to %s", name)
		}
	}
}
