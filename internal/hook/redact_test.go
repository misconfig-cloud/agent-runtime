package hook

import (
	"strings"
	"testing"
)

func TestRedactedToolInputRemovesNestedAndInlineCredentials(t *testing.T) {
	input := Input{ToolInput: map[string]any{
		"command":  "deploy --api-key=cleartext eyJabcdefghijkl.abcdefghijkl.abcdefgh",
		"headers":  map[string]any{"Authorization": "Bearer cleartext"},
		"ordinary": "kubectl get pods",
	}}
	redacted := RedactedToolInput(input)
	encoded := redacted["command"].(string)
	if strings.Contains(encoded, "cleartext") || strings.Contains(encoded, "eyJabcdefghijkl") {
		t.Fatalf("credential remained in command: %q", encoded)
	}
	if redacted["headers"].(map[string]any)["Authorization"] != "[REDACTED]" {
		t.Fatal("nested authorization was not redacted")
	}
	if redacted["ordinary"] != "kubectl get pods" {
		t.Fatal("ordinary value changed")
	}
}
