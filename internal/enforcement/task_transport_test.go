package enforcement

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/hook"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
	"github.com/misconfig-cloud/agent-runtime/internal/tasktransport"
)

func TestTaskTransportDoesNotGrantGenericShellOrForeignMCP(t *testing.T) {
	engine, _, path, now := fixture(t, policy.EffectTyped)
	active, err := localstate.LoadActive(path)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := tasktransport.ExecutableDigest(executable)
	if err != nil {
		t.Fatal(err)
	}
	binding := tasktransport.Binding{SessionID: active.Session.ID, ProfileDigest: active.Session.ProfileDigest, ServerName: "misconfig_12345678901234567890", Executable: executable, ExecutableDigest: digest}
	if err := engine.Store.SaveTaskBridge(binding); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, tool string
		allowed    bool
	}{
		{"context", "mcp__" + binding.ServerName + "__task_context", true},
		{"execution transport", "mcp__" + binding.ServerName + "__execute_action", true},
		{"foreign server", "mcp__misconfig_other__execute_action", false},
		{"invented tool", "mcp__" + binding.ServerName + "__approve_action", false},
		{"native shell", "Bash", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := engine.Pre(context.Background(), path, hook.Input{ToolName: test.tool, ToolUseID: test.name, ToolInput: map[string]any{"command": "kubectl delete namespace production"}})
			if err != nil || (result.Decision.Effect == policy.EffectAllow) != test.allowed {
				t.Fatalf("decision: %#v %v", result, err)
			}
			if test.allowed && result.Action.Resource != "misconfig://sessions/"+active.Session.ID {
				t.Fatal("transport claimed a provider resource")
			}
		})
	}
	input := hook.Input{ToolName: "mcp__" + binding.ServerName + "__task_context", ToolUseID: "context", ToolInput: map[string]any{"command": "kubectl delete namespace production"}}
	engine.Now = func() time.Time { return now.Add(2 * time.Hour) }
	result, err := engine.Pre(context.Background(), path, input)
	if err != nil || result.Decision.Effect != policy.EffectDeny {
		t.Fatalf("expired retry retained transport allow: %#v %v", result, err)
	}
	engine.Now = func() time.Time { return now }
	active.Session.State = domain.SessionStopped
	if _, err := engine.Store.SaveActive(active); err != nil {
		t.Fatal(err)
	}
	result, err = engine.Pre(context.Background(), path, input)
	if err != nil || result.Decision.Effect != policy.EffectDeny {
		t.Fatalf("stopped retry retained transport allow: %#v %v", result, err)
	}
}

func TestPreviouslyAllowedNativeRetryIsDeniedAfterPolicyExpiry(t *testing.T) {
	engine, _, path, now := fixture(t, policy.EffectAllow)
	input := hook.Input{ToolName: "Bash", ToolUseID: "same-tool-use", ToolInput: map[string]any{"command": "aws ec2 describe-instances"}}
	first, err := engine.Pre(context.Background(), path, input)
	if err != nil || first.Decision.Effect != policy.EffectAllow {
		t.Fatal(err)
	}
	engine.Now = func() time.Time { return now.Add(2 * time.Hour) }
	retry, err := engine.Pre(context.Background(), path, input)
	if err != nil || retry.Decision.Effect != policy.EffectDeny || retry.Action.ID != first.Action.ID {
		t.Fatalf("retry: %#v %v", retry, err)
	}
}
