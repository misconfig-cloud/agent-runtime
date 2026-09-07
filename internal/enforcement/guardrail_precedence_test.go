package enforcement

import (
	"context"
	"testing"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/hook"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
)

func TestGuardrailCannotOverrideSignedPolicy(t *testing.T) {
	for _, effect := range []policy.Effect{policy.EffectDeny, policy.EffectStop, policy.EffectApproval, policy.EffectAllow} {
		t.Run(string(effect), func(t *testing.T) {
			engine, control, activePath, _ := fixtureForProvider(t, domain.AgentCodex, effect, "local-agent")
			result, err := engine.Pre(context.Background(), activePath, hook.Input{
				ToolName: "Bash", ToolUseID: "guarded-action", ToolInput: map[string]any{"command": "touch empty.txt"},
			})
			if err != nil || result.Decision.Effect != effect {
				t.Fatalf("classifier replaced signed %s: %+v %v", effect, result, err)
			}
			if (effect == policy.EffectDeny || effect == policy.EffectStop) && control.guardrailCalls != 0 {
				t.Fatal("already denied action unnecessarily reached classifier")
			}
		})
	}
}

func TestStandardGuardDoesNotInferCloudAuthorityFromCommandSpelling(t *testing.T) {
	engine, control, activePath, _ := fixtureForProvider(t, domain.AgentCodex, policy.EffectAllow, "local-agent")
	result, err := engine.Pre(context.Background(), activePath, hook.Input{
		ToolName: "Bash", ToolUseID: "guarded-action", ToolInput: map[string]any{"command": "aws sts get-caller-identity"},
	})
	if err != nil || result.Action.Destination.Provider != "local-agent" || result.Decision.Effect != policy.EffectAllow || control.guardrailCalls != 1 {
		t.Fatalf("native call escaped signed local scope: %+v %v", result, err)
	}
}

func TestGuardrailCannotOverrideStoppedSession(t *testing.T) {
	engine, control, activePath, _ := fixtureForProvider(t, domain.AgentCodex, policy.EffectAllow, "local-agent")
	active, err := localstate.LoadActive(activePath)
	if err != nil {
		t.Fatal(err)
	}
	active.Session.State = domain.SessionStopped
	if _, err := engine.Store.SaveActive(active); err != nil {
		t.Fatal(err)
	}
	result, err := engine.Pre(context.Background(), activePath, hook.Input{ToolName: "Bash", ToolUseID: "stopped", ToolInput: map[string]any{"command": "touch empty.txt"}})
	if err == nil && result.Decision.Effect == policy.EffectAllow {
		t.Fatal("stopped session gained continuation")
	}
	if control.guardrailCalls != 0 {
		t.Fatal("stopped session reached classifier")
	}
}
