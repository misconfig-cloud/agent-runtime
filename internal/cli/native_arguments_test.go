package cli

import (
	"strings"
	"testing"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
)

func TestNativeArgumentsCannotDisableLaunchControls(t *testing.T) {
	for _, args := range [][]string{
		{"exec", "--", "prompt"},
		{"exec", "--disable", "hooks", "prompt"},
		{"--disable=hooks", "exec", "prompt"},
		{"exec", "--disable", "codex_hooks", "prompt"},
		{"--disable=plugins,hooks", "exec", "prompt"},
	} {
		_, _, err := (&App{}).nativeCommand(localstate.Store{Root: t.TempDir()}, "/unused", "session-1", domain.SessionProfile{Agent: domain.AgentCodex}, args)
		if err == nil {
			t.Fatalf("accepted bypass arguments %q", args)
		}
	}
	if err := validateNativeArguments(domain.AgentClaude, []string{"--", "prompt"}); err == nil {
		t.Fatal("Claude argument terminator accepted")
	}
}

func TestNativeHookFeatureOverrideFollowsCallerConfig(t *testing.T) {
	_, args, err := (&App{}).nativeCommand(localstate.Store{Root: t.TempDir()}, "/unused", "session-1", domain.SessionProfile{Agent: domain.AgentCodex}, []string{"exec", "-c", "features.hooks=false", "--disable", "plugins", "prompt"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.LastIndex(joined, "features.hooks=true") < strings.LastIndex(joined, "features.hooks=false") {
		t.Fatalf("caller configuration overrides runtime: %q", args)
	}
}
