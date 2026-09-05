package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
	provideradapter "github.com/misconfig-cloud/provider-sdk"
)

func capabilityFixture(t *testing.T) (*actionFixture, provideradapter.CapabilitySelector) {
	t.Helper()
	f := newActionFixture(t)
	selected := provideradapter.CapabilitySelector{Ref: "fixture.shift@1", Digest: "sha256:" + strings.Repeat("a", 64)}
	seedActionPolicy(t, f.store.Root, f.control, f.active, f.now, func(b *policy.Bundle) {
		b.Rules[0].Capabilities = []provideradapter.CapabilitySelector{selected}
	})
	f.control.credentialProviders = []controlclient.CredentialProvider{{Release: "fixture.session@1", Provider: "fixture", Actions: []controlclient.ActionDescriptor{
		{Ref: selected.Ref, Operation: "ShiftVector", CapabilityDigest: selected.Digest, ParametersSchema: json.RawMessage(`{"type":"object"}`)},
		{Ref: "fixture.alternative@1", Operation: "ShiftVector", CapabilityDigest: "sha256:" + strings.Repeat("b", 64), ParametersSchema: json.RawMessage(`{"type":"object"}`)},
	}}}
	f.control.typedActions[0].CapabilityDigest = selected.Digest
	return f, selected
}

func TestCapabilityDiscoveryUsesExactIdentityNotOperation(t *testing.T) {
	f, selected := capabilityFixture(t)
	s := actionSession{active: f.active, policy: f.control.signed.Bundle}
	list, err := taskCapabilities(context.Background(), f.control, s)
	if err != nil || len(list) != 1 || list[0].Ref != selected.Ref || list[0].CapabilityDigest != selected.Digest {
		t.Fatalf("selection broadened: %#v %v", list, err)
	}
	other := f.control.credentialProviders[0].Actions[1]
	s.policy.Rules[0].Capabilities = append(s.policy.Rules[0].Capabilities, provideradapter.CapabilitySelector{Ref: other.Ref, Digest: other.CapabilityDigest})
	list, err = taskCapabilities(context.Background(), f.control, s)
	if err != nil || len(list) != 2 {
		t.Fatalf("two explicitly bound capabilities rejected: %#v %v", list, err)
	}
	s.policy.Rules[0].Capabilities = nil
	if _, err := taskCapabilities(context.Background(), f.control, s); err == nil {
		t.Fatal("legacy operation-only policy accepted ambiguous capabilities")
	}
}

func TestCapabilityBoundProposalRejectsUnselectedOrChangedImplementation(t *testing.T) {
	for _, scenario := range []string{"selected", "other reference", "changed digest", "missing digest"} {
		t.Run(scenario, func(t *testing.T) {
			f, selected := capabilityFixture(t)
			ref := selected.Ref
			switch scenario {
			case "other reference":
				ref = "fixture.alternative@1"
			case "changed digest":
				f.control.credentialProviders[0].Actions[0].CapabilityDigest = "sha256:" + strings.Repeat("c", 64)
			case "missing digest":
				f.control.credentialProviders[0].Actions[0].CapabilityDigest = ""
			}
			err := f.app.Run(context.Background(), []string{"action", "propose", "--capability", ref, "--operation", "ShiftVector", "--resource", "fixture://system-1/selected", "--parameters-file", "-"})
			if scenario == "selected" {
				if err != nil || f.control.typedActionRequest.CapabilityRef != selected.Ref {
					t.Fatalf("selected proposal failed: %v", err)
				}
			} else if err == nil || f.control.typedActionRequest.SessionID != "" {
				t.Fatal("unselected proposal reached control plane")
			}
		})
	}
}

func TestCapabilityBoundExecutionChecksReturnedActionIdentity(t *testing.T) {
	for _, scenario := range []string{"selected", "other reference", "changed digest", "missing digest"} {
		t.Run(scenario, func(t *testing.T) {
			f, _ := capabilityFixture(t)
			switch scenario {
			case "other reference":
				f.control.typedActions[0].CapabilityRef = "fixture.alternative@1"
			case "changed digest":
				f.control.typedActions[0].CapabilityDigest = "sha256:" + strings.Repeat("c", 64)
			case "missing digest":
				f.control.typedActions[0].CapabilityDigest = ""
			}
			err := f.app.Run(context.Background(), []string{"action", "execute", "action-a"})
			if scenario == "selected" {
				if err != nil || f.control.executedTypedActionID != "action-a" {
					t.Fatalf("selected execution failed: %v", err)
				}
			} else if err == nil || f.control.executedTypedActionID != "" {
				t.Fatal("unselected execution reached control plane")
			}
		})
	}
}
