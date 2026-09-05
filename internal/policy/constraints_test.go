package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	provideradapter "github.com/misconfig-cloud/provider-sdk"
)

func TestExactResourceAndParameterCeilings(t *testing.T) {
	for _, tc := range []struct {
		name, resource string
		parameters     map[string]any
		effect         Effect
	}{
		{"allowed", "edge://station/alert/main", map[string]any{"value": 80}, EffectAllow},
		{"prefix collision", "edge://station/alert/main-backup", map[string]any{"value": 80}, EffectDeny},
		{"over ceiling", "edge://station/alert/main", map[string]any{"value": 81}, EffectDeny},
		{"unknown parameter", "edge://station/alert/main", map[string]any{"value": 80, "delete": true}, EffectDeny},
		{"missing parameter", "edge://station/alert/main", map[string]any{}, EffectDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, active, action, bundle := fixture(t)
			profile.Scope.Provider = "custom-edge"
			profile.Scope.ResourcePrefixes = nil
			profile.Scope.ResourceIDs = []string{"edge://station/alert/main"}
			active.ProfileDigest, _ = domain.Digest(profile)
			action.Destination.Provider = profile.Scope.Provider
			action.Operation, action.Resource, action.Parameters = "AdjustThreshold", tc.resource, tc.parameters
			ceiling := json.Number("80")
			bundle.Rules = []Rule{
				{ID: "broad", Effect: EffectAllow, Reason: "legacy allow"},
				{ID: "bounded", Effect: EffectAllow, Operations: []string{action.Operation}, ResourceIDs: profile.Scope.ResourceIDs, Reason: "selected work",
					ParameterLimits: &provideradapter.ParameterLimits{Fields: map[string]provideradapter.ParameterLimit{"value": {Type: "integer", Maximum: &ceiling}}}},
			}
			decision := (Evaluator{Bundle: bundle}).Evaluate(profile, active, action, time.Now().UTC())
			if decision.Effect != tc.effect {
				t.Fatalf("%#v", decision)
			}
			bundle.Rules = append(bundle.Rules, Rule{ID: "stop", Effect: EffectStop, Reason: "stop task"})
			if tc.resource == profile.Scope.ResourceIDs[0] {
				decision = (Evaluator{Bundle: bundle}).Evaluate(profile, active, action, time.Now().UTC())
				if decision.Effect != EffectStop {
					t.Fatalf("parameter check masked stop: %#v", decision)
				}
			}
		})
	}
}

func TestRemovingUnknownConstraintsInvalidatesSignedPolicy(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, bundle := fixture(t)
	bundle.Rules[0].ResourceIDs = []string{"edge://station/alert/main"}
	bundle.Rules[0].ParameterLimits = &provideradapter.ParameterLimits{Fields: map[string]provideradapter.ParameterLimit{}}
	signed, err := Sign(bundle, "test", private)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, public, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	// An older decoder drops unfamiliar fields. Verify against exactly that
	// reconstructed payload, not an assertion about version string ordering.
	encoded, _ := json.Marshal(signed.Bundle)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(fields["rules"], &rules); err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		delete(rule, "resource_ids")
		delete(rule, "parameter_limits")
	}
	fields["rules"], _ = json.Marshal(rules)
	encoded, _ = json.Marshal(fields)
	var stripped Bundle
	if err := json.Unmarshal(encoded, &stripped); err != nil {
		t.Fatal(err)
	}
	signed.Bundle = stripped
	if err := Verify(signed, public, time.Now().UTC()); err == nil {
		t.Fatal("downgraded policy retained authority")
	}
}
