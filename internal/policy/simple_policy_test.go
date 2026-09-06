package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	adapter "github.com/misconfig-cloud/provider-sdk"
)

func TestSimplePolicySignatureRejectsDowngradeAndSubstitution(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, bundle := fixture(t)
	bundle.Rules = []Rule{{ID: "typed", Effect: EffectTyped, Reason: "server assessed"}}
	bundle.SimplePolicy = &adapter.SimplePolicy{Protocol: adapter.SimplePolicyProtocol, Preset: adapter.PolicyReadOnly}
	signed, err := Sign(bundle, "test", private)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, public, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []*adapter.SimplePolicy{nil, {Protocol: adapter.SimplePolicyProtocol, Preset: adapter.PolicyReviewChanges}} {
		changed := signed
		changed.Bundle.SimplePolicy = p
		if Verify(changed, public, time.Now()) == nil {
			t.Fatal("policy restriction silently dropped or substituted")
		}
	}
	// Legacy policies serialize exactly as before (no null/new field).
	bundle.SimplePolicy = nil
	raw, _ := json.Marshal(bundle)
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	if _, exists := fields["simple_policy"]; exists {
		t.Fatal("legacy signature payload changed")
	}
}

func TestSimplePolicyCannotTurnLocalHookIntoExecutionAuthority(t *testing.T) {
	profile, active, action, bundle := fixture(t)
	bundle.SimplePolicy = &adapter.SimplePolicy{Protocol: adapter.SimplePolicyProtocol, Preset: adapter.PolicyReadOnly}
	for _, effect := range []Effect{EffectAllow, EffectApproval, EffectTyped} {
		bundle.Rules = []Rule{{ID: "test", Effect: effect, Reason: "read claim"}}
		if got := (Evaluator{Bundle: bundle}).Evaluate(profile, active, action, time.Now()); got.Effect != EffectDeny {
			t.Fatalf("attached credentials gained simple-policy authority: %+v", got)
		}
	}
}
