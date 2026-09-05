package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	provideradapter "github.com/misconfig-cloud/provider-sdk"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
)

// actionSession binds the local action surface to one live session. This is
// defense in depth, not a replacement for the broker's execution-time checks
// or isolation from other processes holding the device credential.
type actionSession struct {
	active localstate.ActiveSession
	policy policy.Bundle
}

func (a *App) loadActionSession(ctx context.Context, store localstate.Store, config localstate.Config, control Control) (actionSession, error) {
	active, err := a.activeSession(config)
	if err != nil {
		return actionSession{}, err
	}
	if err := active.Profile.Validate(); err != nil {
		return actionSession{}, fmt.Errorf("invalid action session profile: %w", err)
	}
	if err := active.Session.Validate(); err != nil {
		return actionSession{}, fmt.Errorf("invalid action session: %w", err)
	}
	if active.Profile.TenantID != config.TenantID || active.Session.ActorID != config.ActorID || store.IsStopped(active.Session.ID) {
		return actionSession{}, errors.New("action session identity is invalid or stopped")
	}
	digest, err := domain.Digest(active.Profile)
	if err != nil || digest != active.Session.ProfileDigest {
		return actionSession{}, errors.New("action session profile was changed; launch a new session")
	}
	remote, err := control.Session(ctx, active.Session.ID)
	if err != nil {
		return actionSession{}, fmt.Errorf("verify live action session: %w", err)
	}
	if remote.ID != active.Session.ID || remote.TenantID != config.TenantID || remote.DeviceID != config.DeviceID ||
		remote.ActorID != config.ActorID || remote.ProfileID != active.Profile.ID || remote.ProfileDigest != digest ||
		remote.State != domain.SessionRunning {
		return actionSession{}, errors.New("action session is no longer running with the original identity")
	}
	signed, err := control.Policy(ctx, active.Session.ID)
	if err != nil {
		return actionSession{}, fmt.Errorf("verify current action policy: %w", err)
	}
	key, err := base64.RawURLEncoding.DecodeString(config.PolicyPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || signed.KeyID != config.PolicyKeyID {
		return actionSession{}, errors.New("action policy signing key does not match enrollment")
	}
	if err := policy.Verify(signed, ed25519.PublicKey(key), a.Now()); err != nil {
		return actionSession{}, fmt.Errorf("verify action policy: %w", err)
	}
	if signed.Bundle.TenantID != config.TenantID || signed.Bundle.ProfileID != active.Profile.ID || signed.Bundle.Release != active.Profile.PolicyRelease {
		return actionSession{}, errors.New("action policy does not belong to the active profile")
	}
	return actionSession{active: active, policy: signed.Bundle}, nil
}

func (s actionSession) owns(action controlclient.TypedAction) bool {
	return action.TenantID == s.active.Session.TenantID && action.SessionID == s.active.Session.ID
}

func (a *App) checkTypedAction(s actionSession, operation, resource, environment string, parameters json.RawMessage) error {
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(parameters))
	decoder.UseNumber()
	if len(parameters) == 0 || len(parameters) > maximumActionParametersSize || !json.Valid(parameters) || decoder.Decode(&object) != nil || object == nil {
		return errors.New("action parameters must be a bounded JSON object")
	}
	id, err := domain.NewID("act")
	if err != nil {
		return err
	}
	active := s.active
	decision := (policy.Evaluator{Bundle: s.policy}).Evaluate(active.Profile, active.Session, domain.ActionEnvelope{
		ID: id, TenantID: active.Session.TenantID, ActorID: active.Session.ActorID,
		DeviceID: active.Session.DeviceID, SessionID: active.Session.ID, Agent: active.Profile.Agent,
		AdapterRelease: active.Profile.AdapterRelease, Tool: "misconfig.action", Operation: operation, Resource: resource,
		Destination: domain.Destination{Provider: active.Profile.Scope.Provider, AccountRef: active.Profile.Scope.AccountRef, Environment: environment},
		Parameters:  object, RequestedAt: a.Now(),
	}, a.Now())
	// An allow/approval rule for a native tool must not become typed execution
	// authority. The broker separately validates the exact capability release.
	if decision.Effect != policy.EffectTyped {
		return fmt.Errorf("typed action is outside the current task: %s", decision.Reason)
	}
	// Check the original bytes too: decoding to an envelope must not erase
	// duplicate keys or otherwise normalize an invalid constrained request.
	rules := make([]provideradapter.AuthorizationRule, 0, len(s.policy.Rules))
	for _, rule := range s.policy.Rules {
		rules = append(rules, provideradapter.AuthorizationRule{
			Providers: rule.Providers, Operations: rule.Operations, ResourcePrefixes: rule.ResourcePrefixes,
			ResourceIDs: rule.ResourceIDs, ParameterLimits: rule.ParameterLimits,
		})
	}
	if !provideradapter.ParametersWithinRules(rules, active.Profile.Scope.Provider, operation, resource, parameters) {
		return errors.New("action parameters exceed the task limits or contain ambiguous JSON")
	}
	return nil
}
