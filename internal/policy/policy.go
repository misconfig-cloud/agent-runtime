package policy

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	provideradapter "github.com/misconfig-cloud/provider-sdk"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
)

type Effect string

const (
	EffectAllow    Effect = "allow"
	EffectDeny     Effect = "deny"
	EffectApproval Effect = "require_approval"
	EffectTyped    Effect = "require_typed_capability"
	EffectStop     Effect = "stop_session"
)

type Rule struct {
	ID               string                               `json:"id"`
	Effect           Effect                               `json:"effect"`
	Providers        []string                             `json:"providers,omitempty"`
	Operations       []string                             `json:"operations,omitempty"`
	Capabilities     []provideradapter.CapabilitySelector `json:"capabilities,omitempty"`
	ResourcePrefixes []string                             `json:"resource_prefixes,omitempty"`
	ResourceIDs      []string                             `json:"resource_ids,omitempty"`
	ParameterLimits  *provideradapter.ParameterLimits     `json:"parameter_limits,omitempty"`
	Reason           string                               `json:"reason"`
}

type Bundle struct {
	Release   string    `json:"release"`
	TenantID  string    `json:"tenant_id"`
	ProfileID string    `json:"profile_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Rules     []Rule    `json:"rules"`
}

type SignedBundle struct {
	KeyID     string `json:"key_id"`
	Bundle    Bundle `json:"bundle"`
	Signature string `json:"signature"`
}

type Decision struct {
	Effect        Effect `json:"effect"`
	RuleID        string `json:"rule_id"`
	Reason        string `json:"reason"`
	PolicyRelease string `json:"policy_release"`
}

func (b Bundle) Validate(now time.Time) error {
	for label, value := range map[string]string{"release": b.Release, "tenant_id": b.TenantID, "profile_id": b.ProfileID} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", label)
		}
	}
	if b.IssuedAt.IsZero() || b.ExpiresAt.IsZero() || !b.ExpiresAt.After(b.IssuedAt) {
		return errors.New("valid issued_at and expires_at are required")
	}
	if !now.Before(b.ExpiresAt) {
		return errors.New("policy bundle is expired")
	}
	if len(b.Rules) == 0 {
		return errors.New("at least one policy rule is required")
	}
	for _, rule := range b.Rules {
		if err := provideradapter.ValidateCapabilitySelection(rule.Capabilities); err != nil {
			return err
		}
		if err := provideradapter.ValidateResourceSelection(rule.ResourcePrefixes, rule.ResourceIDs); err != nil {
			return err
		}
		if rule.ParameterLimits != nil {
			if rule.Effect != EffectAllow && rule.Effect != EffectTyped {
				return errors.New("parameter ceilings require an allow or typed rule")
			}
			if err := rule.ParameterLimits.Validate(); err != nil {
				return err
			}
		}
		if strings.TrimSpace(rule.ID) == "" || strings.TrimSpace(rule.Reason) == "" {
			return errors.New("every rule requires id and reason")
		}
		switch rule.Effect {
		case EffectAllow, EffectDeny, EffectApproval, EffectTyped, EffectStop:
		default:
			return fmt.Errorf("rule %s has invalid effect %q", rule.ID, rule.Effect)
		}
	}
	return nil
}

func Sign(bundle Bundle, keyID string, privateKey ed25519.PrivateKey) (SignedBundle, error) {
	if err := bundle.Validate(time.Now().UTC()); err != nil {
		return SignedBundle{}, err
	}
	if strings.TrimSpace(keyID) == "" {
		return SignedBundle{}, errors.New("key_id is required")
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		return SignedBundle{}, fmt.Errorf("encode policy: %w", err)
	}
	return SignedBundle{
		KeyID: keyID, Bundle: bundle,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func Verify(signed SignedBundle, publicKey ed25519.PublicKey, now time.Time) error {
	if err := signed.Bundle.Validate(now); err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil {
		return errors.New("policy signature is malformed")
	}
	payload, err := json.Marshal(signed.Bundle)
	if err != nil {
		return fmt.Errorf("encode policy: %w", err)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("policy signature is invalid")
	}
	return nil
}

type Evaluator struct {
	Bundle Bundle
}

func (e Evaluator) Evaluate(profile domain.SessionProfile, session domain.AgentSession, action domain.ActionEnvelope, now time.Time) Decision {
	fail := func(reason string) Decision {
		return Decision{Effect: EffectDeny, RuleID: "misconfig.boundary", Reason: reason, PolicyRelease: e.Bundle.Release}
	}
	if err := e.Bundle.Validate(now); err != nil {
		return fail(err.Error())
	}
	if err := profile.Validate(); err != nil {
		return fail("session profile is invalid")
	}
	if err := session.Validate(); err != nil {
		return fail("agent session is invalid")
	}
	if err := action.Validate(); err != nil {
		return fail("action envelope is invalid")
	}
	if session.State != domain.SessionRunning {
		return fail("session is not running")
	}
	if e.Bundle.TenantID != profile.TenantID || e.Bundle.ProfileID != profile.ID ||
		profile.TenantID != session.TenantID || session.ProfileID != profile.ID ||
		action.TenantID != session.TenantID || action.SessionID != session.ID ||
		action.ActorID != session.ActorID || action.DeviceID != session.DeviceID ||
		action.Agent != profile.Agent || action.AdapterRelease != profile.AdapterRelease {
		return fail("session identity or immutable release binding does not match")
	}
	profileDigest, err := domain.Digest(profile)
	if err != nil || profileDigest != session.ProfileDigest {
		return fail("session profile digest does not match")
	}
	if action.Destination.Provider != profile.Scope.Provider ||
		action.Destination.AccountRef != profile.Scope.AccountRef ||
		!slices.Contains(profile.Scope.Environments, action.Destination.Environment) {
		return fail("action destination is outside the session scope")
	}
	if !provideradapter.MatchesResources(action.Resource, profile.Scope.ResourcePrefixes, profile.Scope.ResourceIDs) {
		return fail("action resource is outside the session scope")
	}
	// Preserve stop/deny precedence even when a parameter ceiling also fails.
	for _, effect := range []Effect{EffectStop, EffectDeny} {
		for _, rule := range e.Bundle.Rules {
			if rule.Effect == effect && matches(rule, action) {
				return Decision{Effect: rule.Effect, RuleID: rule.ID, Reason: rule.Reason, PolicyRelease: e.Bundle.Release}
			}
		}
	}
	parameters, err := json.Marshal(action.Parameters)
	if err != nil {
		return fail("action parameters cannot be verified")
	}
	for _, rule := range e.Bundle.Rules {
		if rule.ParameterLimits != nil && matches(rule, action) && !rule.ParameterLimits.Matches(parameters) {
			return fail("action parameters exceed the task limits")
		}
	}

	for _, effect := range []Effect{EffectApproval, EffectTyped, EffectAllow} {
		for _, rule := range e.Bundle.Rules {
			if rule.Effect == effect && matches(rule, action) {
				return Decision{Effect: rule.Effect, RuleID: rule.ID, Reason: rule.Reason, PolicyRelease: e.Bundle.Release}
			}
		}
	}
	return fail("no policy rule matched")
}

func matches(rule Rule, action domain.ActionEnvelope) bool {
	var capability provideradapter.CapabilitySelector
	if action.Capability != nil {
		capability = *action.Capability
	}
	return memberOrAny(rule.Providers, action.Destination.Provider) &&
		memberOrAny(rule.Operations, action.Operation) &&
		provideradapter.MatchesCapabilities(capability, rule.Capabilities) &&
		provideradapter.MatchesResources(action.Resource, rule.ResourcePrefixes, rule.ResourceIDs)
}

func memberOrAny(values []string, actual string) bool {
	return len(values) == 0 || slices.Contains(values, actual)
}

func hasPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

type Cache struct {
	Path      string
	PublicKey ed25519.PublicKey
	Now       func() time.Time
}

func (c Cache) Store(bundle SignedBundle) error {
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	if err := Verify(bundle, c.PublicKey, now); err != nil {
		return err
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("encode signed policy: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o700); err != nil {
		return fmt.Errorf("create policy directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(c.Path), ".policy-*.tmp")
	if err != nil {
		return fmt.Errorf("create policy cache: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect policy cache: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write policy cache: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync policy cache: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close policy cache: %w", err)
	}
	if err := os.Rename(temporaryPath, c.Path); err != nil {
		return fmt.Errorf("replace policy cache: %w", err)
	}
	directory, err := os.Open(filepath.Dir(c.Path))
	if err != nil {
		return fmt.Errorf("open policy cache directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync policy cache directory: %w", err)
	}
	return nil
}

func (c Cache) Load() (SignedBundle, error) {
	encoded, err := os.ReadFile(c.Path)
	if err != nil {
		return SignedBundle{}, fmt.Errorf("read policy cache: %w", err)
	}
	var bundle SignedBundle
	if err := json.Unmarshal(encoded, &bundle); err != nil {
		return SignedBundle{}, fmt.Errorf("decode policy cache: %w", err)
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	if err := Verify(bundle, c.PublicKey, now); err != nil {
		return SignedBundle{}, err
	}
	return bundle, nil
}
