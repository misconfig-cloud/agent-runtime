package enforcement

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/hook"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
	"github.com/misconfig-cloud/agent-runtime/internal/spool"
)

type Control interface {
	Session(context.Context, string) (domain.AgentSession, error)
	Policy(context.Context, string) (policy.SignedBundle, error)
	PutReceipt(context.Context, spool.Receipt) error
	Stop(context.Context, string, string) error
}

type Result struct {
	Decision policy.Decision
	Action   domain.ActionEnvelope
}

type Engine struct {
	Store   localstate.Store
	Control Control
	Now     func() time.Time
}

func (e Engine) Pre(ctx context.Context, activePath string, input hook.Input) (Result, error) {
	active, config, publicKey, err := e.load(activePath)
	if err != nil {
		return Result{}, err
	}
	now := e.now()

	action, err := hook.Action(active.Profile, active.Session, input, now)
	if err != nil {
		return Result{}, err
	}
	inputDigest, err := hook.InputDigest(input)
	if err != nil {
		return Result{}, err
	}
	signed, err := e.cachedPolicy(config, active, publicKey)
	if err != nil {
		decision := policy.Decision{
			Effect: policy.EffectDeny, RuleID: "misconfig.policy.unavailable",
			Reason: "a current signed policy is unavailable", PolicyRelease: active.Profile.PolicyRelease,
		}
		persisted, persistErr := e.Store.LoadOrSaveAction(active.Session.ID, hook.CorrelationKey(input), localstate.PendingAction{
			Action: action, Decision: decision, InputDigest: inputDigest,
		})
		if persistErr != nil {
			return Result{}, fmt.Errorf("persist native action identity: %w", persistErr)
		}
		action, decision = persisted.Action, stricterDecision(persisted.Decision, decision)
		if recordErr := e.record(action, decision, spool.OutcomeBlocked, ""); recordErr != nil {
			return Result{}, recordErr
		}
		return Result{Decision: decision, Action: action}, nil
	}
	decision := (policy.Evaluator{Bundle: signed.Bundle}).Evaluate(active.Profile, active.Session, action, now)
	if transportDecision, tool, ok := e.taskTransportDecision(active, signed.Bundle, input.ToolName); ok {
		decision = transportDecision
		action.Operation = "misconfig.task_transport." + tool
		action.Resource = "misconfig://sessions/" + active.Session.ID
		// This receipt is for transport access, not for a provider mutation.
		action.Parameters = map[string]any{"hook_tool_use_id": input.ToolUseID}
	}
	persisted, err := e.Store.LoadOrSaveAction(active.Session.ID, hook.CorrelationKey(input), localstate.PendingAction{
		Action: action, Decision: decision, InputDigest: inputDigest,
	})
	if err != nil {
		return Result{}, fmt.Errorf("persist native action identity: %w", err)
	}
	action, decision = persisted.Action, stricterDecision(persisted.Decision, decision)

	outcome := spool.OutcomeBlocked
	switch decision.Effect {
	case policy.EffectAllow:
		outcome = spool.OutcomeApproved
	case policy.EffectApproval:
		outcome = spool.OutcomeWaitingForApproval
	case policy.EffectStop:
		active.Session.State = domain.SessionStopped
		if err := e.Store.MarkStopped(active.Session.ID); err != nil {
			return Result{}, fmt.Errorf("persist session stop marker: %w", err)
		}
		if _, err := e.Store.SaveActive(active); err != nil {
			return Result{}, fmt.Errorf("persist stopped session: %w", err)
		}
	}
	if err := e.record(action, decision, outcome, ""); err != nil {
		return Result{}, err
	}
	return Result{Decision: decision, Action: action}, nil
}

// Native retries retain their original action identity, not an obsolete allow
// decision. Expiry, revocation or a new denial must still block the retry.
func stricterDecision(previous, current policy.Decision) policy.Decision {
	rank := map[policy.Effect]int{policy.EffectAllow: 1, policy.EffectApproval: 2, policy.EffectTyped: 3, policy.EffectDeny: 4, policy.EffectStop: 5}
	if rank[current.Effect] >= rank[previous.Effect] {
		return current
	}
	return previous
}

func (e Engine) taskTransportDecision(active localstate.ActiveSession, bundle policy.Bundle, toolName string) (policy.Decision, string, bool) {
	binding, err := e.Store.LoadTaskBridge(active.Session.ID)
	if err != nil {
		return policy.Decision{}, "", false
	}
	tool, matched := binding.NativeTool(toolName)
	if !matched {
		return policy.Decision{}, "", false
	}
	decision := policy.Decision{Effect: policy.EffectDeny, RuleID: "misconfig.task_transport", Reason: "task transport binding is invalid or unavailable", PolicyRelease: bundle.Release}
	digest, err := domain.Digest(active.Profile)
	if err != nil || digest != active.Session.ProfileDigest || active.Session.State != domain.SessionRunning ||
		active.Profile.Validate() != nil || active.Session.Validate() != nil || active.Profile.ID != active.Session.ProfileID || active.Profile.TenantID != active.Session.TenantID ||
		bundle.ProfileID != active.Profile.ID || bundle.TenantID != active.Profile.TenantID || bundle.Release != active.Profile.PolicyRelease ||
		binding.Validate(active.Session.ID, digest) != nil {
		return decision, tool, true
	}
	// Only the exact launcher-owned server and fixed task tools use this path.
	// The tool server independently authenticates/revalidates every request;
	// broker execution remains the infrastructure authorization boundary.
	decision.Effect = policy.EffectAllow
	decision.Reason = "Task transport only; provider actions require separate policy, approval and verification checks"
	return decision, tool, true
}

func (e Engine) Post(ctx context.Context, activePath string, input hook.Input) error {
	active, _, _, err := e.load(activePath)
	if err != nil {
		return err
	}
	key := hook.CorrelationKey(input)
	pending, err := e.Store.LoadAction(active.Session.ID, key)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return err
		}
		return fmt.Errorf("load pending action: %w", err)
	}
	outcome, conclusive := completionOutcome(input)
	if !conclusive {
		// Codex currently emits raw strings for several successful and failed
		// built-in tools. A raw string has no stable success bit, so retaining
		// only the pre-tool approval is more honest than inventing success.
		return nil
	}
	receiptDigest := ""
	if input.ToolResponse != nil {
		receiptDigest, _ = domain.Digest(input.ToolResponse)
	}
	if err := e.record(pending.Action, pending.Decision, outcome, receiptDigest); err != nil {
		return err
	}
	return nil
}

func (e Engine) Replay(ctx context.Context) error {
	config, err := e.Store.LoadConfig()
	if err != nil {
		return err
	}
	receipts := spool.Store{Root: e.Store.ReceiptRoot()}
	pending, err := receipts.Pending()
	if err != nil {
		return err
	}
	for _, receipt := range pending {
		if receipt.TenantID != config.TenantID {
			return errors.New("pending receipt tenant does not match enrolled device")
		}
		if err := e.Control.PutReceipt(ctx, receipt); err != nil {
			return err
		}
		if err := receipts.MarkSent(receipt.ID); err != nil {
			return err
		}
	}
	return nil
}

func (e Engine) record(action domain.ActionEnvelope, decision policy.Decision, outcome spool.Outcome, providerReceipt string) error {
	receipt, err := spool.NewReceipt(action, decision, outcome, providerReceipt, e.now())
	if err != nil {
		return err
	}
	store := spool.Store{Root: e.Store.ReceiptRoot()}
	return store.Put(receipt)
}

func (e Engine) cachedPolicy(config localstate.Config, active localstate.ActiveSession, publicKey ed25519.PublicKey) (policy.SignedBundle, error) {
	cache := policy.Cache{Path: e.Store.PolicyPath(active.Session.ID), PublicKey: publicKey, Now: e.Now}
	signed, err := cache.Load()
	if err != nil {
		return policy.SignedBundle{}, err
	}
	if signed.KeyID != config.PolicyKeyID {
		return policy.SignedBundle{}, errors.New("policy signing key does not match enrolled device")
	}
	return signed, nil
}

// Refresh is the only path that contacts the control plane while an agent is
// running. Native pre/post hooks never call it: they make bounded decisions
// from the atomically refreshed session snapshot and signed policy cache.
func (e Engine) Refresh(ctx context.Context, activePath string) error {
	if e.Control == nil {
		return errors.New("control plane client is required for refresh")
	}
	active, config, publicKey, err := e.load(activePath)
	if err != nil {
		return err
	}
	if active.Session.State == domain.SessionStopped || e.Store.IsStopped(active.Session.ID) {
		return e.Control.Stop(ctx, active.Session.ID, "local policy stopped the session")
	}
	remote, err := e.Control.Session(ctx, active.Session.ID)
	if err != nil {
		return fmt.Errorf("refresh session: %w", err)
	}
	if remote.ID != active.Session.ID || remote.TenantID != config.TenantID || remote.DeviceID != config.DeviceID || remote.ProfileID != active.Profile.ID {
		return errors.New("refreshed session identity does not match the local binding")
	}
	if e.Store.IsStopped(active.Session.ID) {
		return e.Control.Stop(ctx, active.Session.ID, "local policy stopped the session")
	}
	active.Session = remote
	if _, err := e.Store.SaveActive(active); err != nil {
		return fmt.Errorf("persist refreshed session: %w", err)
	}
	if remote.State != domain.SessionRunning {
		return nil
	}
	signed, err := e.Control.Policy(ctx, active.Session.ID)
	if err != nil {
		return fmt.Errorf("refresh policy: %w", err)
	}
	if signed.KeyID != config.PolicyKeyID {
		return errors.New("policy signing key does not match enrolled device")
	}
	cache := policy.Cache{Path: e.Store.PolicyPath(active.Session.ID), PublicKey: publicKey, Now: e.Now}
	if err := cache.Store(signed); err != nil {
		return fmt.Errorf("verify refreshed policy: %w", err)
	}
	return e.Replay(ctx)
}

func (e Engine) load(activePath string) (localstate.ActiveSession, localstate.Config, ed25519.PublicKey, error) {
	active, err := localstate.LoadActive(activePath)
	if err != nil {
		return localstate.ActiveSession{}, localstate.Config{}, nil, fmt.Errorf("load active session: %w", err)
	}
	config, err := e.Store.LoadConfig()
	if err != nil {
		return localstate.ActiveSession{}, localstate.Config{}, nil, fmt.Errorf("load device configuration: %w", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(config.PolicyPublicKey)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return localstate.ActiveSession{}, localstate.Config{}, nil, errors.New("enrolled policy public key is invalid")
	}
	if active.Session.TenantID != config.TenantID || active.Session.DeviceID != config.DeviceID {
		return localstate.ActiveSession{}, localstate.Config{}, nil, errors.New("active session does not belong to enrolled device")
	}
	if e.Store.IsStopped(active.Session.ID) {
		active.Session.State = domain.SessionStopped
	}
	return active, config, ed25519.PublicKey(decoded), nil
}

func (e Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func completionOutcome(input hook.Input) (spool.Outcome, bool) {
	if strings.Contains(strings.ToLower(input.HookEventName), "fail") {
		return spool.OutcomeFailed, true
	}
	response, ok := input.ToolResponse.(map[string]any)
	if !ok {
		return "", false
	}
	if value, ok := response["is_error"].(bool); ok && value {
		return spool.OutcomeFailed, true
	}
	if value, ok := response["success"].(bool); ok {
		if value {
			return spool.OutcomeSucceeded, true
		}
		return spool.OutcomeFailed, true
	}
	if response["error"] != nil {
		return spool.OutcomeFailed, true
	}
	if value, ok := response["ok"].(bool); ok {
		if value {
			return spool.OutcomeSucceeded, true
		}
		return spool.OutcomeFailed, true
	}
	if value, ok := response["status"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "ok", "success", "succeeded", "completed":
			return spool.OutcomeSucceeded, true
		case "error", "failed", "failure":
			return spool.OutcomeFailed, true
		}
	}
	return "", false
}
