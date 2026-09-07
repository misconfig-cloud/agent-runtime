package enforcement

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/hook"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
	"github.com/misconfig-cloud/agent-runtime/internal/semantics"
	"github.com/misconfig-cloud/agent-runtime/internal/spool"
)

type Control interface {
	Session(context.Context, string) (domain.AgentSession, error)
	Policy(context.Context, string) (policy.SignedBundle, error)
	PutReceipt(context.Context, spool.Receipt) error
	Stop(context.Context, string, string) error
	AssessGuardrail(context.Context, string, controlclient.GuardrailAssessmentRequest) (controlclient.GuardrailDecision, error)
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
		if recordErr := e.record(action, decision, spool.OutcomeBlocked, "", 0, nil); recordErr != nil {
			return Result{}, recordErr
		}
		return Result{Decision: decision, Action: action}, nil
	}
	var decision policy.Decision
	if active.Profile.Scope.Provider == "local-agent" {
		redacted := hook.RedactedToolInput(input)
		redactedDigest, digestErr := hook.RedactedInputDigest(input.ToolName, redacted)
		if digestErr != nil {
			return Result{}, fmt.Errorf("digest redacted native action: %w", digestErr)
		}
		action.Parameters = map[string]any{"hook_tool_use_id": hook.CorrelationKey(input), "tool_input": redacted}
		decision = (policy.Evaluator{Bundle: signed.Bundle}).Evaluate(active.Profile, active.Session, action, now)
		if decision.Effect != policy.EffectDeny && decision.Effect != policy.EffectStop {
			decision = stricterDecision(decision, e.semanticDecision(ctx, active, signed.Bundle, input, redacted, redactedDigest))
		}
	} else {
		decision = (policy.Evaluator{Bundle: signed.Bundle}).Evaluate(active.Profile, active.Session, action, now)
	}
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
	if err := e.record(action, decision, outcome, "", 0, nil); err != nil {
		return Result{}, err
	}
	return Result{Decision: decision, Action: action}, nil
}

func (e Engine) semanticDecision(ctx context.Context, active localstate.ActiveSession, bundle policy.Bundle, input hook.Input, redacted map[string]any, inputDigest string) policy.Decision {
	fail := func(reason string) policy.Decision {
		return policy.Decision{Effect: policy.EffectDeny, RuleID: "misconfig.guardrail.unavailable", Reason: reason, PolicyRelease: bundle.Release}
	}
	if e.Control == nil {
		return fail("the semantic guardrail is unavailable")
	}
	local := (semantics.Engine{}).AnalyzeTool(semantics.ToolRequest{
		Workspace: active.Profile.Workspace, CWD: input.CWD, Name: input.ToolName, Input: input.ToolInput,
	})
	transport, reportErr := localTransportReport(local, inputDigest)
	if reportErr != nil {
		return fail("local analysis could not be prepared for recording")
	}
	decision, err := e.Control.AssessGuardrail(ctx, active.Session.ID, controlclient.GuardrailAssessmentRequest{
		ToolName: input.ToolName, ToolInput: redacted, NativeToolUseID: input.ToolUseID, PathClass: actionPathClass(input),
		AgentModel: input.Model, InputDigest: inputDigest,
		LocalAnalysis: &transport,
	})
	if err != nil {
		return fail("the semantic guardrail could not classify this action")
	}
	if !local.Fresh() {
		return fail("Filesystem evidence changed while the action was being checked; retry for a fresh assessment")
	}
	if !e.now().Before(bundle.ExpiresAt) || e.Store.IsStopped(active.Session.ID) {
		return fail("The session stopped or its signed policy expired during assessment")
	}
	if (decision.AssessmentSource != "local" && decision.AssessmentSource != "model_assisted") || decision.InputDigest != inputDigest || decision.Classification != string(transport.Classification) {
		return fail("the control plane did not acknowledge the exact local analysis")
	}
	if transport.Classification == semantics.CredentialExposure && decision.Effect != "block" {
		return fail("Local analysis detected possible credential disclosure")
	}
	if strings.TrimSpace(decision.Reason) == "" || decision.PolicyVersion < 1 {
		return fail("the semantic guardrail returned an invalid decision")
	}
	effect := policy.EffectDeny
	if decision.Effect == "continue" {
		effect = policy.EffectAllow
	} else if decision.Effect != "block" {
		return fail("the semantic guardrail returned an unsupported effect")
	}
	return policy.Decision{
		Effect: effect, RuleID: fmt.Sprintf("workspace-guard-v%d", decision.PolicyVersion),
		Reason: decision.Reason, PolicyRelease: bundle.Release,
	}
}

func actionPathClass(input hook.Input) string {
	if strings.TrimSpace(input.ParentToolUseID) != "" {
		return "nested"
	}
	if strings.TrimSpace(input.AgentID) != "" {
		return "subagent"
	}
	return "direct"
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
	exitCode := completionExitCode(input, outcome)
	if err := e.record(pending.Action, pending.Decision, outcome, receiptDigest, input.DurationMS, exitCode); err != nil {
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

func (e Engine) record(action domain.ActionEnvelope, decision policy.Decision, outcome spool.Outcome, providerReceipt string, durationMillis int64, exitCode *int) error {
	receipt, err := spool.NewReceipt(action, decision, outcome, providerReceipt, e.now())
	if err != nil {
		return err
	}
	if durationMillis > 0 {
		receipt.DurationMillis = durationMillis
	}
	receipt.ExitCode = exitCode
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

var exitCodePattern = regexp.MustCompile(`(?i)exit(?:ed)?(?: with)?(?: status| code)?[=: ]+(-?[0-9]+)`)

func completionExitCode(input hook.Input, outcome spool.Outcome) *int {
	if response, ok := input.ToolResponse.(map[string]any); ok {
		for _, key := range []string{"exit_code", "exitCode", "code"} {
			if code, ok := integerValue(response[key]); ok && code >= -1 && code <= 255 {
				return &code
			}
		}
	}
	for _, value := range []string{input.Error, fmt.Sprint(input.ToolResponse)} {
		if match := exitCodePattern.FindStringSubmatch(value); len(match) == 2 {
			if code, err := strconv.Atoi(match[1]); err == nil && code >= -1 && code <= 255 {
				return &code
			}
		}
	}
	code := 0
	if outcome == spool.OutcomeFailed {
		code = 1
	}
	return &code
}

func integerValue(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), int64(int(typed)) == typed
	case float64:
		return int(typed), typed == float64(int(typed))
	case json.Number:
		parsed, err := strconv.Atoi(typed.String())
		return parsed, err == nil
	default:
		return 0, false
	}
}
