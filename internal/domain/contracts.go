package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

func NewID(prefix string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(random), nil
}

type EnforcementLevel string

const (
	EnforcementObserved EnforcementLevel = "observed"
	EnforcementHook     EnforcementLevel = "hook_enforced"
	EnforcementBrokered EnforcementLevel = "credential_brokered"
	EnforcementTyped    EnforcementLevel = "typed_execution"
	EnforcementVerified EnforcementLevel = "verified"
)

type CredentialMode string

const (
	CredentialAttach   CredentialMode = "attach"
	CredentialBrokered CredentialMode = "brokered"
)

type AgentKind string

const (
	AgentCodex  AgentKind = "codex"
	AgentClaude AgentKind = "claude"
)

type SessionState string

const (
	SessionStarting SessionState = "starting"
	SessionRunning  SessionState = "running"
	SessionStopping SessionState = "stopping"
	SessionStopped  SessionState = "stopped"
	SessionFailed   SessionState = "failed"
)

type Scope struct {
	Provider         string   `json:"provider"`
	AccountRef       string   `json:"account_ref"`
	Environments     []string `json:"environments"`
	ResourcePrefixes []string `json:"resource_prefixes,omitempty"`
}

func (s Scope) Validate() error {
	if strings.TrimSpace(s.Provider) == "" {
		return errors.New("provider is required")
	}
	if strings.TrimSpace(s.AccountRef) == "" {
		return errors.New("account_ref is required")
	}
	if len(s.Environments) == 0 {
		return errors.New("at least one environment is required")
	}
	for _, environment := range s.Environments {
		if strings.TrimSpace(environment) == "" {
			return errors.New("environment cannot be empty")
		}
	}
	return nil
}

type SessionProfile struct {
	ID             string           `json:"id"`
	TenantID       string           `json:"tenant_id"`
	Name           string           `json:"name"`
	Agent          AgentKind        `json:"agent"`
	Workspace      string           `json:"workspace"`
	Scope          Scope            `json:"scope"`
	Enforcement    EnforcementLevel `json:"enforcement"`
	CredentialMode CredentialMode   `json:"credential_mode"`
	AdapterRelease string           `json:"adapter_release"`
	PolicyRelease  string           `json:"policy_release"`
	CreatedAt      time.Time        `json:"created_at"`
}

func (p SessionProfile) Validate() error {
	for label, value := range map[string]string{
		"id": p.ID, "tenant_id": p.TenantID, "name": p.Name,
		"workspace": p.Workspace, "policy_release": p.PolicyRelease,
		"adapter_release": p.AdapterRelease,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", label)
		}
	}
	if p.Agent != AgentCodex && p.Agent != AgentClaude {
		return fmt.Errorf("unsupported agent %q", p.Agent)
	}
	if p.CredentialMode != CredentialAttach && p.CredentialMode != CredentialBrokered {
		return fmt.Errorf("unsupported credential mode %q", p.CredentialMode)
	}
	if p.CredentialMode == CredentialAttach && p.Enforcement != EnforcementObserved && p.Enforcement != EnforcementHook {
		return errors.New("attach credentials cannot claim brokered or verified enforcement")
	}
	if p.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	return p.Scope.Validate()
}

type AgentSession struct {
	ID            string       `json:"id"`
	TenantID      string       `json:"tenant_id"`
	ProfileID     string       `json:"profile_id"`
	ProfileDigest string       `json:"profile_digest"`
	ActorID       string       `json:"actor_id"`
	DeviceID      string       `json:"device_id"`
	State         SessionState `json:"state"`
	StartedAt     time.Time    `json:"started_at"`
	StoppedAt     *time.Time   `json:"stopped_at,omitempty"`
}

func (s AgentSession) Validate() error {
	for label, value := range map[string]string{
		"id": s.ID, "tenant_id": s.TenantID, "profile_id": s.ProfileID,
		"profile_digest": s.ProfileDigest, "actor_id": s.ActorID,
		"device_id": s.DeviceID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", label)
		}
	}
	switch s.State {
	case SessionStarting, SessionRunning, SessionStopping, SessionStopped, SessionFailed:
	default:
		return fmt.Errorf("invalid session state %q", s.State)
	}
	if s.StartedAt.IsZero() {
		return errors.New("started_at is required")
	}
	return nil
}

type Destination struct {
	Provider    string `json:"provider"`
	AccountRef  string `json:"account_ref"`
	Environment string `json:"environment"`
	Location    string `json:"location,omitempty"`
}

// NativeActionIdentity contains only the redacted correlation coordinates
// exposed by an agent client's hook protocol. It deliberately excludes the
// transcript path, working directory, prompt, command output, and credentials.
type NativeActionIdentity struct {
	SessionID       string `json:"session_id,omitempty"`
	TurnID          string `json:"turn_id,omitempty"`
	ToolUseID       string `json:"tool_use_id,omitempty"`
	ParentToolUseID string `json:"parent_tool_use_id,omitempty"`
	AgentID         string `json:"agent_id,omitempty"`
	AgentType       string `json:"agent_type,omitempty"`
	Model           string `json:"model,omitempty"`
	PermissionMode  string `json:"permission_mode,omitempty"`
	PathClass       string `json:"path_class,omitempty"`
}

type ActionEnvelope struct {
	ID             string                 `json:"id"`
	TenantID       string                 `json:"tenant_id"`
	ActorID        string                 `json:"actor_id"`
	DeviceID       string                 `json:"device_id"`
	SessionID      string                 `json:"session_id"`
	Agent          AgentKind              `json:"agent"`
	AdapterRelease string                 `json:"adapter_release"`
	Tool           string                 `json:"tool"`
	Operation      string                 `json:"operation"`
	Resource       string                 `json:"resource"`
	Destination    Destination            `json:"destination"`
	Native         NativeActionIdentity   `json:"native,omitempty"`
	Parameters     map[string]interface{} `json:"parameters,omitempty"`
	RequestedAt    time.Time              `json:"requested_at"`
}

func (a ActionEnvelope) Validate() error {
	for label, value := range map[string]string{
		"id": a.ID, "tenant_id": a.TenantID, "actor_id": a.ActorID,
		"device_id": a.DeviceID, "session_id": a.SessionID,
		"adapter_release": a.AdapterRelease, "tool": a.Tool,
		"operation": a.Operation, "resource": a.Resource,
		"provider":    a.Destination.Provider,
		"account_ref": a.Destination.AccountRef,
		"environment": a.Destination.Environment,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", label)
		}
	}
	if a.Agent != AgentCodex && a.Agent != AgentClaude {
		return fmt.Errorf("unsupported agent %q", a.Agent)
	}
	if a.RequestedAt.IsZero() {
		return errors.New("requested_at is required")
	}
	return nil
}

func Digest(value interface{}) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode canonical value: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
