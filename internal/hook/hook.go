package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
)

type Input struct {
	SessionID      string         `json:"session_id"`
	TurnID         string         `json:"turn_id,omitempty"`
	TranscriptPath string         `json:"transcript_path,omitempty"`
	Model          string         `json:"model,omitempty"`
	PermissionMode string         `json:"permission_mode,omitempty"`
	AgentID        string         `json:"agent_id,omitempty"`
	AgentType      string         `json:"agent_type,omitempty"`
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolResponse   any            `json:"tool_response,omitempty"`
	ToolUseID      string         `json:"tool_use_id"`
	Error          string         `json:"error,omitempty"`
	IsInterrupt    bool           `json:"is_interrupt,omitempty"`
	DurationMS     int64          `json:"duration_ms,omitempty"`
	CWD            string         `json:"cwd"`
}

var arnPattern = regexp.MustCompile(`arn:(?:aws|aws-us-gov|aws-cn):[^\s"']+`)

func Decode(encoded []byte) (Input, error) {
	var input Input
	if err := json.Unmarshal(encoded, &input); err != nil {
		return Input{}, fmt.Errorf("decode hook input: %w", err)
	}
	if strings.TrimSpace(input.ToolName) == "" {
		return Input{}, errors.New("hook tool_name is required")
	}
	if input.ToolInput == nil {
		input.ToolInput = map[string]any{}
	}
	return input, nil
}

func Action(activeProfile domain.SessionProfile, session domain.AgentSession, input Input, now time.Time) (domain.ActionEnvelope, error) {
	command := commandFrom(input)
	provider, operation, resource, location := classify(activeProfile, input.ToolName, command)
	key := input.ToolUseID
	if key == "" {
		digest, err := domain.Digest(struct{ Session, Tool, Command string }{session.ID, input.ToolName, command})
		if err != nil {
			return domain.ActionEnvelope{}, err
		}
		key = digest
	}
	id, err := domain.NewID("act")
	if err != nil {
		return domain.ActionEnvelope{}, err
	}
	return domain.ActionEnvelope{
		ID: id, TenantID: session.TenantID, ActorID: session.ActorID, DeviceID: session.DeviceID,
		SessionID: session.ID, Agent: activeProfile.Agent, AdapterRelease: activeProfile.AdapterRelease,
		Tool: input.ToolName, Operation: operation, Resource: resource,
		Destination: domain.Destination{Provider: provider, AccountRef: activeProfile.Scope.AccountRef, Environment: activeProfile.Scope.Environments[0], Location: location},
		Parameters:  map[string]any{"hook_tool_use_id": key, "command": redactCommand(command)}, RequestedAt: now.UTC(),
	}, nil
}

func CorrelationKey(input Input) string {
	if input.ToolUseID != "" {
		return input.ToolUseID
	}
	command := commandFrom(input)
	digest, _ := domain.Digest(struct{ Tool, Command string }{input.ToolName, command})
	return digest
}

func commandFrom(input Input) string {
	for _, key := range []string{"command", "cmd", "script"} {
		if value, ok := input.ToolInput[key].(string); ok {
			return strings.TrimSpace(value)
		}
	}
	encoded, _ := json.Marshal(input.ToolInput)
	return string(encoded)
}

func classify(profile domain.SessionProfile, tool, command string) (provider, operation, resource, location string) {
	provider = profile.Scope.Provider
	resource = provider + "://" + profile.Scope.AccountRef
	if len(profile.Scope.ResourcePrefixes) > 0 {
		resource = profile.Scope.ResourcePrefixes[0]
	}
	fields := strings.Fields(command)
	if len(fields) >= 3 && fields[0] == "aws" {
		provider = "aws"
		operation = "aws." + fields[1] + "." + camel(fields[2])
		if arn := arnPattern.FindString(command); arn != "" {
			resource = strings.TrimRight(arn, ",;")
		}
		location = flagValue(fields, "--region")
		return
	}
	if len(fields) >= 2 && (fields[0] == "kubectl" || strings.HasSuffix(fields[0], "/kubectl")) {
		provider = "kubernetes"
		verb := camel(fields[1])
		operation = "kubernetes." + verb
		namespace := flagValue(fields, "--namespace")
		if namespace == "" {
			namespace = flagValue(fields, "-n")
		}
		if namespace == "" {
			namespace = "default"
		}
		kind, name := "resource", "*"
		if len(fields) > 2 {
			kind = fields[2]
		}
		if len(fields) > 3 && !strings.HasPrefix(fields[3], "-") {
			name = fields[3]
		}
		resource = "k8s://" + profile.Scope.AccountRef + "/" + namespace + "/" + kind + "/" + name
		location = namespace
		return
	}
	if operation == "" {
		operation = "shell.Execute"
	}
	if strings.TrimSpace(tool) != "" && !strings.EqualFold(tool, "bash") {
		operation = "tool." + camel(tool)
	}
	return
}

func camel(value string) string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '-' || r == '_' || r == ':' })
	for index := range parts {
		if parts[index] == "" {
			continue
		}
		parts[index] = strings.ToUpper(parts[index][:1]) + parts[index][1:]
	}
	return strings.Join(parts, "")
}

func flagValue(fields []string, flag string) string {
	for index, value := range fields {
		if value == flag && index+1 < len(fields) {
			return fields[index+1]
		}
		if strings.HasPrefix(value, flag+"=") {
			return strings.TrimPrefix(value, flag+"=")
		}
	}
	return ""
}

func redactCommand(command string) string {
	fields := strings.Fields(command)
	for index, field := range fields {
		lower := strings.ToLower(field)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "password") || strings.Contains(lower, "key=") {
			if strings.Contains(field, "=") {
				fields[index] = strings.SplitN(field, "=", 2)[0] + "=[REDACTED]"
			} else if index+1 < len(fields) {
				fields[index+1] = "[REDACTED]"
			}
		}
	}
	return strings.Join(fields, " ")
}

func DecisionJSON(event string, decision string, reason string) ([]byte, error) {
	if event == "" {
		event = "PreToolUse"
	}
	return json.Marshal(map[string]any{"hookSpecificOutput": map[string]string{
		"hookEventName": event, "permissionDecision": decision, "permissionDecisionReason": reason,
	}})
}
