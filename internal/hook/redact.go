package hook

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
)

var (
	sensitiveKey    = regexp.MustCompile(`(?i)(authorization|cookie|credential|password|passwd|secret|token|api[-_]?key|private[-_]?key|client[-_]?secret)`)
	privateKeyBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	jwtValue        = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\b`)
	knownTokenValue = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:gh[opsu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b`)
)

func RedactedToolInput(input Input) map[string]any {
	redacted, _ := redactValue("", input.ToolInput).(map[string]any)
	if redacted == nil {
		return map[string]any{}
	}
	return redacted
}

func RedactedInputDigest(toolName string, input map[string]any) (string, error) {
	encoded, err := json.Marshal(struct {
		ToolName  string         `json:"tool_name"`
		ToolInput map[string]any `json:"tool_input"`
	}{toolName, input})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func redactValue(key string, value any) any {
	if sensitiveKey.MatchString(key) {
		return "[REDACTED]"
	}
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for childKey, child := range typed {
			result[childKey] = redactValue(childKey, child)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = redactValue(key, child)
		}
		return result
	case string:
		return redactString(typed)
	default:
		return value
	}
}

func redactString(value string) string {
	value = privateKeyBlock.ReplaceAllString(value, "[REDACTED PRIVATE KEY]")
	value = jwtValue.ReplaceAllString(value, "[REDACTED TOKEN]")
	value = knownTokenValue.ReplaceAllString(value, "[REDACTED CREDENTIAL]")
	fields := strings.Fields(value)
	for index, field := range fields {
		name, _, assigned := strings.Cut(field, "=")
		if assigned && sensitiveKey.MatchString(strings.TrimLeft(name, "-$")) {
			fields[index] = name + "=[REDACTED]"
			continue
		}
		if sensitiveKey.MatchString(strings.TrimLeft(field, "-$")) && index+1 < len(fields) {
			fields[index+1] = "[REDACTED]"
		}
	}
	value = strings.Join(fields, " ")
	if len(value) > 32*1024 {
		sum := sha256.Sum256([]byte(value))
		value = value[:16*1024] + " [TRUNCATED sha256:" + hex.EncodeToString(sum[:]) + "]"
	}
	return value
}
