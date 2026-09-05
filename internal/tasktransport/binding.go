// Package tasktransport describes the runtime-owned task channel. Allowing a
// call on this channel never authorizes its requested provider action.
package tasktransport

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
)

var Tools = []string{"task_context", "propose_action", "list_actions", "execute_action"}

type Binding struct {
	SessionID        string `json:"session_id"`
	ProfileDigest    string `json:"profile_digest"`
	ServerName       string `json:"server_name"`
	Executable       string `json:"executable"`
	ExecutableDigest string `json:"executable_digest"`
}

func (b Binding) Validate(sessionID, profileDigest string) error {
	if sessionID == "" || profileDigest == "" || b.SessionID != sessionID || b.ProfileDigest != profileDigest || !strings.HasPrefix(b.ServerName, "misconfig_") ||
		len(b.ServerName) < 20 || len(b.ServerName) > 64 || strings.IndexFunc(b.ServerName, func(r rune) bool {
		return r != '_' && (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) != -1 {
		return errors.New("task transport does not match the active session")
	}
	digest, err := ExecutableDigest(b.Executable)
	if err != nil || digest != b.ExecutableDigest {
		return errors.New("task transport executable changed or is unavailable")
	}
	return nil
}

func (b Binding) NativeTool(name string) (string, bool) {
	for _, tool := range Tools {
		if name == "mcp__"+b.ServerName+"__"+tool {
			return tool, true
		}
	}
	return "", false
}

func ExecutableDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("task transport executable is not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
