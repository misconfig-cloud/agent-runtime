package localstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
)

type Config struct {
	ControlURL      string `json:"control_url"`
	TenantID        string `json:"tenant_id"`
	ActorID         string `json:"actor_id"`
	DeviceID        string `json:"device_id"`
	DeviceName      string `json:"device_name"`
	PolicyKeyID     string `json:"policy_key_id"`
	PolicyPublicKey string `json:"policy_public_key"`
}

type ActiveSession struct {
	Profile domain.SessionProfile `json:"profile"`
	Session domain.AgentSession   `json:"session"`
}

type PendingAction struct {
	Action      domain.ActionEnvelope `json:"action"`
	Decision    policy.Decision       `json:"decision"`
	InputDigest string                `json:"input_digest"`
}

type Store struct {
	Root       string
	FileTokens bool
}

func DefaultRoot() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("MISCONFIG_HOME")); configured != "" {
		absolute, err := filepath.Abs(configured)
		if err != nil {
			return "", fmt.Errorf("resolve MISCONFIG_HOME: %w", err)
		}
		return filepath.Clean(absolute), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".misconfig"), nil
}

func (s Store) SaveConfig(config Config) error {
	if strings.TrimSpace(config.ControlURL) == "" || strings.TrimSpace(config.TenantID) == "" || strings.TrimSpace(config.DeviceID) == "" {
		return errors.New("control URL, tenant and device are required")
	}
	return writeJSON(filepath.Join(s.Root, "config.json"), config)
}

func (s Store) LoadConfig() (Config, error) {
	var config Config
	if err := readJSON(filepath.Join(s.Root, "config.json"), &config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (s Store) SaveActive(active ActiveSession) (string, error) {
	path := filepath.Join(s.Root, "sessions", active.Session.ID+".json")
	return path, writeJSON(path, active)
}

func LoadActive(path string) (ActiveSession, error) {
	var active ActiveSession
	if err := readJSON(path, &active); err != nil {
		return ActiveSession{}, err
	}
	return active, nil
}

func (s Store) SaveAction(sessionID, key string, action PendingAction) error {
	return writeJSON(filepath.Join(s.Root, "actions", sessionID, safe(key)+".json"), action)
}

// LoadOrSaveAction gives a native hook retry the exact action identity and
// timestamp created by its first invocation. The filesystem link is the
// commit point, so concurrent duplicate hooks cannot replace one another.
func (s Store) LoadOrSaveAction(sessionID, key string, candidate PendingAction) (PendingAction, error) {
	path := filepath.Join(s.Root, "actions", safe(sessionID), safe(key)+".json")
	encoded, err := json.MarshalIndent(candidate, "", "  ")
	if err != nil {
		return PendingAction{}, err
	}
	encoded = append(encoded, '\n')
	if err := writeOnce(path, encoded); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return PendingAction{}, err
		}
		var existing PendingAction
		if err := readJSON(path, &existing); err != nil {
			return PendingAction{}, err
		}
		if existing.InputDigest == "" || existing.InputDigest != candidate.InputDigest {
			return PendingAction{}, errors.New("native action correlation identity collision")
		}
		return existing, nil
	}
	return candidate, nil
}

func (s Store) MarkStopped(sessionID string) error {
	return writeSecret(filepath.Join(s.Root, "stops", safe(sessionID)), "stopped\n")
}

func (s Store) IsStopped(sessionID string) bool {
	_, err := os.Stat(filepath.Join(s.Root, "stops", safe(sessionID)))
	return err == nil
}

func (s Store) LoadAction(sessionID, key string) (PendingAction, error) {
	var action PendingAction
	err := readJSON(filepath.Join(s.Root, "actions", sessionID, safe(key)+".json"), &action)
	return action, err
}

func (s Store) DeleteAction(sessionID, key string) error {
	err := os.Remove(filepath.Join(s.Root, "actions", sessionID, safe(key)+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s Store) PutDeviceToken(deviceID, token string) error {
	if runtime.GOOS == "darwin" && !s.FileTokens {
		command := exec.Command("security", "add-generic-password", "-U", "-s", "misconfig.cloud.agent-runtime", "-a", deviceID, "-w", token)
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("store device token in Keychain: %s: %w", strings.TrimSpace(string(output)), err)
		}
		return nil
	}
	return writeSecret(filepath.Join(s.Root, "secrets", safe(deviceID)), token)
}

func (s Store) DeviceToken(deviceID string) (string, error) {
	if runtime.GOOS == "darwin" && !s.FileTokens {
		output, err := exec.Command("security", "find-generic-password", "-s", "misconfig.cloud.agent-runtime", "-a", deviceID, "-w").Output()
		if err != nil {
			return "", fmt.Errorf("read device token from Keychain: %w", err)
		}
		return strings.TrimSpace(string(output)), nil
	}
	value, err := os.ReadFile(filepath.Join(s.Root, "secrets", safe(deviceID)))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(value)), nil
}

func (s Store) DeleteDeviceToken(deviceID string) error {
	if runtime.GOOS == "darwin" && !s.FileTokens {
		command := exec.Command("security", "delete-generic-password", "-s", "misconfig.cloud.agent-runtime", "-a", deviceID)
		if err := command.Run(); err != nil {
			return fmt.Errorf("delete device token from Keychain: %w", err)
		}
		return nil
	}
	err := os.Remove(filepath.Join(s.Root, "secrets", safe(deviceID)))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s Store) Remove() error { return os.RemoveAll(s.Root) }

func (s Store) SaveRuntimeConfig(sessionID, name string, value any) (string, error) {
	path := filepath.Join(s.Root, "runtime", safe(sessionID), safe(name))
	return path, writeJSON(path, value)
}

func (s Store) PolicyPath(sessionID string) string {
	return filepath.Join(s.Root, "policies", safe(sessionID)+".json")
}

func (s Store) ReceiptRoot() string { return filepath.Join(s.Root, "receipts") }

func readJSON(path string, target any) error {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeSecret(path, string(encoded)+"\n")
}

func writeSecret(path, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".misconfig-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write([]byte(value)); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func writeOnce(path string, encoded []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".misconfig-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func safe(value string) string {
	return strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(value)
}
