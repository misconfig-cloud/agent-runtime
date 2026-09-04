package localstate

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
)

func TestDefaultRootHonorsMisconfigHome(t *testing.T) {
	t.Setenv("MISCONFIG_HOME", filepath.Join("relative", "runtime-state"))
	root, err := DefaultRoot()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(root) || filepath.Base(root) != "runtime-state" {
		t.Fatalf("MISCONFIG_HOME was not resolved safely: %q", root)
	}
}

func TestFileTokenModeUsesPrivateLocalState(t *testing.T) {
	root := t.TempDir()
	store := Store{Root: root, FileTokens: true}
	if err := store.PutDeviceToken("device/one", "super-secret"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "secrets", "device_one")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token permissions are %o", info.Mode().Perm())
	}
	if err := store.DeleteDeviceToken("device/one"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("token survived deletion: %v", err)
	}
}

func TestLoadOrSaveActionPreservesOneIdentityAcrossConcurrentHooks(t *testing.T) {
	store := Store{Root: t.TempDir()}
	const workers = 12
	results := make(chan PendingAction, workers)
	errorsByWorker := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			candidate := PendingAction{
				Action: domain.ActionEnvelope{
					ID: "action-" + string(rune('a'+index)), TenantID: "tenant-1", ActorID: "actor-1",
					DeviceID: "device-1", SessionID: "session-1", Agent: domain.AgentCodex,
					AdapterRelease: "codex@1", Tool: "Bash", Operation: "aws.sts.GetCallerIdentity",
					Resource: "aws://123456789012", Destination: domain.Destination{Provider: "aws", AccountRef: "123456789012", Environment: "production"},
					RequestedAt: time.Date(2026, 9, 4, 16, index, 0, 0, time.UTC),
				},
				Decision:    policy.Decision{Effect: policy.EffectAllow, RuleID: "allow-sts", PolicyRelease: "policy@1"},
				InputDigest: "sha256:same-native-input",
			}
			result, err := store.LoadOrSaveAction("session-1", "tool-use-1", candidate)
			if err != nil {
				errorsByWorker <- err
				return
			}
			results <- result
		}(index)
	}
	wait.Wait()
	close(results)
	close(errorsByWorker)
	for err := range errorsByWorker {
		t.Fatal(err)
	}
	identity := ""
	for result := range results {
		if identity == "" {
			identity = result.Action.ID
		}
		if result.Action.ID != identity {
			t.Fatalf("concurrent hooks observed different action identities: %q and %q", identity, result.Action.ID)
		}
	}
	if identity == "" {
		t.Fatal("no action identity was returned")
	}

	_, err := store.LoadOrSaveAction("session-1", "tool-use-1", PendingAction{InputDigest: "sha256:different-input"})
	if err == nil || err.Error() != "native action correlation identity collision" {
		t.Fatalf("changed input reused the native correlation key: %v", err)
	}
}
