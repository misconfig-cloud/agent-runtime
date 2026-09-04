package localstate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
