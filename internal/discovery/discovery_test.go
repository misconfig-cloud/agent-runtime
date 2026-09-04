package discovery

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestScanOnlyReadsAWSProfileNames(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := "[default]\nregion=eu-central-1\n[profile production]\nrole_arn=arn:aws:iam::123:role/operator\n"
	if err := os.WriteFile(filepath.Join(home, ".aws", "config"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Scan(home, func(name string) (string, error) {
		if name == "codex" {
			return "/usr/local/bin/codex", nil
		}
		return "", errors.New("not found")
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Agents[0].Available || result.Agents[1].Available {
		t.Fatalf("unexpected agents: %#v", result.Agents)
	}
	if len(result.AWSProfiles) != 2 || result.AWSProfiles[0] != "default" || result.AWSProfiles[1] != "production" {
		t.Fatalf("unexpected profiles: %#v", result.AWSProfiles)
	}
}
