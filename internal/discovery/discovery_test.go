package discovery

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestScanOnlyReadsLocalIdentityNames(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := "[default]\nregion=eu-central-1\n[profile production]\nrole_arn=arn:aws:iam::123:role/operator\n"
	if err := os.WriteFile(filepath.Join(home, ".aws", "config"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	credentials := "[production]\naws_access_key_id=must-not-be-returned\n[staging]\naws_access_key_id=also-secret\n"
	if err := os.WriteFile(filepath.Join(home, ".aws", "credentials"), []byte(credentials), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".kube"), 0o700); err != nil {
		t.Fatal(err)
	}
	kubeconfig := "apiVersion: v1\nclusters:\n- cluster:\n    server: https://must-not-be-returned\n  name: cluster-a\ncontexts:\n- context:\n    cluster: cluster-a\n    user: secret-user\n  name: production-eu\n- name: staging-us\n  context:\n    cluster: cluster-b\ncurrent-context: production-eu\nusers:\n- name: secret-user\n  user:\n    token: must-not-be-returned\n"
	if err := os.WriteFile(filepath.Join(home, ".kube", "config"), []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", "")
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
	if len(result.AWSProfiles) != 3 || result.AWSProfiles[0] != "default" || result.AWSProfiles[1] != "production" || result.AWSProfiles[2] != "staging" {
		t.Fatalf("unexpected profiles: %#v", result.AWSProfiles)
	}
	if len(result.KubeContexts) != 2 || result.KubeContexts[0] != "production-eu" || result.KubeContexts[1] != "staging-us" {
		t.Fatalf("unexpected kube contexts: %#v", result.KubeContexts)
	}
	encoded := fmt.Sprintf("%#v", result)
	for _, secret := range []string{"must-not-be-returned", "also-secret", "secret-user"} {
		if strings.Contains(encoded, secret) {
			t.Fatalf("discovery leaked local configuration value %q: %s", secret, encoded)
		}
	}
}

func TestScanMergesKubeconfigPathContexts(t *testing.T) {
	home := t.TempDir()
	first := filepath.Join(t.TempDir(), "first.yaml")
	second := filepath.Join(t.TempDir(), "second.yaml")
	if err := os.WriteFile(first, []byte("contexts:\n- name: shared\n  context: {}\n- name: alpha\n  context: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("contexts:\n- context: {}\n  name: shared\n- context: {}\n  name: beta\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", strings.Join([]string{first, second}, string(os.PathListSeparator)))
	result, err := Scan(home, func(string) (string, error) { return "", errors.New("not found") })
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha", "beta", "shared"}
	if !reflect.DeepEqual(result.KubeContexts, want) {
		t.Fatalf("unexpected kube contexts: got %#v want %#v", result.KubeContexts, want)
	}
}
