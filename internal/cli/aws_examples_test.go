package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/misconfig-cloud/agent-runtime/internal/policy"
)

func TestPublishedAWSExamplesUseAccountBoundSessionScope(t *testing.T) {
	t.Parallel()

	const want = "aws://123456789012"
	for _, name := range []string{"aws-read-only-rules.json", "aws-read-with-subagent-rules.json"} {
		encoded, err := os.ReadFile(filepath.Join("..", "..", "examples", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var rules []policy.Rule
		if err := json.Unmarshal(encoded, &rules); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		if len(rules) == 0 {
			t.Fatalf("%s has no rules", name)
		}
		for _, rule := range rules {
			if len(rule.ResourcePrefixes) != 1 || rule.ResourcePrefixes[0] != want {
				t.Fatalf("%s rule %s scope = %v, want [%s]", name, rule.ID, rule.ResourcePrefixes, want)
			}
		}
	}

	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "--resource-prefix "+want) || strings.Contains(string(readme), "--resource-prefix arn:aws:") {
		t.Fatal("README must publish the account-bound AWS session scope")
	}
}
