package tasktransport

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBindingRejectsSubstitutionAndChangedExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime")
	if err := os.WriteFile(path, []byte("original test executable"), 0700); err != nil {
		t.Fatal(err)
	}
	digest, err := ExecutableDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{SessionID: "session-a", ProfileDigest: "profile-digest", ServerName: "misconfig_12345678901234567890", Executable: path, ExecutableDigest: digest}
	if err := b.Validate(b.SessionID, b.ProfileDigest); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"session-b", b.ProfileDigest}, {b.SessionID, "changed-profile"}, {"", ""}} {
		if b.Validate(pair[0], pair[1]) == nil {
			t.Fatal("substitution accepted")
		}
	}
	for _, suffix := range []string{".other", "\"", "=", "[", "\n", "é"} {
		bad := b
		bad.ServerName += suffix
		if bad.Validate(b.SessionID, b.ProfileDigest) == nil {
			t.Fatalf("unsafe config name accepted: %q", bad.ServerName)
		}
	}
	if err := os.WriteFile(path, []byte("replacement"), 0700); err != nil {
		t.Fatal(err)
	}
	if b.Validate(b.SessionID, b.ProfileDigest) == nil {
		t.Fatal("replaced executable accepted")
	}
	b.Executable = filepath.Dir(path)
	if b.Validate(b.SessionID, b.ProfileDigest) == nil {
		t.Fatal("directory accepted as executable")
	}
}

func TestNativeToolNamesAreExactAndNeverIncludeApproval(t *testing.T) {
	b := Binding{ServerName: "misconfig_12345678901234567890"}
	for _, tool := range Tools {
		if got, ok := b.NativeTool("mcp__" + b.ServerName + "__" + tool); !ok || got != tool {
			t.Fatalf("missing tool %s", tool)
		}
	}
	for _, name := range []string{"execute_action", "mcp__other__execute_action", "mcp__" + b.ServerName + "__approve_action", "mcp__" + b.ServerName + "__execute_action_extra"} {
		if _, ok := b.NativeTool(name); ok {
			t.Fatalf("foreign tool accepted: %s", name)
		}
	}
}
