package semantics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativePatchEffects(t *testing.T) {
	root := workspace(t)
	if err := os.WriteFile(filepath.Join(root, "existing.txt"), []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "empty.txt"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("existing.txt", filepath.Join(root, "linked.txt")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, patch string
		want        Classification
	}{
		{"create", "*** Add File: new.txt\n+hello", Ordinary},
		{"edit", "*** Update File: existing.txt\n@@\n-old\n+new", Risky},
		{"delete-empty", "*** Delete File: empty.txt", Ordinary},
		{"multiple", "*** Add File: new.txt\n+hello\n*** Delete File: .env", Dangerous},
		{"escape", "*** Add File: ../outside.txt\n+hello", Dangerous},
		{"symlink", "*** Update File: linked.txt\n@@\n-old\n+new", Unknown},
		{"secret", "*** Add File: new.txt\n+ghp_" + strings.Repeat("x", 36), CredentialExposure},
		{"unknown-syntax", "*** Add File: new.txt\n+hello\n*** Run Script: evil", Unknown},
		{"repeat-target", "*** Delete File: empty.txt\n*** Add File: empty.txt\n+replacement", Unknown},
		{"move", "*** Update File: existing.txt\n*** Move to: moved.txt\n@@\n-old\n+new", Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := (Engine{}).AnalyzeTool(ToolRequest{Workspace: root, Name: "apply_patch", Input: map[string]any{"command": "*** Begin Patch\n" + tc.patch + "\n*** End Patch\n"}})
			if r.Classification != tc.want {
				t.Fatalf("got %+v want %s", r, tc.want)
			}
			if !r.Fresh() {
				t.Fatal("unchanged patch evidence stale")
			}
		})
	}
}

func TestNativePatchUnknownEnvelopeAndChangedTarget(t *testing.T) {
	root := workspace(t)
	for _, input := range []any{nil, "", "*** Begin Patch\n*** End Patch", "unframed text", strings.Repeat("x", 65537)} {
		r := (Engine{}).AnalyzeTool(ToolRequest{Workspace: root, Name: "apply_patch", Input: map[string]any{"command": input}})
		if r.Classification != Unknown || r.Complete {
			t.Fatalf("unrecognized patch trusted: %+v", r)
		}
	}
	r := (Engine{}).AnalyzeTool(ToolRequest{Workspace: root, Name: "apply_patch", Input: map[string]any{"command": "*** Begin Patch\n*** Add File: new.txt\n+hello\n*** End Patch"}})
	if err := os.WriteFile(filepath.Join(root, "new.txt"), []byte("now exists"), 0600); err != nil {
		t.Fatal(err)
	}
	if r.Fresh() {
		t.Fatal("newly existing target inherited earlier result")
	}
}
