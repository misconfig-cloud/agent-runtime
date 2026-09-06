package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestJobDefinitionValidation(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, mode := range []string{"valid", "tamper", "foreign", "duplicate", "cycle", "missing dependency", "duplicate dependency", "duplicate result", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			d := JobDefinition{Document: JobDocument{Schema: "misconfig.job-definition/v1", ID: "job", TenantID: "tenant", Name: "Job", Request: "Request", SourceState: "customer_supplied", CreatedAt: time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC), Steps: []JobStep{{Key: "first", Name: "Step", ProfileID: "profile", ProfileDigest: digest, PolicyRelease: "policy", PolicyDigest: digest, ExpectedActionDigests: []string{digest}}}}}
			s := &d.Document.Steps[0]
			switch mode {
			case "foreign":
				d.Document.TenantID = "other"
			case "duplicate":
				d.Document.Steps = append(d.Document.Steps, *s)
			case "cycle":
				s.DependsOn = []string{"first"}
			case "missing dependency":
				s.DependsOn = []string{"missing"}
			case "duplicate dependency":
				s.DependsOn = []string{"second", "second"}
				second := *s
				second.Key = "second"
				second.DependsOn = nil
				d.Document.Steps = append(d.Document.Steps, second)
			case "duplicate result":
				s.ExpectedActionDigests = append(s.ExpectedActionDigests, digest)
			case "legacy":
				s.ExpectedActionDigests = nil
			}
			d.Digest, _ = Digest(d.Document)
			if mode == "tamper" {
				d.Document.Request = "Changed"
			}
			err := d.Validate("tenant")
			if (err == nil) != (mode == "valid" || mode == "legacy") {
				t.Fatalf("validation: %v", err)
			}
			if mode == "legacy" {
				if _, err := (JobSelection{Definition: d, StepKey: "first"}).Step("tenant"); err == nil {
					t.Fatal("metadata-only plan became executable")
				}
			}
		})
	}
}

func TestJobStepWireOrderPreservesServerEmbeddedStepContract(t *testing.T) {
	// The server embeds StepInput before policy fields. Order is part of its
	// retained document digest, including omission of empty legacy fields.
	s := JobStep{Key: "change", Name: "Change", ProfileID: "p", ProfileDigest: "d", DependsOn: []string{"read"}, ExpectedActionDigests: []string{"a"}, PolicyRelease: "r", PolicyDigest: "s"}
	b, err := json.Marshal(s)
	want := `{"key":"change","name":"Change","profile_id":"p","profile_digest":"d","depends_on":["read"],"expected_action_digests":["a"],"policy_release":"r","policy_digest":"s"}`
	if err != nil || string(b) != want {
		t.Fatalf("wire contract changed: %s %v", b, err)
	}
	s.DependsOn = nil
	s.ExpectedActionDigests = nil
	b, _ = json.Marshal(s)
	if strings.Contains(string(b), "expected_action") || strings.Contains(string(b), "depends_on") {
		t.Fatal("legacy digest changed")
	}
}
