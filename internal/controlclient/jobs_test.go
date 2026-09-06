package controlclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
)

func TestJobLaunchRequiresExactDefinitionAndNeverFallsBack(t *testing.T) {
	for _, mode := range []string{"valid", "job missing", "job tampered", "new job field", "policy changed", "profile changed", "start unsupported"} {
		t.Run(mode, func(t *testing.T) {
			profile := testProfile()
			profile.Enforcement = domain.EnforcementTyped
			profile.CredentialMode = domain.CredentialAction
			profile.ProviderBinding = &domain.ProviderBinding{ConnectionID: "connection-a", ProviderRelease: "custom@1"}
			pd, _ := domain.Digest(profile)
			signed := policy.SignedBundle{KeyID: "test", Bundle: policy.Bundle{Release: profile.PolicyRelease, TenantID: profile.TenantID, ProfileID: profile.ID}, Signature: "test"}
			sd, _ := domain.Digest(signed)
			d := domain.JobDefinition{Document: domain.JobDocument{Schema: "misconfig.job-definition/v1", ID: "job-a", TenantID: profile.TenantID, Name: "Reviewed job", Request: "Selected work", SourceState: "customer_supplied", CreatedAt: profile.CreatedAt, Steps: []domain.JobStep{{Key: "change", Name: "Change selected resource", ProfileID: profile.ID, ProfileDigest: pd, PolicyRelease: profile.PolicyRelease, PolicyDigest: sd, ExpectedActionDigests: []string{"sha256:" + strings.Repeat("a", 64)}}}}}
			d.Digest, _ = domain.Digest(d.Document)
			selected := domain.JobSelection{Definition: d, StepKey: "change"}
			var starts atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/jobs/job-a":
					if mode == "job missing" {
						http.NotFound(w, r)
						return
					}
					response := d
					if mode == "job tampered" {
						response.Document.Request = "changed"
					}
					if mode == "new job field" {
						b, _ := json.Marshal(d.Document)
						var doc map[string]any
						json.Unmarshal(b, &doc)
						doc["new_authority"] = "unsupported"
						digest, _ := domain.Digest(doc)
						writeTestJSON(t, w, 200, map[string]any{"document": doc, "digest": digest})
						return
					}
					writeTestJSON(t, w, 200, response)
				case "/v1/session-profiles/" + profile.ID:
					p, s := profile, signed
					if mode == "policy changed" {
						s.Signature = "changed"
					}
					if mode == "profile changed" {
						p.Name = "changed"
					}
					writeTestJSON(t, w, 200, map[string]any{"profile": p, "profile_digest": pd, "policy": s})
				case "/v1/sessions":
					starts.Add(1)
					var request struct {
						Job           domain.JobBinding `json:"job"`
						ProfileDigest string            `json:"profile_digest"`
					}
					if json.NewDecoder(r.Body).Decode(&request) != nil || request.Job != selected.Binding() || request.ProfileDigest != pd {
						t.Error("lost explicit job binding")
					}
					if mode == "start unsupported" {
						http.Error(w, "unsupported", 400)
						return
					}
					writeTestJSON(t, w, 201, domain.AgentSession{ID: "session-a"})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			_, err := (Client{BaseURL: server.URL, TenantID: profile.TenantID, Token: "test-token"}).StartJobSession(context.Background(), profile, selected)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("unexpected result: %v", err)
			}
			want := int64(0)
			if mode == "valid" || mode == "start unsupported" {
				want = 1
			}
			if starts.Load() != want {
				t.Fatalf("unexpected fallback or start: %d", starts.Load())
			}
		})
	}
}
