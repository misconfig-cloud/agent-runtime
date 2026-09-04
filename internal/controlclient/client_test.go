package controlclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
)

func TestStartSessionRefusesLegacyDigestDriftBeforeLaunch(t *testing.T) {
	profile := testProfile()
	signedShape := profile
	signedShape.CreatedAt = signedShape.CreatedAt.Add(789 * time.Nanosecond)
	legacyDigest, err := domain.Digest(signedShape)
	if err != nil {
		t.Fatal(err)
	}
	var starts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/session-profiles/"+profile.ID:
			writeTestJSON(t, w, http.StatusOK, map[string]any{"profile": profile, "profile_digest": legacyDigest})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sessions":
			starts.Add(1)
			writeTestJSON(t, w, http.StatusCreated, domain.AgentSession{ID: "should-not-start"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err = (Client{BaseURL: server.URL, TenantID: "tenant-a", Token: "device-token"}).StartSession(context.Background(), profile)
	var migration *ProfileSuccessorRequiredError
	if !errors.As(err, &migration) {
		t.Fatalf("legacy profile did not return a typed migration error: %T %v", err, err)
	}
	if migration.ProfileID != profile.ID || migration.ProfileDigest != legacyDigest || !strings.HasSuffix(migration.SuccessorPath, "/"+profile.ID+"/successors") {
		t.Fatalf("migration error is not actionable: %#v", migration)
	}
	if starts.Load() != 0 {
		t.Fatal("legacy profile reached session creation before migration")
	}
}

func TestStartSessionUsesTheStoredImmutableDigest(t *testing.T) {
	profile := testProfile()
	digest, err := domain.Digest(profile)
	if err != nil {
		t.Fatal(err)
	}
	var received struct {
		ProfileID     string `json:"profile_id"`
		ProfileDigest string `json:"profile_digest"`
		Agent         string `json:"agent"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			writeTestJSON(t, w, http.StatusOK, map[string]any{"profile": profile, "profile_digest": digest})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sessions":
			if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
				t.Fatal(err)
			}
			writeTestJSON(t, w, http.StatusCreated, domain.AgentSession{ID: "session-a", ProfileID: profile.ID, ProfileDigest: digest})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	started, err := (Client{BaseURL: server.URL, TenantID: "tenant-a", Token: "device-token"}).StartSession(context.Background(), profile)
	if err != nil {
		t.Fatal(err)
	}
	if started.ID != "session-a" || received.ProfileID != profile.ID || received.ProfileDigest != digest || received.Agent != "codex" {
		t.Fatalf("session was not bound to the stored definition: %#v %#v", started, received)
	}
}

func TestStartSessionPreservesServerSuccessorMetadata(t *testing.T) {
	profile := testProfile()
	digest, err := domain.Digest(profile)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeTestJSON(t, w, http.StatusOK, map[string]any{"profile": profile, "profile_digest": digest})
			return
		}
		writeTestJSON(t, w, http.StatusConflict, map[string]any{
			"error": "profile_successor_required", "profile_id": profile.ID, "profile_digest": "sha256:legacy",
			"successor": map[string]string{"method": http.MethodPost, "path": "/v1/session-profiles/" + profile.ID + "/successors"},
		})
	}))
	defer server.Close()

	_, err = (Client{BaseURL: server.URL, TenantID: "tenant-a", Token: "device-token"}).StartSession(context.Background(), profile)
	var migration *ProfileSuccessorRequiredError
	if !errors.As(err, &migration) || migration.ProfileDigest != "sha256:legacy" || migration.SuccessorPath == "" {
		t.Fatalf("server migration metadata was lost: %T %#v", err, migration)
	}
}

func TestCreateProfileSuccessorUsesTheExplicitMigrationEndpoint(t *testing.T) {
	var received CreateProfileSuccessorRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.EscapedPath() != "/v1/session-profiles/profile%2Flegacy/successors" {
			t.Fatalf("unexpected migration request: %s %s", r.Method, r.URL.EscapedPath())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer device-token" {
			t.Fatalf("authorization = %q", got)
		}
		if got := r.Header.Get("X-Misconfig-Tenant"); got != "tenant-a" {
			t.Fatalf("tenant = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		writeTestJSON(t, w, http.StatusCreated, map[string]any{
			"profile": domain.SessionProfile{ID: "profile-new"}, "profile_digest": "sha256:new",
			"predecessor": map[string]string{"profile_id": "profile/legacy", "profile_digest": "sha256:old"},
		})
	}))
	defer server.Close()

	successor, err := (Client{BaseURL: server.URL, TenantID: "tenant-a", Token: "device-token"}).CreateProfileSuccessor(
		context.Background(), "profile/legacy", CreateProfileSuccessorRequest{AdapterRelease: "codex@2.0.0", PolicyTTLSeconds: 300},
	)
	if err != nil {
		t.Fatal(err)
	}
	if received.AdapterRelease != "codex@2.0.0" || received.PolicyTTLSeconds != 300 {
		t.Fatalf("migration request = %#v", received)
	}
	if successor.Profile.ID != "profile-new" || successor.Predecessor.ProfileID != "profile/legacy" || successor.Predecessor.ProfileDigest != "sha256:old" {
		t.Fatalf("migration response = %#v", successor)
	}
}

func testProfile() domain.SessionProfile {
	return domain.SessionProfile{
		ID: "profile-a", TenantID: "tenant-a", Name: "Production", Agent: domain.AgentCodex,
		Workspace: "/work/acme", Scope: domain.Scope{Provider: "aws", AccountRef: "123456789012", Environments: []string{"production"}},
		Enforcement: domain.EnforcementHook, CredentialMode: domain.CredentialAttach,
		AdapterRelease: "codex@2.0.0", PolicyRelease: "policy-a",
		CreatedAt: time.Date(2026, 9, 4, 18, 0, 0, 123456000, time.UTC),
	}
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, status int, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(err)
	}
}
