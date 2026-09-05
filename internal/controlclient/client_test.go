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
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
	"github.com/misconfig-cloud/agent-runtime/internal/spool"
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

func TestPutReceiptProjectsSafeNativeActionIdentity(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	action := domain.ActionEnvelope{
		ID: "action-a", TenantID: "tenant-a", ActorID: "actor-a", DeviceID: "device-a", SessionID: "session-a",
		Agent: domain.AgentCodex, AdapterRelease: "codex@0.152.0", Tool: "shell", Operation: "aws.sts.GetCallerIdentity",
		Resource: "aws://123456789012", Destination: domain.Destination{Provider: "aws", AccountRef: "123456789012", Environment: "production"},
		Native:      domain.NativeActionIdentity{SessionID: "native-a", TurnID: "turn-a", ToolUseID: "call-a", AgentID: "agent-a", AgentType: "worker", Model: "gpt-5.6-codex", PermissionMode: "full-access", PathClass: "subagent"},
		RequestedAt: now,
	}
	receipt, err := spool.NewReceipt(action, policy.Decision{Effect: policy.EffectAllow, RuleID: "read", PolicyRelease: "policy-a"}, spool.OutcomeApproved, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := (Client{BaseURL: server.URL, TenantID: "tenant-a", Token: "device-token"}).PutReceipt(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"native_session_id": "native-a", "native_turn_id": "turn-a", "native_tool_use_id": "call-a",
		"native_agent_id": "agent-a", "native_agent_type": "worker", "native_model": "gpt-5.6-codex",
		"native_permission_mode": "full-access", "native_path_class": "subagent",
	} {
		if received[key] != want {
			t.Fatalf("%s = %#v, want %q", key, received[key], want)
		}
	}
	for _, forbidden := range []string{"transcript_path", "cwd", "tool_response"} {
		if _, ok := received[forbidden]; ok {
			t.Fatalf("private field %q crossed the control boundary", forbidden)
		}
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

func TestBrowserDeviceAuthorizationUsesPublicOneTimeExchange(t *testing.T) {
	var polls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Misconfig-Tenant") != "" {
			t.Fatalf("browser authorization must not claim tenant identity before approval: %#v", r.Header)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/device-authorizations":
			var request map[string]string
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request["device_name"] != "engineering-laptop" {
				t.Fatalf("device name = %q", request["device_name"])
			}
			writeTestJSON(t, w, http.StatusCreated, DeviceAuthorizationStart{
				DeviceCode: "opaque-device-code", UserCode: "ABCD-EFGH-JKLM",
				VerificationURI:         "https://console.example/device",
				VerificationURIComplete: "https://console.example/device?user_code=ABCD-EFGH-JKLM",
				ExpiresIn:               600, Interval: 3,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/device-authorizations/token":
			var request map[string]string
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request["device_code"] != "opaque-device-code" {
				t.Fatalf("device code = %q", request["device_code"])
			}
			if polls.Add(1) == 1 {
				writeTestJSON(t, w, http.StatusAccepted, DeviceAuthorizationExchange{State: "pending"})
				return
			}
			var authorized DeviceAuthorizationExchange
			authorized.State = "authorized"
			authorized.Enrollment.Device.ID = "device-a"
			authorized.Enrollment.Device.TenantID = "tenant-a"
			authorized.Enrollment.Device.ActorID = "actor-a"
			authorized.Enrollment.Device.Name = "engineering-laptop"
			authorized.Enrollment.DeviceToken = "issued-once"
			authorized.Enrollment.PolicyKeyID = "key-a"
			authorized.Enrollment.PolicyPublicKey = "public-key"
			writeTestJSON(t, w, http.StatusOK, authorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, TenantID: "must-not-be-sent", Token: "must-not-be-sent"}
	started, err := client.CreateDeviceAuthorization(context.Background(), "engineering-laptop")
	if err != nil {
		t.Fatal(err)
	}
	if started.UserCode != "ABCD-EFGH-JKLM" || started.DeviceCode != "opaque-device-code" || started.ExpiresIn != 600 {
		t.Fatalf("start response changed: %#v", started)
	}
	pending, err := client.ExchangeDeviceAuthorization(context.Background(), started.DeviceCode)
	if err != nil || pending.State != "pending" {
		t.Fatalf("pending exchange = %#v err=%v", pending, err)
	}
	authorized, err := client.ExchangeDeviceAuthorization(context.Background(), started.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if authorized.State != "authorized" || authorized.Enrollment.Device.TenantID != "tenant-a" || authorized.Enrollment.DeviceToken != "issued-once" {
		t.Fatalf("authorized exchange changed identity: %#v", authorized)
	}
}

func TestCredentialConnectionLifecycleUsesTenantBoundEndpoints(t *testing.T) {
	now := time.Date(2026, 9, 5, 8, 0, 0, 0, time.UTC)
	var created CreateCredentialConnectionRequest
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.EscapedPath())
		if r.Header.Get("Authorization") != "Bearer device-token" || r.Header.Get("X-Misconfig-Tenant") != "tenant-a" {
			t.Fatalf("credential request lost device or tenant identity: %#v", r.Header)
		}
		connection := CredentialConnection{
			ID: "connection-a", TenantID: "tenant-a", Provider: "orbital-fabric",
			AccountRef: "station-9", ProviderRelease: "orbital.session@1.0.0",
			Name: "Station", State: "pending", CreatedAt: now,
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/credential-providers":
			writeTestJSON(t, w, http.StatusOK, map[string]any{"providers": []CredentialProvider{{Release: connection.ProviderRelease, Provider: connection.Provider, CredentialKind: "orbital.exec-token.v9"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/credential-connections":
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Fatal(err)
			}
			writeTestJSON(t, w, http.StatusCreated, PreparedCredentialConnection{Connection: connection, Onboarding: json.RawMessage(`{"instruction":"configure station"}`)})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/credential-connections":
			writeTestJSON(t, w, http.StatusOK, map[string]any{"connections": []CredentialConnection{connection}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/credential-connections/connection-a/verify":
			connection.State = "verified"
			writeTestJSON(t, w, http.StatusOK, connection)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/credential-connections/connection-a":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, TenantID: "tenant-a", Token: "device-token"}
	providers, err := client.CredentialProviders(context.Background())
	if err != nil || len(providers) != 1 || providers[0].Provider != "orbital-fabric" {
		t.Fatalf("providers = %#v err=%v", providers, err)
	}
	request := CreateCredentialConnectionRequest{
		Provider: "orbital-fabric", ProviderRelease: "orbital.session@1.0.0",
		AccountRef: "station-9", Name: "Station", Input: json.RawMessage(`{"audience":"edge"}`),
	}
	prepared, err := client.CreateCredentialConnection(context.Background(), request)
	if err != nil || prepared.Connection.ID != "connection-a" || string(prepared.Onboarding) == "" {
		t.Fatalf("prepared = %#v err=%v", prepared, err)
	}
	if created.Provider != request.Provider || created.ProviderRelease != request.ProviderRelease || string(created.Input) != string(request.Input) {
		t.Fatalf("create request changed: %#v", created)
	}
	connections, err := client.CredentialConnections(context.Background())
	if err != nil || len(connections) != 1 || connections[0].ID != "connection-a" {
		t.Fatalf("connections = %#v err=%v", connections, err)
	}
	verified, err := client.VerifyCredentialConnection(context.Background(), "connection-a")
	if err != nil || verified.State != "verified" {
		t.Fatalf("verified = %#v err=%v", verified, err)
	}
	if err := client.RevokeCredentialConnection(context.Background(), "connection-a"); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 5 {
		t.Fatalf("unexpected credential lifecycle requests: %#v", paths)
	}
}

func TestTypedActionLifecycleUsesProviderNeutralTenantBoundEndpoints(t *testing.T) {
	now := time.Date(2026, 9, 5, 9, 30, 0, 0, time.UTC)
	var proposed CreateTypedActionRequest
	var requests []string
	action := TypedAction{
		ID: "action/orbital", TenantID: "tenant-a", SessionID: "session-edge", Provider: "orbital-fabric",
		AccountRef: "station-9", Environment: "production", CapabilityRef: "orbital.vector-shift@1",
		Operation: "ShiftVector", Resource: "orbital://station-9/vector/red", Parameters: json.RawMessage(`{"bearing":17}`),
		State: "pending_approval", CreatedAt: now,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer device-token" || r.Header.Get("X-Misconfig-Tenant") != "tenant-a" {
			t.Fatalf("typed action request lost device or tenant identity: %#v", r.Header)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/actions":
			if err := json.NewDecoder(r.Body).Decode(&proposed); err != nil {
				t.Fatal(err)
			}
			writeTestJSON(t, w, http.StatusCreated, action)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/actions":
			if r.URL.Query().Get("session_id") != "session-edge" || r.URL.Query().Get("limit") != "100" {
				t.Fatalf("action list query = %s", r.URL.RawQuery)
			}
			writeTestJSON(t, w, http.StatusOK, map[string]any{"actions": []TypedAction{action}})
		case r.Method == http.MethodPost && r.URL.EscapedPath() == "/v1/actions/action%2Forbital/execute":
			action.State = "verified"
			writeTestJSON(t, w, http.StatusOK, action)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, TenantID: "tenant-a", Token: "device-token"}
	request := CreateTypedActionRequest{
		SessionID: "session-edge", CapabilityRef: action.CapabilityRef, Operation: action.Operation,
		Resource: action.Resource, Environment: action.Environment, Parameters: action.Parameters,
	}
	created, err := client.CreateTypedAction(context.Background(), request)
	if err != nil || created.ID != action.ID || proposed.CapabilityRef != action.CapabilityRef {
		t.Fatalf("create action = %#v request=%#v err=%v", created, proposed, err)
	}
	listed, err := client.TypedActions(context.Background(), "session-edge")
	if err != nil || len(listed) != 1 || listed[0].Provider != "orbital-fabric" {
		t.Fatalf("list actions = %#v err=%v", listed, err)
	}
	executed, err := client.ExecuteTypedAction(context.Background(), action.ID)
	if err != nil || executed.State != "verified" {
		t.Fatalf("execute action = %#v err=%v", executed, err)
	}
	if len(requests) != 3 {
		t.Fatalf("unexpected typed action requests: %#v", requests)
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
