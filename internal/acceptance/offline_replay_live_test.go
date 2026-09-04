package acceptance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/enforcement"
	"github.com/misconfig-cloud/agent-runtime/internal/hook"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
	"github.com/misconfig-cloud/agent-runtime/internal/spool"
)

func TestLiveOfflineRestartAndExactlyOnceReplay(t *testing.T) {
	baseURL := strings.TrimSpace(os.Getenv("MISCONFIG_RA32_CONTROL_URL"))
	enrollmentToken := strings.TrimSpace(os.Getenv("MISCONFIG_RA32_ENROLLMENT_TOKEN"))
	if baseURL == "" || enrollmentToken == "" {
		t.Skip("MISCONFIG_RA32_CONTROL_URL and MISCONFIG_RA32_ENROLLMENT_TOKEN are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	suffix := randomHex(t, 8)
	tenantID := "tenant-ra32-" + suffix
	client := controlclient.Client{BaseURL: baseURL, TenantID: tenantID}
	enrollment, err := client.Enroll(ctx, enrollmentToken, tenantID, "RA-32 offline replay acceptance", "founder-ra32", "ra32-device")
	if err != nil {
		t.Fatal(err)
	}
	client.Token = enrollment.DeviceToken
	workspace := t.TempDir()
	profile, _, err := client.CreateProfile(ctx, controlclient.CreateProfileRequest{
		Name: "RA-32 AWS read", Agent: string(domain.AgentCodex), Workspace: workspace,
		Scope:       domain.Scope{Provider: "aws", AccountRef: "730335354084", Environments: []string{"staging"}},
		Enforcement: domain.EnforcementHook, CredentialMode: domain.CredentialAttach,
		AdapterRelease: "codex@ra32", PolicyTTLSeconds: 3600,
		Rules: []policy.Rule{{
			ID: "allow-sts-identity", Effect: policy.EffectAllow, Providers: []string{"aws"},
			Operations: []string{"aws.sts.GetCallerIdentity"}, Reason: "read-only identity proof is allowed in the RA-32 scope",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.StartSession(ctx, profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		_ = client.Stop(stopCtx, session.ID, "RA-32 acceptance completed")
	})

	root := filepath.Join(t.TempDir(), "state")
	store := localstate.Store{Root: root, FileTokens: true}
	if err := store.SaveConfig(localstate.Config{
		ControlURL: baseURL, TenantID: tenantID, ActorID: session.ActorID,
		DeviceID: session.DeviceID, DeviceName: "ra32-device",
		PolicyKeyID: enrollment.PolicyKeyID, PolicyPublicKey: enrollment.PolicyPublicKey,
	}); err != nil {
		t.Fatal(err)
	}
	activePath, err := store.SaveActive(localstate.ActiveSession{Profile: profile, Session: session})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := client.Policy(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := decodePublicKey(enrollment.PolicyPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := (policy.Cache{Path: store.PolicyPath(session.ID), PublicKey: publicKey}).Store(signed); err != nil {
		t.Fatal(err)
	}

	secretFixture := "RA32_NEVER_STORE_" + randomHex(t, 12)
	input := hook.Input{
		SessionID: "native-ra32", HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "tool-ra32-1",
		ToolInput: map[string]any{"command": "aws sts get-caller-identity --session-token " + secretFixture},
	}
	firstEngine := enforcement.Engine{Store: store, Now: func() time.Time { return time.Now().UTC() }}
	result, err := firstEngine.Pre(ctx, activePath, input)
	if err != nil || result.Decision.Effect != policy.EffectAllow {
		t.Fatalf("fresh cached read policy did not work offline: %#v %v", result.Decision, err)
	}
	mutation, err := firstEngine.Pre(ctx, activePath, hook.Input{
		SessionID: "native-ra32", HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "tool-ra32-mutation",
		ToolInput: map[string]any{"command": "aws ec2 terminate-instances --instance-ids i-ra32fixture"},
	})
	if err != nil || mutation.Decision.Effect != policy.EffectDeny {
		t.Fatalf("offline mutation did not fail closed: %#v %v", mutation.Decision, err)
	}
	assertTreeDoesNotContain(t, root, secretFixture)

	// Reconstruct the engine, then lose the response after the server commits.
	// The receipt must remain pending locally and a later process must replay it
	// without creating a second logical action.
	crashControl := &crashAfterCommitControl{Client: client}
	restarted := enforcement.Engine{Store: localstate.Store{Root: root, FileTokens: true}, Control: crashControl}
	if err := restarted.Replay(ctx); err == nil {
		t.Fatal("failure injection did not interrupt replay after server commit")
	}
	pending, err := (spool.Store{Root: store.ReceiptRoot()}).Pending()
	if err != nil || len(pending) != 2 {
		t.Fatalf("receipt did not survive the interrupted upload: %#v %v", pending, err)
	}
	durableReceipts := append([]spool.Receipt(nil), pending...)
	finalEngine := enforcement.Engine{Store: localstate.Store{Root: root, FileTokens: true}, Control: client}
	if err := finalEngine.Replay(ctx); err != nil {
		t.Fatal(err)
	}
	if err := finalEngine.Replay(ctx); err != nil {
		t.Fatal(err)
	}
	pending, err = (spool.Store{Root: store.ReceiptRoot()}).Pending()
	if err != nil || len(pending) != 0 {
		t.Fatalf("successful replay left pending receipts: %#v %v", pending, err)
	}

	detail := fetchSessionDetail(t, ctx, client, session.ID)
	sentIDs := receiptIDsFromSent(t, store.ReceiptRoot())
	if len(detail.Receipts) != 2 || !sameReceiptIDs(detail.Receipts, sentIDs) {
		t.Fatalf("server did not retain each logical receipt exactly once: %#v", detail.Receipts)
	}
	if detail.Session.ToolCalls != 2 {
		t.Fatalf("replay double-counted the logical action: %d", detail.Session.ToolCalls)
	}

	otherTenant := "tenant-ra32-isolation-" + suffix
	other := controlclient.Client{BaseURL: baseURL, TenantID: otherTenant}
	otherEnrollment, err := other.Enroll(ctx, enrollmentToken, otherTenant, "RA-32 tenant isolation", "other-actor", "other-device")
	if err != nil {
		t.Fatal(err)
	}
	other.Token = otherEnrollment.DeviceToken
	foreign := durableReceipts[0]
	foreign.Action.TenantID = tenantID
	foreign.TenantID = tenantID
	foreignClient := controlclient.Client{BaseURL: baseURL, TenantID: tenantID, Token: other.Token}
	if err := foreignClient.PutReceipt(ctx, foreign); err == nil {
		t.Fatal("a device from another tenant injected a receipt")
	}
	assertTreeDoesNotContain(t, root, secretFixture)
	t.Logf("RA-32 tenant=%s session=%s receipts=%s,%s", tenantID, session.ID, durableReceipts[0].ID, durableReceipts[1].ID)
}

type crashAfterCommitControl struct {
	controlclient.Client
	crashed bool
}

func (c *crashAfterCommitControl) PutReceipt(ctx context.Context, receipt spool.Receipt) error {
	if err := c.Client.PutReceipt(ctx, receipt); err != nil {
		return err
	}
	if !c.crashed {
		c.crashed = true
		return errors.New("injected lost response after commit")
	}
	return nil
}

type liveSessionDetail struct {
	Session struct {
		ToolCalls int64 `json:"tool_calls"`
	} `json:"session"`
	Receipts []struct {
		ID        string `json:"id"`
		TenantID  string `json:"tenant_id"`
		SessionID string `json:"session_id"`
		ActionID  string `json:"action_id"`
	} `json:"receipts"`
}

func fetchSessionDetail(t *testing.T, ctx context.Context, client controlclient.Client, sessionID string) liveSessionDetail {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(client.BaseURL, "/")+"/v1/sessions/"+sessionID, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+client.Token)
	request.Header.Set("X-Misconfig-Tenant", client.TenantID)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		t.Fatalf("session detail returned %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	var detail liveSessionDetail
	if err := json.NewDecoder(response.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	return detail
}

func receiptIDsFromSent(t *testing.T, receiptRoot string) map[string]struct{} {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(receiptRoot, "sent"))
	if err != nil || len(entries) != 2 {
		t.Fatalf("expected two sent receipts: %#v %v", entries, err)
	}
	ids := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		encoded, err := os.ReadFile(filepath.Join(receiptRoot, "sent", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var receipt spool.Receipt
		if err := json.Unmarshal(encoded, &receipt); err != nil {
			t.Fatal(err)
		}
		ids[receipt.ID] = struct{}{}
	}
	return ids
}

func sameReceiptIDs(receipts []struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	SessionID string `json:"session_id"`
	ActionID  string `json:"action_id"`
}, expected map[string]struct{}) bool {
	if len(receipts) != len(expected) {
		return false
	}
	for _, receipt := range receipts {
		if _, ok := expected[receipt.ID]; !ok {
			return false
		}
	}
	return true
}

func assertTreeDoesNotContain(t *testing.T, root, secret string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(encoded), secret) {
			return errors.New("secret fixture persisted at " + path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func randomHex(t *testing.T, bytesCount int) string {
	t.Helper()
	value := make([]byte, bytesCount)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value)
}

func decodePublicKey(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("invalid policy public key length")
	}
	return ed25519.PublicKey(decoded), nil
}
