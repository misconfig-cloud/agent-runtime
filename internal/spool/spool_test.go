package spool

import (
	"testing"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
)

func TestReceiptSpoolIsIdempotentAndDurable(t *testing.T) {
	now := time.Now().UTC()
	action := domain.ActionEnvelope{
		ID: "action-1", TenantID: "tenant-1", ActorID: "actor-1", DeviceID: "device-1",
		SessionID: "session-1", Agent: domain.AgentCodex, AdapterRelease: "codex@1.0.0",
		Tool: "kubectl", Operation: "DeletePod", Resource: "k8s://cluster/production/pod/api-1",
		Destination: domain.Destination{Provider: "kubernetes", AccountRef: "cluster-1", Environment: "production"},
		RequestedAt: now,
	}
	decision := policy.Decision{Effect: policy.EffectDeny, RuleID: "deny-delete", Reason: "production deletion requires approval", PolicyRelease: "policy@1.0.0"}
	receipt, err := NewReceipt(action, decision, OutcomeBlocked, "", now)
	if err != nil {
		t.Fatal(err)
	}
	store := Store{Root: t.TempDir()}
	if err := store.Put(receipt); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(receipt); err != nil {
		t.Fatalf("idempotent put failed: %v", err)
	}
	pending, err := store.Pending()
	if err != nil || len(pending) != 1 || pending[0].ID != receipt.ID {
		t.Fatalf("unexpected pending receipts: %#v %v", pending, err)
	}
	if err := store.MarkSent(receipt.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkSent(receipt.ID); err != nil {
		t.Fatalf("idempotent mark sent failed: %v", err)
	}
	pending, err = store.Pending()
	if err != nil || len(pending) != 0 {
		t.Fatalf("expected empty pending spool: %#v %v", pending, err)
	}
}
