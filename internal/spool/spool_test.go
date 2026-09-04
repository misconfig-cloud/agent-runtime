package spool

import (
	"sync"
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
	if receipt.VerificationState != VerificationNotRequested {
		t.Fatalf("decision receipt claimed verification: %#v", receipt)
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

func TestConcurrentReceiptPutCommitsOneSemanticReceipt(t *testing.T) {
	now := time.Date(2026, 9, 4, 16, 30, 0, 0, time.UTC)
	action := domain.ActionEnvelope{
		ID: "action-concurrent", TenantID: "tenant-1", ActorID: "actor-1", DeviceID: "device-1",
		SessionID: "session-1", Agent: domain.AgentCodex, AdapterRelease: "codex@1",
		Tool: "Bash", Operation: "aws.sts.GetCallerIdentity", Resource: "aws://123456789012",
		Destination: domain.Destination{Provider: "aws", AccountRef: "123456789012", Environment: "production"},
		RequestedAt: now,
	}
	decision := policy.Decision{Effect: policy.EffectAllow, RuleID: "allow-sts", PolicyRelease: "policy@1"}
	store := Store{Root: t.TempDir()}
	const workers = 16
	var wait sync.WaitGroup
	errorsByWorker := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			receipt, err := NewReceipt(action, decision, OutcomeApproved, "", now.Add(time.Duration(index)*time.Millisecond))
			if err == nil {
				err = store.Put(receipt)
			}
			errorsByWorker <- err
		}(index)
	}
	wait.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		if err != nil {
			t.Fatal(err)
		}
	}
	pending, err := store.Pending()
	if err != nil || len(pending) != 1 {
		t.Fatalf("expected one durable receipt, got %#v: %v", pending, err)
	}

	collision := pending[0]
	collision.ProviderReceipt = "sha256:different-provider-result"
	if err := store.Put(collision); err == nil || err.Error() != "receipt identity collision" {
		t.Fatalf("semantic collision was accepted: %v", err)
	}
}
