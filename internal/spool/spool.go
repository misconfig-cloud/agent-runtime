package spool

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
)

type Outcome string

const (
	OutcomeBlocked            Outcome = "blocked"
	OutcomeWaitingForApproval Outcome = "waiting_for_approval"
	OutcomeApproved           Outcome = "approved"
	OutcomeSucceeded          Outcome = "succeeded"
	OutcomeFailed             Outcome = "failed"
)

type Receipt struct {
	ID                string                `json:"id"`
	TenantID          string                `json:"tenant_id"`
	SessionID         string                `json:"session_id"`
	ActionID          string                `json:"action_id"`
	ActionDigest      string                `json:"action_digest"`
	Action            domain.ActionEnvelope `json:"action"`
	Decision          policy.Decision       `json:"decision"`
	Outcome           Outcome               `json:"outcome"`
	ProviderReceipt   string                `json:"provider_receipt,omitempty"`
	VerificationState VerificationState     `json:"verification_state"`
	RecordedAt        time.Time             `json:"recorded_at"`
}

type VerificationState string

const (
	VerificationNotRequested VerificationState = "not_requested"
	VerificationObserved     VerificationState = "observed"
)

func NewReceipt(action domain.ActionEnvelope, decision policy.Decision, outcome Outcome, providerReceipt string, recordedAt time.Time) (Receipt, error) {
	if err := action.Validate(); err != nil {
		return Receipt{}, err
	}
	if recordedAt.IsZero() {
		return Receipt{}, errors.New("recorded_at is required")
	}
	switch outcome {
	case OutcomeBlocked, OutcomeWaitingForApproval, OutcomeApproved, OutcomeSucceeded, OutcomeFailed:
	default:
		return Receipt{}, fmt.Errorf("invalid receipt outcome %q", outcome)
	}
	actionDigest, err := domain.Digest(action)
	if err != nil {
		return Receipt{}, err
	}
	identity := struct {
		TenantID          string            `json:"tenant_id"`
		SessionID         string            `json:"session_id"`
		ActionDigest      string            `json:"action_digest"`
		Decision          policy.Decision   `json:"decision"`
		Outcome           Outcome           `json:"outcome"`
		VerificationState VerificationState `json:"verification_state"`
	}{action.TenantID, action.SessionID, actionDigest, decision, outcome, verificationForOutcome(outcome)}
	id, err := domain.Digest(identity)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{
		ID: id, TenantID: action.TenantID, SessionID: action.SessionID,
		ActionID: action.ID, ActionDigest: actionDigest, Action: action, Decision: decision,
		Outcome: outcome, ProviderReceipt: providerReceipt, VerificationState: verificationForOutcome(outcome),
		RecordedAt: recordedAt.UTC().Truncate(time.Microsecond),
	}, nil
}

func verificationForOutcome(outcome Outcome) VerificationState {
	switch outcome {
	case OutcomeSucceeded, OutcomeFailed:
		return VerificationObserved
	default:
		return VerificationNotRequested
	}
}

type Store struct {
	Root string
}

func (s Store) Put(receipt Receipt) error {
	if strings.TrimSpace(receipt.ID) == "" || strings.TrimSpace(receipt.TenantID) == "" || strings.TrimSpace(receipt.SessionID) == "" {
		return errors.New("receipt identity is required")
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("encode receipt: %w", err)
	}
	directory := filepath.Join(s.Root, "pending")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create receipt spool: %w", err)
	}
	path := filepath.Join(directory, filename(receipt.ID))
	if existing, err := os.ReadFile(path); err == nil {
		if !sameReceipt(existing, encoded) {
			return errors.New("receipt identity collision")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read existing receipt: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".receipt-*.tmp")
	if err != nil {
		return fmt.Errorf("create receipt temp file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect receipt: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write receipt: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync receipt: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close receipt: %w", err)
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := os.ReadFile(path)
			if readErr == nil && sameReceipt(existing, encoded) {
				return nil
			}
			if readErr == nil {
				return errors.New("receipt identity collision")
			}
		}
		return fmt.Errorf("commit receipt: %w", err)
	}
	return syncDirectory(directory)
}

func (s Store) Pending() ([]Receipt, error) {
	directory := filepath.Join(s.Root, "pending")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return []Receipt{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read receipt spool: %w", err)
	}
	receipts := make([]Receipt, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		encoded, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read pending receipt: %w", err)
		}
		var receipt Receipt
		if err := json.Unmarshal(encoded, &receipt); err != nil {
			return nil, fmt.Errorf("decode pending receipt: %w", err)
		}
		receipts = append(receipts, receipt)
	}
	sort.Slice(receipts, func(i, j int) bool {
		if receipts[i].RecordedAt.Equal(receipts[j].RecordedAt) {
			return receipts[i].ID < receipts[j].ID
		}
		return receipts[i].RecordedAt.Before(receipts[j].RecordedAt)
	})
	return receipts, nil
}

func (s Store) MarkSent(id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("receipt id is required")
	}
	if err := os.MkdirAll(filepath.Join(s.Root, "sent"), 0o700); err != nil {
		return fmt.Errorf("create sent receipt directory: %w", err)
	}
	from := filepath.Join(s.Root, "pending", filename(id))
	to := filepath.Join(s.Root, "sent", filename(id))
	if _, err := os.Stat(to); err == nil {
		return nil
	}
	if err := os.Rename(from, to); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, sentErr := os.Stat(to); sentErr == nil {
				return nil
			}
		}
		return fmt.Errorf("mark receipt sent: %w", err)
	}
	if err := syncDirectory(filepath.Dir(from)); err != nil {
		return fmt.Errorf("sync pending receipt directory: %w", err)
	}
	if err := syncDirectory(filepath.Dir(to)); err != nil {
		return fmt.Errorf("sync sent receipt directory: %w", err)
	}
	return nil
}

func sameReceipt(left, right []byte) bool {
	var a, b Receipt
	if json.Unmarshal(left, &a) != nil || json.Unmarshal(right, &b) != nil {
		return false
	}
	a.RecordedAt = time.Time{}
	b.RecordedAt = time.Time{}
	encodedA, _ := json.Marshal(a)
	encodedB, _ := json.Marshal(b)
	return string(encodedA) == string(encodedB)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func filename(id string) string {
	replacer := strings.NewReplacer(":", "_", "/", "_", "\\", "_")
	return replacer.Replace(id) + ".json"
}
