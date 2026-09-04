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
	OutcomeBlocked   Outcome = "blocked"
	OutcomeApproved  Outcome = "approved"
	OutcomeSucceeded Outcome = "succeeded"
	OutcomeFailed    Outcome = "failed"
)

type Receipt struct {
	ID              string          `json:"id"`
	TenantID        string          `json:"tenant_id"`
	SessionID       string          `json:"session_id"`
	ActionID        string          `json:"action_id"`
	ActionDigest    string          `json:"action_digest"`
	Decision        policy.Decision `json:"decision"`
	Outcome         Outcome         `json:"outcome"`
	ProviderReceipt string          `json:"provider_receipt,omitempty"`
	RecordedAt      time.Time       `json:"recorded_at"`
}

func NewReceipt(action domain.ActionEnvelope, decision policy.Decision, outcome Outcome, providerReceipt string, recordedAt time.Time) (Receipt, error) {
	if err := action.Validate(); err != nil {
		return Receipt{}, err
	}
	if recordedAt.IsZero() {
		return Receipt{}, errors.New("recorded_at is required")
	}
	switch outcome {
	case OutcomeBlocked, OutcomeApproved, OutcomeSucceeded, OutcomeFailed:
	default:
		return Receipt{}, fmt.Errorf("invalid receipt outcome %q", outcome)
	}
	actionDigest, err := domain.Digest(action)
	if err != nil {
		return Receipt{}, err
	}
	identity := struct {
		TenantID     string          `json:"tenant_id"`
		SessionID    string          `json:"session_id"`
		ActionDigest string          `json:"action_digest"`
		Decision     policy.Decision `json:"decision"`
		Outcome      Outcome         `json:"outcome"`
	}{action.TenantID, action.SessionID, actionDigest, decision, outcome}
	id, err := domain.Digest(identity)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{
		ID: id, TenantID: action.TenantID, SessionID: action.SessionID,
		ActionID: action.ID, ActionDigest: actionDigest, Decision: decision,
		Outcome: outcome, ProviderReceipt: providerReceipt, RecordedAt: recordedAt.UTC(),
	}, nil
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
		if string(existing) != string(encoded) {
			return errors.New("receipt identity collision")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read existing receipt: %w", err)
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return fmt.Errorf("write receipt: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("commit receipt: %w", err)
	}
	return nil
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
		return fmt.Errorf("mark receipt sent: %w", err)
	}
	return nil
}

func filename(id string) string {
	replacer := strings.NewReplacer(":", "_", "/", "_", "\\", "_")
	return replacer.Replace(id) + ".json"
}
