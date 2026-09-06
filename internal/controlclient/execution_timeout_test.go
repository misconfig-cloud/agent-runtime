package controlclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestExecutionWaitsBeyondReadTimeoutWithoutRepeatingWrite(t *testing.T) {
	var posts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		timer := time.NewTimer(8500 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}
		writeTestJSON(t, w, 200, TypedAction{ID: "action-a", State: "verified"})
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	action, err := (Client{BaseURL: server.URL}).ExecuteTypedAction(ctx, "action-a")
	if err != nil || action.State != "verified" || posts.Load() != 1 {
		t.Fatalf("premature timeout or replay: %v, posts=%d", err, posts.Load())
	}
}

func TestExecutionHonorsCallerDeadlineAndNeverRetries(t *testing.T) {
	var posts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { posts.Add(1); <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := (Client{BaseURL: server.URL}).ExecuteTypedAction(ctx, "action-a")
	if !errors.Is(err, context.DeadlineExceeded) || posts.Load() != 1 {
		t.Fatalf("deadline or single-write boundary lost: %v posts=%d", err, posts.Load())
	}
}
