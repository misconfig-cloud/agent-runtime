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

func TestReadRetriesTransientTransportFailureWithinCallerBoundary(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
		writeTestJSON(t, w, http.StatusOK, map[string]any{"sessions": []any{}})
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client := Client{BaseURL: server.URL, HTTP: &http.Client{Timeout: 50 * time.Millisecond}}
	if _, err := client.Sessions(ctx); err != nil {
		t.Fatalf("transient read was not recovered: %v", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("read requests = %d, want 2", requests.Load())
	}
}

func TestReadRetriesOnlyTransientHTTPResponses(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusUnauthorized} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				request := requests.Add(1)
				if request == 1 {
					w.WriteHeader(status)
					return
				}
				writeTestJSON(t, w, http.StatusOK, map[string]any{"sessions": []any{}})
			}))
			defer server.Close()

			_, err := (Client{BaseURL: server.URL}).Sessions(context.Background())
			if status == http.StatusServiceUnavailable && err != nil {
				t.Fatalf("retryable response was not recovered: %v", err)
			}
			if status == http.StatusUnauthorized && err == nil {
				t.Fatal("authorization failure was retried into success")
			}
			want := int64(2)
			if status == http.StatusUnauthorized {
				want = 1
			}
			if requests.Load() != want {
				t.Fatalf("requests = %d, want %d", requests.Load(), want)
			}
		})
	}
}

func TestWriteTransportFailureIsNeverRetried(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, HTTP: &http.Client{Timeout: 40 * time.Millisecond}}
	_, err := client.CreateTypedAction(context.Background(), CreateTypedActionRequest{})
	if err == nil || requests.Load() != 1 {
		t.Fatalf("write failure changed retry boundary: err=%v requests=%d", err, requests.Load())
	}
}

func TestReadRetryHonorsCallerCancellation(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	client := Client{BaseURL: server.URL, HTTP: &http.Client{Timeout: time.Second}}
	_, err := client.Sessions(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || requests.Load() != 1 {
		t.Fatalf("caller deadline changed: err=%v requests=%d", err, requests.Load())
	}
}
