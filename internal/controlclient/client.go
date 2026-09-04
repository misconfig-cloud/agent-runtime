package controlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
	"github.com/misconfig-cloud/agent-runtime/internal/spool"
)

type Client struct {
	BaseURL  string
	TenantID string
	Token    string
	HTTP     *http.Client
}

type Enrollment struct {
	Device struct {
		ID       string `json:"id"`
		TenantID string `json:"tenant_id"`
		ActorID  string `json:"actor_id"`
		Name     string `json:"name"`
	} `json:"device"`
	DeviceToken     string `json:"device_token"`
	PolicyKeyID     string `json:"policy_key_id"`
	PolicyPublicKey string `json:"policy_public_key"`
}

type CreateProfileRequest struct {
	Name             string                  `json:"name"`
	Agent            string                  `json:"agent"`
	Workspace        string                  `json:"workspace"`
	Scope            domain.Scope            `json:"scope"`
	Enforcement      domain.EnforcementLevel `json:"enforcement"`
	CredentialMode   domain.CredentialMode   `json:"credential_mode"`
	AdapterRelease   string                  `json:"adapter_release"`
	Rules            []policy.Rule           `json:"rules"`
	PolicyTTLSeconds int64                   `json:"policy_ttl_seconds"`
}

func (c Client) Enroll(ctx context.Context, enrollmentToken, tenantID, tenantName, actorID, deviceName string) (Enrollment, error) {
	body := map[string]string{"tenant_id": tenantID, "tenant_name": tenantName, "actor_id": actorID, "device_name": deviceName}
	var response Enrollment
	err := c.request(ctx, http.MethodPost, "/v1/devices/enroll", enrollmentToken, "", body, &response)
	return response, err
}

func (c Client) CreateProfile(ctx context.Context, request CreateProfileRequest) (domain.SessionProfile, string, error) {
	var response struct {
		Profile       domain.SessionProfile `json:"profile"`
		ProfileDigest string                `json:"profile_digest"`
	}
	err := c.request(ctx, http.MethodPost, "/v1/session-profiles", c.Token, c.TenantID, request, &response)
	return response.Profile, response.ProfileDigest, err
}

func (c Client) Profiles(ctx context.Context) ([]domain.SessionProfile, error) {
	var response struct {
		Profiles []domain.SessionProfile `json:"profiles"`
	}
	err := c.request(ctx, http.MethodGet, "/v1/session-profiles", c.Token, c.TenantID, nil, &response)
	return response.Profiles, err
}

func (c Client) StartSession(ctx context.Context, profile domain.SessionProfile) (domain.AgentSession, error) {
	digest, err := domain.Digest(profile)
	if err != nil {
		return domain.AgentSession{}, err
	}
	request := map[string]string{"profile_id": profile.ID, "profile_digest": digest, "agent": string(profile.Agent)}
	var response domain.AgentSession
	err = c.request(ctx, http.MethodPost, "/v1/sessions", c.Token, c.TenantID, request, &response)
	return response, err
}

func (c Client) Session(ctx context.Context, sessionID string) (domain.AgentSession, error) {
	var response struct {
		Session domain.AgentSession `json:"session"`
	}
	err := c.request(ctx, http.MethodGet, "/v1/sessions/"+url.PathEscape(sessionID), c.Token, c.TenantID, nil, &response)
	return response.Session, err
}

func (c Client) Sessions(ctx context.Context) ([]domain.AgentSession, error) {
	var response struct {
		Sessions []domain.AgentSession `json:"sessions"`
	}
	err := c.request(ctx, http.MethodGet, "/v1/sessions?limit=100", c.Token, c.TenantID, nil, &response)
	return response.Sessions, err
}

func (c Client) Policy(ctx context.Context, sessionID string) (policy.SignedBundle, error) {
	var response policy.SignedBundle
	err := c.request(ctx, http.MethodGet, "/v1/sessions/"+url.PathEscape(sessionID)+"/policy", c.Token, c.TenantID, nil, &response)
	return response, err
}

func (c Client) Stop(ctx context.Context, sessionID, reason string) error {
	return c.request(ctx, http.MethodPost, "/v1/sessions/"+url.PathEscape(sessionID)+"/stop", c.Token, c.TenantID, map[string]string{"reason": reason}, nil)
}

func (c Client) PutReceipt(ctx context.Context, receipt spool.Receipt) error {
	outcome := string(receipt.Outcome)
	action := receipt.Action
	if err := action.Validate(); err != nil {
		return fmt.Errorf("receipt action is invalid: %w", err)
	}
	request := map[string]any{
		"id": receipt.ID, "tenant_id": receipt.TenantID, "session_id": receipt.SessionID,
		"action_id": receipt.ActionID, "action_digest": receipt.ActionDigest,
		"decision": string(receipt.Decision.Effect), "rule_id": receipt.Decision.RuleID,
		"policy_release": receipt.Decision.PolicyRelease, "outcome": outcome,
		"tool": action.Tool, "operation": action.Operation, "resource": action.Resource,
		"provider": action.Destination.Provider, "account_ref": action.Destination.AccountRef,
		"environment": action.Destination.Environment, "location": action.Destination.Location,
		"provider_receipt": receipt.ProviderReceipt, "recorded_at": receipt.RecordedAt,
	}
	return c.request(ctx, http.MethodPost, "/v1/receipts", c.Token, c.TenantID, request, nil)
}

func (c Client) request(ctx context.Context, method, path, token, tenant string, input, output any) error {
	base, err := url.Parse(strings.TrimRight(c.BaseURL, "/"))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return errors.New("control URL must be absolute HTTP(S)")
	}
	reference, err := url.Parse(path)
	if err != nil {
		return err
	}
	endpoint := base.ResolveReference(reference)
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if tenant != "" {
		request.Header.Set("X-Misconfig-Tenant", tenant)
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var problem struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &problem)
		if problem.Error == "" {
			problem.Error = strings.TrimSpace(string(data))
		}
		return fmt.Errorf("control plane returned %d: %s", response.StatusCode, problem.Error)
	}
	if output != nil && len(data) > 0 {
		if err := json.Unmarshal(data, output); err != nil {
			return fmt.Errorf("decode control response: %w", err)
		}
	}
	return nil
}
