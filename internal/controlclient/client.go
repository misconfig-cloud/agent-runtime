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

type DeviceAuthorizationStart struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type DeviceAuthorizationExchange struct {
	State      string     `json:"state"`
	Enrollment Enrollment `json:"enrollment"`
}

type CreateProfileRequest struct {
	Name              string                    `json:"name"`
	Agent             string                    `json:"agent"`
	Workspace         string                    `json:"workspace"`
	Scope             domain.Scope              `json:"scope"`
	Enforcement       domain.EnforcementLevel   `json:"enforcement"`
	CredentialMode    domain.CredentialMode     `json:"credential_mode"`
	CredentialBinding *domain.CredentialBinding `json:"credential_binding,omitempty"`
	AdapterRelease    string                    `json:"adapter_release"`
	Rules             []policy.Rule             `json:"rules"`
	PolicyTTLSeconds  int64                     `json:"policy_ttl_seconds"`
}

type CredentialProvider struct {
	Release             string `json:"release"`
	Provider            string `json:"provider"`
	CredentialKind      string `json:"credential_kind"`
	MaximumTTLSeconds   int64  `json:"maximum_ttl_seconds"`
	ConfigurationSchema string `json:"configuration_schema"`
	RevocationSemantics string `json:"revocation_semantics"`
}

type CredentialConnection struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	Provider        string     `json:"provider"`
	AccountRef      string     `json:"account_ref"`
	ProviderRelease string     `json:"provider_release"`
	Name            string     `json:"name"`
	State           string     `json:"state"`
	TargetIdentity  string     `json:"target_identity,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	VerifiedAt      *time.Time `json:"verified_at,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
}

type CreateCredentialConnectionRequest struct {
	Provider        string          `json:"provider"`
	ProviderRelease string          `json:"provider_release"`
	AccountRef      string          `json:"account_ref"`
	Name            string          `json:"name"`
	Input           json.RawMessage `json:"input"`
}

type PreparedCredentialConnection struct {
	Connection CredentialConnection `json:"connection"`
	Onboarding json.RawMessage      `json:"onboarding"`
}

type CredentialMaterial struct {
	Kind                string          `json:"kind"`
	Payload             json.RawMessage `json:"payload"`
	ExpiresAt           time.Time       `json:"expires_at"`
	TargetIdentity      string          `json:"target_identity"`
	RevocationSemantics string          `json:"revocation_semantics"`
}

type CreateProfileSuccessorRequest struct {
	AdapterRelease   string `json:"adapter_release"`
	PolicyTTLSeconds int64  `json:"policy_ttl_seconds"`
}

type ProfileSuccessor struct {
	Profile       domain.SessionProfile `json:"profile"`
	ProfileDigest string                `json:"profile_digest"`
	Predecessor   struct {
		ProfileID     string `json:"profile_id"`
		ProfileDigest string `json:"profile_digest"`
	} `json:"predecessor"`
}

type ProfileSuccessorRequiredError struct {
	ProfileID     string
	ProfileDigest string
	SuccessorPath string
}

func (e *ProfileSuccessorRequiredError) Error() string {
	return fmt.Sprintf("profile %s uses an older immutable contract; create a compatible successor with `misconfig profile migrate --profile %s`", e.ProfileID, e.ProfileID)
}

type APIError struct {
	StatusCode    int
	Code          string
	ProfileID     string
	ProfileDigest string
	SuccessorPath string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("control plane returned %d: %s", e.StatusCode, e.Code)
}

func (c Client) Enroll(ctx context.Context, enrollmentToken, tenantID, tenantName, actorID, deviceName string) (Enrollment, error) {
	body := map[string]string{"tenant_id": tenantID, "tenant_name": tenantName, "actor_id": actorID, "device_name": deviceName}
	var response Enrollment
	err := c.request(ctx, http.MethodPost, "/v1/devices/enroll", enrollmentToken, "", body, &response)
	return response, err
}

func (c Client) CreateDeviceAuthorization(ctx context.Context, deviceName string) (DeviceAuthorizationStart, error) {
	var response DeviceAuthorizationStart
	err := c.request(ctx, http.MethodPost, "/v1/device-authorizations", "", "", map[string]string{"device_name": deviceName}, &response)
	return response, err
}

func (c Client) ExchangeDeviceAuthorization(ctx context.Context, deviceCode string) (DeviceAuthorizationExchange, error) {
	var response DeviceAuthorizationExchange
	err := c.request(ctx, http.MethodPost, "/v1/device-authorizations/token", "", "", map[string]string{"device_code": deviceCode}, &response)
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

func (c Client) CredentialProviders(ctx context.Context) ([]CredentialProvider, error) {
	var response struct {
		Providers []CredentialProvider `json:"providers"`
	}
	err := c.request(ctx, http.MethodGet, "/v1/credential-providers", c.Token, c.TenantID, nil, &response)
	return response.Providers, err
}

func (c Client) CreateCredentialConnection(ctx context.Context, request CreateCredentialConnectionRequest) (PreparedCredentialConnection, error) {
	var response PreparedCredentialConnection
	err := c.request(ctx, http.MethodPost, "/v1/credential-connections", c.Token, c.TenantID, request, &response)
	return response, err
}

func (c Client) CredentialConnections(ctx context.Context) ([]CredentialConnection, error) {
	var response struct {
		Connections []CredentialConnection `json:"connections"`
	}
	err := c.request(ctx, http.MethodGet, "/v1/credential-connections", c.Token, c.TenantID, nil, &response)
	return response.Connections, err
}

func (c Client) VerifyCredentialConnection(ctx context.Context, connectionID string) (CredentialConnection, error) {
	var response CredentialConnection
	err := c.request(ctx, http.MethodPost, "/v1/credential-connections/"+url.PathEscape(connectionID)+"/verify", c.Token, c.TenantID, map[string]any{}, &response)
	return response, err
}

func (c Client) RevokeCredentialConnection(ctx context.Context, connectionID string) error {
	return c.request(ctx, http.MethodDelete, "/v1/credential-connections/"+url.PathEscape(connectionID), c.Token, c.TenantID, nil, nil)
}

func (c Client) CredentialLease(ctx context.Context, sessionID, requestID string) (CredentialMaterial, error) {
	var response CredentialMaterial
	err := c.request(ctx, http.MethodPost, "/v1/sessions/"+url.PathEscape(sessionID)+"/credential-leases", c.Token, c.TenantID, map[string]string{"request_id": requestID}, &response)
	return response, err
}

func (c Client) StartSession(ctx context.Context, profile domain.SessionProfile) (domain.AgentSession, error) {
	definition, err := c.profileDefinition(ctx, profile.ID)
	if err != nil {
		return domain.AgentSession{}, fmt.Errorf("load immutable profile definition: %w", err)
	}
	if definition.Profile.ID != profile.ID || definition.Profile.Agent != profile.Agent {
		return domain.AgentSession{}, errors.New("immutable profile definition does not match the selected profile")
	}
	digest, err := domain.Digest(definition.Profile)
	if err != nil {
		return domain.AgentSession{}, err
	}
	if digest != definition.ProfileDigest {
		return domain.AgentSession{}, &ProfileSuccessorRequiredError{
			ProfileID: profile.ID, ProfileDigest: definition.ProfileDigest,
			SuccessorPath: "/v1/session-profiles/" + url.PathEscape(profile.ID) + "/successors",
		}
	}
	request := map[string]string{"profile_id": profile.ID, "profile_digest": definition.ProfileDigest, "agent": string(profile.Agent)}
	var response domain.AgentSession
	err = c.request(ctx, http.MethodPost, "/v1/sessions", c.Token, c.TenantID, request, &response)
	var apiError *APIError
	if errors.As(err, &apiError) && apiError.Code == "profile_successor_required" {
		return domain.AgentSession{}, &ProfileSuccessorRequiredError{
			ProfileID: apiError.ProfileID, ProfileDigest: apiError.ProfileDigest, SuccessorPath: apiError.SuccessorPath,
		}
	}
	return response, err
}

func (c Client) CreateProfileSuccessor(ctx context.Context, profileID string, request CreateProfileSuccessorRequest) (ProfileSuccessor, error) {
	var response ProfileSuccessor
	err := c.request(ctx, http.MethodPost, "/v1/session-profiles/"+url.PathEscape(profileID)+"/successors", c.Token, c.TenantID, request, &response)
	return response, err
}

func (c Client) profileDefinition(ctx context.Context, profileID string) (struct {
	Profile       domain.SessionProfile `json:"profile"`
	ProfileDigest string                `json:"profile_digest"`
}, error) {
	var response struct {
		Profile       domain.SessionProfile `json:"profile"`
		ProfileDigest string                `json:"profile_digest"`
	}
	err := c.request(ctx, http.MethodGet, "/v1/session-profiles/"+url.PathEscape(profileID), c.Token, c.TenantID, nil, &response)
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
		"verification_state": receipt.VerificationState,
		"tool":               action.Tool, "operation": action.Operation, "resource": action.Resource,
		"provider": action.Destination.Provider, "account_ref": action.Destination.AccountRef,
		"environment": action.Destination.Environment, "location": action.Destination.Location,
		"native_session_id": action.Native.SessionID, "native_turn_id": action.Native.TurnID,
		"native_tool_use_id": action.Native.ToolUseID, "native_parent_tool_use_id": action.Native.ParentToolUseID,
		"native_agent_id": action.Native.AgentID, "native_agent_type": action.Native.AgentType,
		"native_model": action.Native.Model, "native_permission_mode": action.Native.PermissionMode,
		"native_path_class": action.Native.PathClass,
		"provider_receipt":  receipt.ProviderReceipt, "recorded_at": receipt.RecordedAt,
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
			Error         string `json:"error"`
			ProfileID     string `json:"profile_id"`
			ProfileDigest string `json:"profile_digest"`
			Successor     struct {
				Path string `json:"path"`
			} `json:"successor"`
		}
		_ = json.Unmarshal(data, &problem)
		if problem.Error == "" {
			problem.Error = strings.TrimSpace(string(data))
		}
		return &APIError{
			StatusCode: response.StatusCode, Code: problem.Error, ProfileID: problem.ProfileID,
			ProfileDigest: problem.ProfileDigest, SuccessorPath: problem.Successor.Path,
		}
	}
	if output != nil && len(data) > 0 {
		if err := json.Unmarshal(data, output); err != nil {
			return fmt.Errorf("decode control response: %w", err)
		}
	}
	return nil
}
