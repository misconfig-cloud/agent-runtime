package controlclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
)

func (c Client) Job(ctx context.Context, id string) (domain.JobDefinition, error) {
	var d domain.JobDefinition
	if err := c.request(ctx, http.MethodGet, "/v1/jobs/"+url.PathEscape(id), c.Token, c.TenantID, nil, &d); err != nil {
		return d, fmt.Errorf("load reviewed job (compatible server required): %w", err)
	}
	if d.Document.ID != id {
		return domain.JobDefinition{}, errors.New("job identity does not match request")
	}
	if err := d.Validate(c.TenantID); err != nil {
		return domain.JobDefinition{}, err
	}
	return d, nil
}
func (c Client) JobProgress(ctx context.Context, id string) ([]domain.JobProgress, error) {
	var response struct {
		Steps []domain.JobProgress `json:"steps"`
	}
	err := c.request(ctx, http.MethodGet, "/v1/jobs/"+url.PathEscape(id)+"/progress", c.Token, c.TenantID, nil, &response)
	return response.Steps, err
}
func (c Client) StartJobSession(ctx context.Context, profile domain.SessionProfile, selected domain.JobSelection) (domain.AgentSession, error) {
	step, err := selected.Step(c.TenantID)
	if err != nil {
		return domain.AgentSession{}, err
	}
	current, err := c.Job(ctx, selected.Definition.Document.ID)
	if err != nil {
		return domain.AgentSession{}, err
	}
	if current.Digest != selected.Definition.Digest {
		return domain.AgentSession{}, errors.New("reviewed job changed before launch")
	}
	definition, err := c.profileDefinition(ctx, profile.ID)
	if err != nil {
		return domain.AgentSession{}, err
	}
	digest, err := domain.Digest(profile)
	if err != nil {
		return domain.AgentSession{}, err
	}
	remoteDigest, err := domain.Digest(definition.Profile)
	if err != nil {
		return domain.AgentSession{}, err
	}
	policyDigest, err := domain.Digest(definition.Policy)
	if err != nil {
		return domain.AgentSession{}, err
	}
	if profile.TenantID != c.TenantID || profile.CredentialMode != domain.CredentialAction || profile.Enforcement != domain.EnforcementTyped || profile.ID != step.ProfileID || digest != step.ProfileDigest || remoteDigest != digest || definition.ProfileDigest != digest || policyDigest != step.PolicyDigest || definition.Policy.Bundle.Release != step.PolicyRelease {
		return domain.AgentSession{}, errors.New("job task or signed policy changed; review the step again")
	}
	// Never retry without the job object. An older server must reject it.
	request := map[string]any{"profile_id": profile.ID, "profile_digest": digest, "agent": profile.Agent, "job": selected.Binding()}
	var active domain.AgentSession
	if err := c.request(ctx, http.MethodPost, "/v1/sessions", c.Token, c.TenantID, request, &active); err != nil {
		return domain.AgentSession{}, err
	}
	return active, nil
}
func (c Client) CompleteJobStep(ctx context.Context, b domain.JobBinding) (domain.JobProgress, error) {
	var result domain.JobProgress
	err := c.request(ctx, http.MethodPost, "/v1/jobs/"+url.PathEscape(b.JobID)+"/steps/"+url.PathEscape(b.StepKey)+"/complete", c.Token, c.TenantID, map[string]string{"job_digest": b.JobDigest}, &result)
	return result, err
}
