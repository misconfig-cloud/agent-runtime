package cli

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
)

// Job binding is checked before native launch and again at the action surface.
// It supplements server enforcement; local state is not a host sandbox.
func verifyJobSession(ctx context.Context, control Control, config localstate.Config, active localstate.ActiveSession, signed policy.SignedBundle) error {
	if active.Job == nil {
		return nil
	}
	step, err := active.Job.Step(config.TenantID)
	if err != nil {
		return err
	}
	digest, err := domain.Digest(active.Profile)
	if err != nil {
		return err
	}
	pd, err := domain.Digest(signed)
	if err != nil {
		return err
	}
	s := active.Session
	if active.Profile.Validate() != nil || s.Validate() != nil || active.Profile.TenantID != config.TenantID ||
		active.Profile.ID != step.ProfileID || digest != step.ProfileDigest || pd != step.PolicyDigest ||
		active.Profile.PolicyRelease != step.PolicyRelease || signed.Bundle.Release != step.PolicyRelease ||
		signed.Bundle.TenantID != config.TenantID || signed.Bundle.ProfileID != step.ProfileID ||
		active.Profile.CredentialMode != domain.CredentialAction || active.Profile.Enforcement != domain.EnforcementTyped ||
		s.TenantID != config.TenantID || s.DeviceID != config.DeviceID || s.ActorID != config.ActorID ||
		s.ProfileID != step.ProfileID || s.ProfileDigest != digest || s.State != domain.SessionRunning {
		return errors.New("session does not match the reviewed job step")
	}
	p, err := selectedJobProgress(ctx, control, config.TenantID, *active.Job)
	if err != nil {
		return err
	}
	if p.SessionID != s.ID || p.State != "running" || p.CompletedAt != nil || len(p.Results) != 0 {
		return errors.New("server did not confirm this session's job binding; agent will not run")
	}
	return nil
}

func selectedJobProgress(ctx context.Context, control Control, tenant string, selected domain.JobSelection) (domain.JobProgress, error) {
	if _, err := selected.Step(tenant); err != nil {
		return domain.JobProgress{}, err
	}
	d, err := control.Job(ctx, selected.Definition.Document.ID)
	if err != nil {
		return domain.JobProgress{}, err
	}
	if d.Validate(tenant) != nil || d.Document.ID != selected.Definition.Document.ID || d.Digest != selected.Definition.Digest {
		return domain.JobProgress{}, errors.New("reviewed job changed or is unavailable")
	}
	progress, err := control.JobProgress(ctx, d.Document.ID)
	if err != nil {
		return domain.JobProgress{}, err
	}
	if err := validateJobProgress(d, progress); err != nil {
		return domain.JobProgress{}, err
	}
	for _, p := range progress {
		if p.StepKey == selected.StepKey {
			return p, nil
		}
	}
	return domain.JobProgress{}, errors.New("job step progress is missing")
}

func validateJobProgress(d domain.JobDefinition, progress []domain.JobProgress) error {
	if len(progress) != len(d.Document.Steps) {
		return errors.New("server returned incomplete job progress")
	}
	keys := map[string]bool{}
	for _, s := range d.Document.Steps {
		keys[s.Key] = true
	}
	for _, p := range progress {
		if !keys[p.StepKey] {
			return errors.New("server returned unknown or duplicate job progress")
		}
		delete(keys, p.StepKey)
		switch p.State {
		case "not_started":
			if p.SessionID != "" || p.CompletedAt != nil || len(p.Results) != 0 {
				return errors.New("invalid unstarted job step")
			}
		case "starting", "running", "stopping", "stopped", "failed", "verified":
			if p.SessionID == "" {
				return errors.New("job step session is missing")
			}
		default:
			return errors.New("unsupported job step state")
		}
	}
	return nil
}

var proofDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validateJobCompletion(step domain.JobStep, sessionID string, p domain.JobProgress) error {
	if p.StepKey != step.Key || p.SessionID != sessionID || sessionID == "" || p.State != "verified" || p.CompletedAt == nil || p.CompletedAt.IsZero() || len(p.Results) != len(step.ExpectedActionDigests) || len(p.Results) == 0 {
		return errors.New("server has not confirmed every expected result for this step")
	}
	expected, ids := map[string]bool{}, map[string]bool{}
	for _, d := range step.ExpectedActionDigests {
		expected[d] = true
	}
	for _, r := range p.Results {
		if !expected[r.ActionDigest] || r.ActionID == "" || ids[r.ActionID] || !proofDigestPattern.MatchString(r.ProofDigest) {
			return errors.New("job completion does not match the reviewed results")
		}
		delete(expected, r.ActionDigest)
		ids[r.ActionID] = true
	}
	return nil
}

func (a *App) completeSelectedJob(ctx context.Context, control Control, config localstate.Config, selected domain.JobSelection, sessionID string) error {
	step, err := selected.Step(config.TenantID)
	if err != nil {
		return err
	}
	p, err := selectedJobProgress(ctx, control, config.TenantID, selected)
	if err != nil {
		return err
	}
	if p.SessionID == "" || (sessionID != "" && p.SessionID != sessionID) {
		return errors.New("job step belongs to another session")
	}
	s, err := control.Session(ctx, p.SessionID)
	if err != nil {
		return err
	}
	if s.Validate() != nil || s.ID != p.SessionID || s.TenantID != config.TenantID || s.ActorID != config.ActorID || s.DeviceID != config.DeviceID || s.ProfileID != step.ProfileID || s.ProfileDigest != step.ProfileDigest || s.State != domain.SessionStopped {
		return errors.New("stop the original job session before confirming its results")
	}
	result, err := control.CompleteJobStep(ctx, selected.Binding())
	if err != nil {
		return err
	}
	if err := validateJobCompletion(step, s.ID, result); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Step complete: %s. %d independently verified result(s) retained.\n", step.Name, len(result.Results))
	return nil
}

func (a *App) job(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("use job show JOB_ID or job complete --job JOB_ID --step STEP")
	}
	flags := a.flags("job " + args[0])
	id := flags.String("job", "", "reviewed job ID")
	step := flags.String("step", "", "reviewed step key")
	jsonOutput := flags.Bool("json", false, "show technical evidence")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if args[0] == "show" && *id == "" && len(flags.Args()) == 1 {
		*id = flags.Args()[0]
	} else if len(flags.Args()) != 0 {
		return errors.New("unexpected job arguments")
	}
	if *id == "" || (args[0] != "show" && args[0] != "complete") || (args[0] == "complete" && (*step == "" || *jsonOutput)) || (args[0] == "show" && *step != "") {
		return errors.New("use job show JOB_ID or job complete --job JOB_ID --step STEP")
	}
	_, config, control, err := a.authenticated()
	if err != nil {
		return err
	}
	d, err := control.Job(ctx, *id)
	if err != nil {
		return err
	}
	if d.Validate(config.TenantID) != nil || d.Document.ID != *id {
		return errors.New("job definition does not match the request")
	}
	if args[0] == "complete" {
		return a.completeSelectedJob(ctx, control, config, domain.JobSelection{Definition: d, StepKey: *step}, "")
	}
	progress, err := control.JobProgress(ctx, *id)
	if err != nil {
		return err
	}
	if err := validateJobProgress(d, progress); err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(a.Out, map[string]any{"definition": d, "steps": progress})
	}
	fmt.Fprintln(a.Out, d.Document.Name)
	byKey := map[string]domain.JobProgress{}
	for _, p := range progress {
		byKey[p.StepKey] = p
	}
	for _, s := range d.Document.Steps {
		p := byKey[s.Key]
		if p.State == "verified" {
			if err := validateJobCompletion(s, p.SessionID, p); err != nil {
				return err
			}
		}
		label := map[string]string{"not_started": "Not started", "starting": "Starting", "running": "In progress", "stopping": "Stopping", "stopped": "Stopped — results not confirmed", "failed": "Session failed", "verified": "Verified"}[p.State]
		fmt.Fprintf(a.Out, "%s — %s\n", s.Name, label)
	}
	return nil
}
