package domain

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// These fields mirror the retained job-definition wire contract. A new server
// field changes the digest and must not silently disappear in an older client.
type JobStep struct {
	Key                   string   `json:"key"`
	Name                  string   `json:"name"`
	ProfileID             string   `json:"profile_id"`
	ProfileDigest         string   `json:"profile_digest"`
	DependsOn             []string `json:"depends_on,omitempty"`
	ExpectedActionDigests []string `json:"expected_action_digests,omitempty"`
	PolicyRelease         string   `json:"policy_release"`
	PolicyDigest          string   `json:"policy_digest"`
}
type JobDocument struct {
	Schema          string    `json:"schema"`
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	Name            string    `json:"name"`
	Request         string    `json:"request"`
	SourceReference string    `json:"source_reference,omitempty"`
	SourceState     string    `json:"source_state"`
	Steps           []JobStep `json:"steps"`
	CreatedAt       time.Time `json:"created_at"`
}
type JobDefinition struct {
	Document JobDocument `json:"document"`
	Digest   string      `json:"digest"`
}
type JobBinding struct {
	JobID     string `json:"job_id"`
	JobDigest string `json:"job_digest"`
	StepKey   string `json:"step_key"`
}
type JobSelection struct {
	Definition JobDefinition `json:"definition"`
	StepKey    string        `json:"step_key"`
}
type JobResult struct {
	ActionID     string `json:"action_id"`
	ActionDigest string `json:"action_digest"`
	ProofDigest  string `json:"proof_digest"`
}
type JobProgress struct {
	StepKey     string      `json:"step_key"`
	SessionID   string      `json:"session_id,omitempty"`
	State       string      `json:"state"`
	Results     []JobResult `json:"results,omitempty"`
	CompletedAt *time.Time  `json:"completed_at,omitempty"`
}

var jobKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
var jobDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (d JobDefinition) Validate(tenant string) error {
	fail := errors.New("job definition is invalid, changed or unsupported")
	v := d.Document
	if v.Schema != "misconfig.job-definition/v1" || v.ID == "" || len(v.ID) > 256 || v.TenantID != tenant || tenant == "" || v.CreatedAt.IsZero() || v.SourceState != "customer_supplied" || strings.TrimSpace(v.Name) == "" || len(v.Name) > 160 || strings.TrimSpace(v.Request) == "" || len(v.Request) > 8000 || len(v.SourceReference) > 2048 || len(v.Steps) == 0 || len(v.Steps) > 16 {
		return fail
	}
	steps := map[string]JobStep{}
	for _, s := range v.Steps {
		if !jobKeyPattern.MatchString(s.Key) || s.Name == "" || len(s.Name) > 160 || s.ProfileID == "" || len(s.ProfileID) > 256 || !jobDigestPattern.MatchString(s.ProfileDigest) || s.PolicyRelease == "" || !jobDigestPattern.MatchString(s.PolicyDigest) || len(s.DependsOn) > 15 || len(s.ExpectedActionDigests) > 64 {
			return fail
		}
		if _, ok := steps[s.Key]; ok {
			return fail
		}
		steps[s.Key] = s
		seen := map[string]bool{}
		for _, digest := range s.ExpectedActionDigests {
			if !jobDigestPattern.MatchString(digest) || seen[digest] {
				return fail
			}
			seen[digest] = true
		}
	}
	visiting, done := map[string]bool{}, map[string]bool{}
	var visit func(string) bool
	visit = func(key string) bool {
		if done[key] {
			return true
		}
		if visiting[key] {
			return false
		}
		s, ok := steps[key]
		if !ok {
			return false
		}
		visiting[key] = true
		seen := map[string]bool{}
		for _, dep := range s.DependsOn {
			if seen[dep] || !visit(dep) {
				return false
			}
			seen[dep] = true
		}
		visiting[key] = false
		done[key] = true
		return true
	}
	for key := range steps {
		if !visit(key) {
			return fail
		}
	}
	digest, err := Digest(v)
	if err != nil || digest != d.Digest {
		return fail
	}
	return nil
}
func (s JobSelection) Binding() JobBinding {
	return JobBinding{JobID: s.Definition.Document.ID, JobDigest: s.Definition.Digest, StepKey: s.StepKey}
}
func (s JobSelection) Step(tenant string) (JobStep, error) {
	if err := s.Definition.Validate(tenant); err != nil {
		return JobStep{}, err
	}
	for _, step := range s.Definition.Document.Steps {
		if len(step.ExpectedActionDigests) == 0 {
			return JobStep{}, errors.New("this plan needs reviewed completion conditions before it can run")
		}
	}
	for _, step := range s.Definition.Document.Steps {
		if step.Key == s.StepKey {
			return step, nil
		}
	}
	return JobStep{}, errors.New("job step was not found")
}
