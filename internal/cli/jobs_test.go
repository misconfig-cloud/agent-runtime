package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
	provideradapter "github.com/misconfig-cloud/provider-sdk"
)

func bindJobFixture(t *testing.T, f *actionFixture) {
	t.Helper()
	pd, _ := domain.Digest(f.control.signed)
	ad, err := provideradapter.ActionDigest("sha256:"+strings.Repeat("a", 64), "ShiftVector", f.active.Profile.Scope.ResourceIDs[0], "test", json.RawMessage(`{"bearing":17}`))
	if err != nil {
		t.Fatal(err)
	}
	d := domain.JobDefinition{Document: domain.JobDocument{Schema: "misconfig.job-definition/v1", ID: "job-a", TenantID: f.active.Profile.TenantID, Name: "Adjust the selected resource", Request: "Set its bearing to 17", SourceState: "customer_supplied", CreatedAt: f.now,
		Steps: []domain.JobStep{{Key: "adjust", Name: "Adjust bearing", ProfileID: f.active.Profile.ID, ProfileDigest: f.active.Session.ProfileDigest, PolicyRelease: f.active.Profile.PolicyRelease, PolicyDigest: pd, ExpectedActionDigests: []string{ad}}}}}
	d.Digest, _ = domain.Digest(d.Document)
	f.active.Job = &domain.JobSelection{Definition: d, StepKey: "adjust"}
	f.control.jobDefinition = d
	f.control.jobProgress = []domain.JobProgress{{StepKey: "adjust", SessionID: f.active.Session.ID, State: "running"}}
	f.control.jobCompletion = domain.JobProgress{StepKey: "adjust", SessionID: f.active.Session.ID, State: "verified", CompletedAt: &f.now, Results: []domain.JobResult{{ActionID: "action-a", ActionDigest: ad, ProofDigest: "sha256:" + strings.Repeat("b", 64)}}}
	if _, err := f.store.SaveActive(f.active); err != nil {
		t.Fatal(err)
	}
}

func TestJobBindingIsCheckedBeforeEveryAction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*actionFixture)
	}{
		{"valid", func(f *actionFixture) {}},
		{"server ignores binding", func(f *actionFixture) { f.control.jobProgress = nil }},
		{"another session", func(f *actionFixture) { f.control.jobProgress[0].SessionID = "another" }},
		{"completed", func(f *actionFixture) { f.control.jobProgress[0] = f.control.jobCompletion }},
		{"duplicate step", func(f *actionFixture) {
			f.control.jobProgress = append(f.control.jobProgress, f.control.jobProgress[0])
		}},
		{"unknown step", func(f *actionFixture) { f.control.jobProgress[0].StepKey = "other" }},
		{"changed job", func(f *actionFixture) { f.control.jobDefinition.Document.Request = "changed" }},
		{"changed policy", func(f *actionFixture) {
			f.active.Job.Definition.Document.Steps[0].PolicyDigest = "sha256:" + strings.Repeat("c", 64)
			f.active.Job.Definition.Digest, _ = domain.Digest(f.active.Job.Definition.Document)
			f.control.jobDefinition = f.active.Job.Definition
			f.store.SaveActive(f.active)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newActionFixture(t)
			bindJobFixture(t, f)
			tc.mutate(f)
			_, config, control, err := f.app.authenticated()
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.app.loadActionSession(context.Background(), f.store, config, control)
			if (err == nil) != (tc.name == "valid") {
				t.Fatalf("unexpected binding result: %v", err)
			}
		})
	}
}

func TestJobExpectedActionNarrowsOtherwisePermittedTask(t *testing.T) {
	f := newActionFixture(t)
	bindJobFixture(t, f)
	s := actionSession{active: f.active, policy: f.control.signed.Bundle}
	cap := provideradapter.CapabilitySelector{Ref: "fixture.shift@1", Digest: "sha256:" + strings.Repeat("a", 64)}
	for _, tc := range []struct {
		parameters string
		allowed    bool
	}{{`{"bearing":17}`, true}, {`{ "bearing" : 17 }`, true}, {`{"bearing":18}`, false}, {`{"bearing":17,"extra":true}`, false}} {
		err := f.app.checkTypedAction(s, "ShiftVector", f.active.Profile.Scope.ResourceIDs[0], "test", cap, json.RawMessage(tc.parameters))
		if (err == nil) != tc.allowed {
			t.Fatalf("%s: %v", tc.parameters, err)
		}
	}
}

func TestJobCompletionRejectsUnrelatedOrMissingResults(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*actionFixture)
	}{
		{"verified", func(f *actionFixture) {}},
		{"running session", func(f *actionFixture) { f.control.remote.State = domain.SessionRunning }},
		{"wrong device", func(f *actionFixture) { f.control.remote.DeviceID = "other" }},
		{"wrong tenant", func(f *actionFixture) { f.control.remote.TenantID = "other" }},
		{"wrong profile", func(f *actionFixture) { f.control.remote.ProfileDigest = "other" }},
		{"another result session", func(f *actionFixture) { f.control.jobCompletion.SessionID = "other" }},
		{"missing proof", func(f *actionFixture) { f.control.jobCompletion.Results[0].ProofDigest = "" }},
		{"unrelated action", func(f *actionFixture) {
			f.control.jobCompletion.Results[0].ActionDigest = "sha256:" + strings.Repeat("e", 64)
		}},
		{"missing result", func(f *actionFixture) { f.control.jobCompletion.Results = nil }},
		{"duplicate result", func(f *actionFixture) {
			f.control.jobCompletion.Results = append(f.control.jobCompletion.Results, f.control.jobCompletion.Results[0])
		}},
		{"unverified", func(f *actionFixture) { f.control.jobCompletion.State = "stopped" }},
		{"no completion time", func(f *actionFixture) { f.control.jobCompletion.CompletedAt = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newActionFixture(t)
			bindJobFixture(t, f)
			f.control.remote.State = domain.SessionStopped
			tc.mutate(f)
			_, config, _, err := f.app.authenticated()
			if err != nil {
				t.Fatal(err)
			}
			err = f.app.completeSelectedJob(context.Background(), f.control, config, *f.active.Job, f.active.Session.ID)
			if (err == nil) != (tc.name == "verified") {
				t.Fatalf("completion result: %v", err)
			}
			if tc.name != "verified" && strings.Contains(f.output.String(), "Step complete:") {
				t.Fatal("printed false completion")
			}
		})
	}
}

func TestJobCompletionCommandRetriesWithoutLaunchingAnAgent(t *testing.T) {
	f := newActionFixture(t)
	bindJobFixture(t, f)
	f.control.remote.State = domain.SessionStopped
	f.app.RunCommand = func(context.Context, string, []string, string, []string, io.Reader, io.Writer, io.Writer) error {
		t.Fatal("completion launched an agent")
		return nil
	}
	for i := 0; i < 2; i++ {
		if err := f.app.Run(context.Background(), []string{"job", "complete", "--job", "job-a", "--step", "adjust"}); err != nil {
			t.Fatal(err)
		}
	}
	if f.control.jobCompleted != 2 {
		t.Fatal("completion was not retried")
	}
}

func TestJobRunRefusesIgnoredBindingBeforeNativeLaunch(t *testing.T) {
	f := newActionFixture(t)
	bindJobFixture(t, f)
	f.control.profiles = []domain.SessionProfile{f.active.Profile}
	f.control.started = f.active.Session
	f.control.jobProgress = nil
	f.app.LookPath = func(string) (string, error) { return "/unused", nil }
	f.app.RunCommand = func(context.Context, string, []string, string, []string, io.Reader, io.Writer, io.Writer) error {
		t.Fatal("unbound agent launched")
		return nil
	}
	err := f.app.Run(context.Background(), []string{"run", "--job", "job-a", "--step", "adjust"})
	if err == nil || len(f.control.stopped) != 1 || f.control.jobStarted == nil {
		t.Fatalf("unsafe launch result: %v stops=%v", err, f.control.stopped)
	}
}

func TestJobRunRejectsAmbiguousSelectionBeforeContactingServer(t *testing.T) {
	for _, args := range [][]string{{"run", "--job", "job-a"}, {"run", "--step", "adjust"}, {"run", "--job", "job-a", "--step", "adjust", "--profile", "task"}} {
		f := newActionFixture(t)
		if err := f.app.Run(context.Background(), args); err == nil {
			t.Fatalf("accepted ambiguous selection: %v", args)
		}
		if f.control.jobStarted != nil {
			t.Fatal("ambiguous selection launched")
		}
	}
}

func TestJobShowUsesReadableNamesWithoutTechnicalEvidence(t *testing.T) {
	f := newActionFixture(t)
	bindJobFixture(t, f)
	if err := f.app.Run(context.Background(), []string{"job", "show", "job-a"}); err != nil {
		t.Fatal(err)
	}
	output := f.output.String()
	if !strings.Contains(output, "Adjust bearing — In progress") || strings.Contains(output, "sha256:") || strings.Contains(output, "session-a") {
		t.Fatalf("unclear job output: %s", output)
	}
}

func TestJobRunRetainsBindingAndRequiresVerifiedCompletionAfterExit(t *testing.T) {
	for _, mode := range []string{"verified", "missing proof", "agent failure", "remote stop"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := capabilityFixture(t)
			bindJobFixture(t, f)
			f.control.profiles = []domain.SessionProfile{f.active.Profile}
			f.control.started = f.active.Session
			f.app.LookPath = func(string) (string, error) { return "/unused", nil }
			f.app.Executable = os.Executable
			launched := false
			f.app.RunCommand = func(_ context.Context, _ string, _ []string, _ string, environment []string, _ io.Reader, _, _ io.Writer) error {
				launched = true
				var path string
				for _, v := range environment {
					if strings.HasPrefix(v, "MISCONFIG_ACTIVE_SESSION=") {
						path = strings.TrimPrefix(v, "MISCONFIG_ACTIVE_SESSION=")
					}
				}
				active, err := localstate.LoadActive(path)
				if err != nil || active.Job == nil || active.Job.Definition.Digest != f.active.Job.Definition.Digest {
					t.Fatalf("lost binding: %v", err)
				}
				f.control.remote.State = domain.SessionStopped
				if mode == "remote stop" {
					active.Session.State = domain.SessionStopped
					if _, err := f.store.SaveActive(active); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "agent failure" {
					return errors.New("agent failed")
				}
				if mode == "missing proof" {
					f.control.jobCompletion.Results = nil
				}
				return nil
			}
			err := f.app.Run(context.Background(), []string{"run", "--job", "job-a", "--step", "adjust"})
			if !launched {
				t.Fatalf("did not launch: %v", err)
			}
			if (err == nil) != (mode == "verified" || mode == "remote stop") {
				t.Fatalf("unexpected run result: %v", err)
			}
			if (f.control.jobCompleted != 0) != (mode == "verified" || mode == "missing proof") {
				t.Fatalf("unexpected completion calls: %d", f.control.jobCompleted)
			}
		})
	}
}
