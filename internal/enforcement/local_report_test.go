package enforcement

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/hook"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
	"github.com/misconfig-cloud/agent-runtime/internal/semantics"
)

func TestLocalReportBindingAndFreshnessAtReturn(t *testing.T) {
	for _, kind := range []string{"ordinary", "changed", "wrong-digest", "wrong-class", "expired", "stopped"} {
		t.Run(kind, func(t *testing.T) {
			engine, control, path, now := fixtureForProvider(t, domain.AgentCodex, policy.EffectAllow, "local-agent")
			active, err := localstate.LoadActive(path)
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(active.Profile.Workspace, "empty.txt")
			if err := os.WriteFile(target, nil, 0600); err != nil {
				t.Fatal(err)
			}
			control.guardrailOverride = func(req controlclient.GuardrailAssessmentRequest) (controlclient.GuardrailDecision, error) {
				if req.LocalAnalysis == nil || req.LocalAnalysis.Classification != semantics.Ordinary || req.LocalAnalysis.InputDigest != req.InputDigest || len(req.LocalAnalysis.Evidence) != 0 {
					t.Fatalf("report not locally analyzed/bound/redacted: %+v", req.LocalAnalysis)
				}
				d := controlclient.GuardrailDecision{Effect: "continue", Classification: "ordinary", Reason: "Ordinary local file operation", PolicyVersion: 1, AssessmentSource: "local", InputDigest: req.InputDigest}
				switch kind {
				case "changed":
					if err := os.WriteFile(target, []byte("now valuable"), 0600); err != nil {
						t.Fatal(err)
					}
				case "wrong-digest":
					d.InputDigest = "other"
				case "wrong-class":
					d.Classification = "unknown"
				case "stopped":
					if err := engine.Store.MarkStopped(active.Session.ID); err != nil {
						t.Fatal(err)
					}
				}
				return d, nil
			}
			// Engine is a value receiver, so a mutable clock closure models time
			// passing while the control-plane request is in flight.
			clock := now
			engine.Now = func() time.Time { return clock }
			original := control.guardrailOverride
			control.guardrailOverride = func(req controlclient.GuardrailAssessmentRequest) (controlclient.GuardrailDecision, error) {
				d, e := original(req)
				if kind == "expired" {
					clock = now.Add(2 * time.Hour)
				}
				return d, e
			}
			r, err := engine.Pre(context.Background(), path, hook.Input{ToolName: "Bash", ToolUseID: "test", ToolInput: map[string]any{"command": "rm -- empty.txt"}, CWD: active.Profile.Workspace})
			if err != nil {
				t.Fatal(err)
			}
			want := policy.EffectDeny
			if kind == "ordinary" {
				want = policy.EffectAllow
			}
			if r.Decision.Effect != want {
				t.Fatalf("%s: got %+v", kind, r.Decision)
			}
		})
	}
}

func TestLocalReportRetentionRedactsTargetsAndDropsEvidence(t *testing.T) {
	secret := "ghp_" + strings.Repeat("x", 30)
	r, err := localTransportReport(semantics.Report{Version: semantics.Version, Classification: semantics.CredentialExposure, Complete: true, Effects: []semantics.Effect{{Kind: semantics.Disclose, Target: "/tmp/" + secret, Classification: semantics.CredentialExposure, Reason: "Recognizable credential"}}, Evidence: []semantics.Evidence{{Path: "private-local-evidence"}}}, "digest")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(r)
	if strings.Contains(string(data), secret) || strings.Contains(string(data), "private-local-evidence") || len(r.Evidence) != 0 {
		t.Fatal("local evidence or credential retained")
	}
}

func TestModelAssistanceCannotPromoteUnknownLocalEffects(t *testing.T) {
	for _, variant := range []string{"acknowledged", "blocked", "promoted", "legacy-source"} {
		t.Run(variant, func(t *testing.T) {
			engine, control, path, _ := fixtureForProvider(t, domain.AgentCodex, policy.EffectAllow, "local-agent")
			active, err := localstate.LoadActive(path)
			if err != nil {
				t.Fatal(err)
			}
			control.guardrailOverride = func(req controlclient.GuardrailAssessmentRequest) (controlclient.GuardrailDecision, error) {
				if req.LocalAnalysis == nil || req.LocalAnalysis.Classification != semantics.Unknown {
					t.Fatalf("unfamiliar interpreter must remain unknown: %+v", req.LocalAnalysis)
				}
				d := controlclient.GuardrailDecision{Effect: "continue", Classification: "unknown", Reason: "Unresolved interpreter effects", PolicyVersion: 1, AssessmentSource: "model_assisted", InputDigest: req.InputDigest}
				switch variant {
				case "blocked":
					d.Effect = "block"
				case "promoted":
					d.Classification = "ordinary"
				case "legacy-source":
					d.AssessmentSource = "legacy_model"
				}
				return d, nil
			}
			r, err := engine.Pre(context.Background(), path, hook.Input{ToolName: "Bash", ToolUseID: "unknown-test", ToolInput: map[string]any{"command": "python3 -c 'print(1)'"}, CWD: active.Profile.Workspace})
			if err != nil {
				t.Fatal(err)
			}
			want := policy.EffectDeny
			if variant == "acknowledged" {
				want = policy.EffectAllow
			}
			if r.Decision.Effect != want {
				t.Fatalf("assistance loosened local truth: %+v", r.Decision)
			}
		})
	}
}
