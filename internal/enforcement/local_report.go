package enforcement

import (
	"encoding/json"
	"sort"

	"github.com/misconfig-cloud/agent-runtime/internal/hook"
	"github.com/misconfig-cloud/agent-runtime/internal/semantics"
)

// Evidence remains on the machine; only redacted effect descriptions are sent.
// Summarization must retain the most consequential effects and cannot create a
// claim of completeness. The original report is rechecked after the API call.
func localTransportReport(report semantics.Report, inputDigest string) (semantics.Report, error) {
	report.InputDigest = inputDigest
	report.Effects = append([]semantics.Effect(nil), report.Effects...)
	rank := map[semantics.Classification]int{semantics.Ordinary: 0, semantics.Risky: 1, semantics.Unknown: 2, semantics.Dangerous: 3, semantics.CredentialExposure: 4}
	if len(report.Effects) > 128 || len(report.UnknownReasons) > 32 {
		sort.SliceStable(report.Effects, func(i, j int) bool {
			return rank[report.Effects[i].Classification] > rank[report.Effects[j].Classification]
		})
		if len(report.Effects) > 128 {
			report.Effects = report.Effects[:128]
		}
		report.Complete = false
		if rank[report.Classification] < rank[semantics.Unknown] {
			report.Classification = semantics.Unknown
		}
		report.UnknownReasons = []string{"The effect report exceeded the retained detail limit"}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return semantics.Report{}, err
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return semantics.Report{}, err
	}
	encoded, err = json.Marshal(hook.RedactedToolInput(hook.Input{ToolInput: fields}))
	if err != nil {
		return semantics.Report{}, err
	}
	var result semantics.Report
	err = json.Unmarshal(encoded, &result)
	return result, err
}
