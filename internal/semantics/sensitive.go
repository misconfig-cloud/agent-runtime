package semantics

import "regexp"

// Recognizable credential formats supplement structural source tracking. They
// are not an exhaustive detector or proof that unrecognized literal data is safe.
// Matches are never placed in the report, telemetry or explanations.
var credentialLiteral = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:gh[opsu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b|\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\b`)

func (s *analysis) inspectLiteral(value string) {
	if credentialLiteral.MatchString(value) {
		s.report.add(Effect{Kind: Disclose, Classification: CredentialExposure, Reason: "Recognizable authentication material enters a command or file payload"})
	}
}
