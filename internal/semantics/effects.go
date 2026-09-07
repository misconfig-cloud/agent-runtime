// Package semantics inspects proposed actions without executing them. It reports
// effects and uncertainty, never authorization. The caller must apply current
// policy and native permissions after checking the report's evidence.
package semantics

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const Version = "local-effects-v1"

type Kind string

const (
	Read     Kind = "read"
	Inspect  Kind = "inspect"
	Write    Kind = "write"
	Delete   Kind = "delete"
	Execute  Kind = "execute"
	Transmit Kind = "transmit"
	Disclose Kind = "disclose"
)

type Classification string

const (
	Ordinary           Classification = "ordinary"
	Risky              Classification = "risky"
	Dangerous          Classification = "dangerous"
	CredentialExposure Classification = "credential_exposure"
	Unknown            Classification = "unknown"
)

type Effect struct {
	Kind           Kind           `json:"kind"`
	Target         string         `json:"target,omitempty"`
	Classification Classification `json:"classification"`
	Reason         string         `json:"reason"`
}

func (e Effect) valid() bool {
	switch e.Kind {
	case Read, Inspect, Write, Delete, Execute, Transmit, Disclose:
	default:
		return false
	}
	switch e.Classification {
	case Ordinary, Risky, Dangerous, CredentialExposure, Unknown:
	default:
		return false
	}
	return strings.TrimSpace(e.Reason) != ""
}

// Evidence stays local. Paths, identities and content hashes must not be
// interpreted as permission or included in cloud telemetry without redaction.
type Evidence struct {
	Path          string
	Exists        bool
	Info          os.FileInfo
	ContentDigest string
}

type Report struct {
	Version        string         `json:"version"`
	Classification Classification `json:"classification"`
	Complete       bool           `json:"complete"`
	Effects        []Effect       `json:"effects"`
	UnknownReasons []string       `json:"unknown_reasons,omitempty"`
	Evidence       []Evidence     `json:"-"`
	DurationMS     int64          `json:"duration_ms"`
}

func (r *Report) add(effect Effect) {
	if effect.Classification == Unknown {
		r.Complete = false
	}
	r.Effects = append(r.Effects, effect)
}
func (r *Report) unknown(reason string) {
	r.Complete = false
	r.UnknownReasons = append(r.UnknownReasons, reason)
}

func (r *Report) finish(start time.Time) {
	r.Classification = Ordinary
	for _, effect := range r.Effects {
		if rank(effect.Classification) > rank(r.Classification) {
			r.Classification = effect.Classification
		}
	}
	if !r.Complete && rank(Unknown) > rank(r.Classification) {
		r.Classification = Unknown
	}
	r.DurationMS = time.Since(start).Milliseconds()
}

func rank(c Classification) int {
	switch c {
	case CredentialExposure:
		return 4
	case Dangerous:
		return 3
	case Unknown:
		return 2
	case Risky:
		return 1
	default:
		return 0
	}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Fresh rechecks every observed object and missing target. It intentionally does
// not cache permission. A pre-tool check cannot eliminate a subsequent TOCTOU
// race in an unconstrained child process; native sandboxing is still required.
func (r Report) Fresh() bool {
	for _, e := range r.Evidence {
		info, err := os.Lstat(e.Path)
		if !e.Exists {
			if !os.IsNotExist(err) {
				return false
			}
			continue
		}
		if err != nil || e.Info == nil || !os.SameFile(e.Info, info) || e.Info.Mode() != info.Mode() {
			return false
		}
		// Parent directories establish path identity, not a snapshot of every
		// sibling. Unrelated file creation must not invalidate a target proof.
		// No analyzer claims to have enumerated directory contents in this version.
		if !info.IsDir() && (e.Info.Size() != info.Size() || !e.Info.ModTime().Equal(info.ModTime())) {
			return false
		}
		if info.Mode().IsRegular() && sharedFile(e.Info) != sharedFile(info) {
			return false
		}
		if e.ContentDigest != "" {
			data, err := readBoundedFile(e.Path, info)
			if err != nil || digest(data) != e.ContentDigest {
				return false
			}
		}
	}
	return true
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
