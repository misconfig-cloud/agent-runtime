package semantics

import (
	"os"
	"path/filepath"
	"strings"
)

// Observe every component rather than cleaning the path first: a/../b must not
// erase an unresolved symlink in a. Symlinks are unknown in this first analyzer.
func (s *analysis) target(name string) (string, os.FileInfo, bool) {
	if name == "" || strings.ContainsAny(name, "\x00\n") {
		s.report.unknown("The filesystem target is unresolved")
		return "", nil, false
	}
	path := s.cwd
	if filepath.IsAbs(name) {
		path = string(filepath.Separator)
	}
	parts := strings.Split(name, string(filepath.Separator))
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) && i == len(parts)-1 {
			s.report.Evidence = append(s.report.Evidence, Evidence{Path: path})
			return path, nil, true
		}
		if err != nil {
			s.report.unknown("A filesystem target or parent could not be inspected")
			return path, nil, false
		}
		s.report.Evidence = append(s.report.Evidence, Evidence{Path: path, Exists: true, Info: info})
		if info.Mode()&os.ModeSymlink != 0 {
			s.report.unknown("A target traverses a symbolic link")
			return path, nil, false
		}
		if i < len(parts)-1 && !info.IsDir() {
			s.report.unknown("A target parent is not a directory")
			return path, nil, false
		}
	}
	info, err := os.Lstat(path)
	return path, info, err == nil
}

func protectedPath(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		p := strings.ToLower(part)
		if p == ".ssh" || p == ".aws" || p == ".kube" || p == ".gnupg" || p == ".codex" || p == ".claude" || p == ".misconfig" || p == ".git" || p == ".env" || strings.HasPrefix(p, ".env.") || p == "credentials" || p == "id_rsa" || p == "id_ed25519" {
			return true
		}
	}
	return false
}

func (s *analysis) filesystem(kind Kind, name string, recursive bool) {
	path, info, known := s.target(name)
	if path == "" {
		return
	}
	classification, reason := Ordinary, "The operation targets one ordinary workspace file"
	if protectedPath(path) && kind != Inspect {
		classification, reason = Dangerous, "The target contains credentials or agent, repository or security configuration"
		if kind == Read {
			classification, reason = CredentialExposure, "The operation may expose a sensitive file to the agent"
		}
	} else if !within(s.root, path) || path == s.root && kind != Inspect {
		classification, reason = Dangerous, "The operation reaches outside the workspace or targets the workspace itself"
		if kind == Read || kind == Inspect {
			classification, reason = Unknown, "The read target is outside the ordinary workspace boundary"
		}
	} else if recursive && kind == Delete {
		classification, reason = Dangerous, "The operation recursively removes filesystem content"
	} else if info != nil && !info.Mode().IsRegular() && kind != Inspect {
		classification, reason = Unknown, "The target is not an ordinary regular file"
		if kind == Delete && info.IsDir() {
			classification, reason = Dangerous, "The operation removes a directory"
		}
	} else if kind == Delete && info != nil && info.Size() > 0 {
		classification, reason = Risky, "The operation removes a nonempty file"
	} else if kind == Write && info != nil && info.Size() > 0 {
		classification, reason = Risky, "The operation changes existing file content"
	}
	if kind == Write && info != nil && sharedFile(info) {
		classification, reason = Dangerous, "The file has multiple hard links and a write can affect another path"
	}
	if kind == Read && known && info != nil && info.Mode().IsRegular() && within(s.root, path) && !protectedPath(path) {
		if data, err := readBoundedFile(path, info); err == nil {
			s.inspectLiteral(string(data))
			s.report.Evidence = append(s.report.Evidence, Evidence{Path: path, Exists: true, Info: info, ContentDigest: digest(data)})
		} else if rank(classification) < rank(Unknown) {
			classification, reason = Unknown, "The file exceeds the local content inspection limit or could not be inspected"
		}
	}
	if !known && rank(classification) < rank(Unknown) {
		classification, reason = Unknown, "Filesystem evidence is incomplete"
	}
	if s.previouslyMutated(path) && rank(classification) < rank(Unknown) {
		classification, reason = Unknown, "An earlier operation can change this target before execution"
	}
	if kind == Write || kind == Delete {
		s.mutated = append(s.mutated, path)
	}
	s.report.add(Effect{Kind: kind, Target: path, Classification: classification, Reason: reason})
}

func (s *analysis) previouslyMutated(path string) bool {
	for _, earlier := range s.mutated {
		if within(earlier, path) || within(path, earlier) {
			return true
		}
	}
	return false
}
