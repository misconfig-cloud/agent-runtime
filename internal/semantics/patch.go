package semantics

import "strings"

// Inspect the native apply_patch envelope, never a shell heredoc or an arbitrary
// program that happens to contain diff text. Every file operation contributes an
// effect. Unsupported syntax stays unknown, even when another hunk is ordinary.
func (s *analysis) patch(patch string) {
	if len(patch) > 64*1024 {
		s.report.unknown("The patch exceeds the local inspection limit")
		return
	}
	lines := strings.Split(strings.TrimSuffix(patch, "\n"), "\n")
	if len(lines) < 3 || lines[0] != "*** Begin Patch" || lines[len(lines)-1] != "*** End Patch" {
		s.report.unknown("The native patch envelope is unsupported")
		return
	}
	mode, source := "", ""
	headers, body, moved := 0, false, false
	for _, line := range lines[1 : len(lines)-1] {
		s.inspectLiteral(line)
		kind, prefix := Write, ""
		switch {
		case strings.HasPrefix(line, "*** Add File: "):
			mode, prefix = "add", "*** Add File: "
		case strings.HasPrefix(line, "*** Update File: "):
			mode, prefix = "update", "*** Update File: "
		case strings.HasPrefix(line, "*** Delete File: "):
			mode, prefix, kind = "delete", "*** Delete File: ", Delete
		}
		if prefix != "" {
			headers++
			if headers > 128 {
				s.report.unknown("The patch has too many file operations")
				return
			}
			source = strings.TrimPrefix(line, prefix)
			if source == "" || source != strings.TrimSpace(source) {
				s.report.unknown("A patch target is unsupported")
				continue
			}
			body, moved = false, false
			s.filesystem(kind, source, false)
			continue
		}
		if strings.HasPrefix(line, "*** Move to: ") {
			if mode != "update" || body || moved {
				s.report.unknown("A patch move has an unsupported position")
				continue
			}
			moved = true
			target := strings.TrimPrefix(line, "*** Move to: ")
			if target == "" || target != strings.TrimSpace(target) {
				s.report.unknown("The patch move target is unsupported")
				continue
			}
			// A move carries existing contents, not only added diff lines. The
			// preceding source write makes this conservatively unresolved; source
			// inspection can still reveal credential exposure and add a block.
			s.filesystem(Read, source, false)
			s.filesystem(Delete, source, false)
			s.filesystem(Write, target, false)
			continue
		}
		body = true
		valid := mode == "add" && strings.HasPrefix(line, "+")
		if mode == "update" {
			valid = line == "@@" || strings.HasPrefix(line, "@@ ") || line == "*** End of File" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-")
		}
		if !valid {
			s.report.unknown("The patch contains unsupported or malformed syntax")
		}
	}
	if headers == 0 {
		s.report.unknown("The patch does not identify any file operations")
	}
}
