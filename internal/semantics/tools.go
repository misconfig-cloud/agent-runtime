package semantics

import "strings"

// ToolRequest is the native tool payload BEFORE redaction. Tool names are
// matched exactly: an MCP tool that happens to end in Read is not a file tool.
// This type contains no policy or authority; reports still require current
// session/policy validation and fresh evidence at the enforcement boundary.
type ToolRequest struct {
	Workspace string
	CWD       string
	Name      string
	Input     map[string]any
}

func (e Engine) AnalyzeTool(request ToolRequest) Report {
	base := Request{Workspace: request.Workspace, CWD: request.CWD}
	return e.analyze(base, func(s *analysis) {
		switch request.Name {
		case "apply_patch":
			patch, ok := request.Input["command"].(string)
			if !ok {
				s.report.unknown("The native patch payload is missing")
				return
			}
			s.patch(patch)
		case "Bash", "shell_command", "exec_command":
			key := "command"
			if request.Name == "exec_command" {
				key = "cmd"
			}
			command, ok := request.Input[key].(string)
			if !ok || command == "" {
				s.report.unknown("The shell command payload is missing or unsupported")
				return
			}
			// cwd/workdir in the native call override the hook's current directory.
			// Do not silently inspect the wrong filesystem context.
			for _, field := range []string{"cwd", "workdir"} {
				if value, exists := request.Input[field]; exists && value != nil {
					path, valid := value.(string)
					if !valid || path != "" && path != s.cwd {
						s.report.unknown("The tool changes the command working directory")
					}
				}
			}
			if shell, exists := request.Input["shell"]; exists && shell != nil && shell != "" && shell != "/bin/bash" && shell != "/bin/sh" {
				s.report.unknown("The requested shell dialect is unsupported")
			}
			s.shell(command)
		case "Read", "Write", "Edit":
			path, ok := request.Input["file_path"].(string)
			if !ok || strings.TrimSpace(path) == "" {
				s.report.unknown("The native file target is missing")
				return
			}
			kind := Read
			if request.Name != "Read" {
				kind = Write
				field := "content"
				if request.Name == "Edit" {
					field = "new_string"
					if _, valid := request.Input["old_string"].(string); !valid {
						s.report.unknown("The edit's original content is missing")
					}
				}
				if data, valid := request.Input[field].(string); valid {
					s.inspectLiteral(data)
				} else {
					s.report.unknown("The file write content is missing or unsupported")
				}
			}
			s.filesystem(kind, path, false)
		default:
			s.report.unknown("This native tool has no installed effect analyzer")
		}
	})
}
