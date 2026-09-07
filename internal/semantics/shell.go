package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"mvdan.cc/sh/v3/syntax"
)

// Analyzer extensions describe effects, not decisions. Only trusted installed
// analyzers belong in this registry; agent/MCP descriptions cannot register one.
type Call struct {
	Executable string
	Args       []string
}
type CallAnalyzer interface{ AnalyzeCall(Call) ([]Effect, bool) }
type Engine struct{ Analyzers []CallAnalyzer }
type Request struct{ Workspace, CWD, Command string }
type analysis struct {
	engine    Engine
	root, cwd string
	report    Report
	depth     int
	tainted   map[string]bool
	mutated   []string
	steps     int
	exhausted bool
}

var sensitive = regexp.MustCompile(`(?i)(secret|token|password|passwd|credential|api[_-]?key|private[_-]?key|authorization|cookie)`)

func (e Engine) Analyze(request Request) Report {
	return e.analyze(request, func(s *analysis) { s.shell(request.Command) })
}

func (e Engine) analyze(request Request, inspect func(*analysis)) Report {
	start := time.Now()
	s := &analysis{engine: e, root: request.Workspace, cwd: request.CWD, report: Report{Version: Version, Complete: true}, tainted: make(map[string]bool)}
	if s.cwd == "" {
		s.cwd = s.root
	}
	if !filepath.IsAbs(s.root) || !filepath.IsAbs(s.cwd) || !within(s.root, s.cwd) {
		s.report.unknown("The current workspace could not be resolved")
	} else if root, err := filepath.EvalSymlinks(s.root); err != nil || root != filepath.Clean(s.root) {
		s.report.unknown("The workspace is unavailable or traverses a symbolic link")
	} else {
		// Observe cwd components too, including its own identity.
		if _, _, ok := s.target(s.cwd); ok {
			inspect(s)
		}
	}
	if !s.report.Fresh() {
		s.report.unknown("Filesystem evidence changed during analysis")
	}
	s.report.finish(start)
	return s.report
}

func (s *analysis) shell(command string) {
	if len(command) > 64*1024 || s.depth >= 4 {
		s.report.unknown("The command exceeds local analysis limits")
		return
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		s.report.unknown("The shell syntax is unsupported or incomplete")
		return
	}
	s.depth++
	defer func() { s.depth-- }()
	for _, stmt := range file.Stmts {
		s.statement(stmt)
	}
}

func (s *analysis) statement(stmt *syntax.Stmt) {
	if !s.step() {
		return
	}
	if stmt.Background || stmt.Coprocess {
		s.report.unknown("Concurrent shell execution has unresolved effects")
	}
	for _, redir := range stmt.Redirs {
		name, ok := s.word(redir.Word)
		if !ok {
			continue
		}
		switch redir.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
			s.filesystem(Write, name, false)
		case syntax.RdrIn:
			s.filesystem(Read, name, false)
		default:
			s.report.unknown("The redirection requires additional analysis")
		}
	}
	switch cmd := stmt.Cmd.(type) {
	case nil:
	case *syntax.CallExpr:
		s.call(cmd)
	case *syntax.BinaryCmd:
		s.statement(cmd.X)
		s.statement(cmd.Y)
	case *syntax.Block:
		for _, child := range cmd.Stmts {
			s.statement(child)
		}
	case *syntax.Subshell:
		s.report.unknown("Subshell state requires additional analysis")
		for _, child := range cmd.Stmts {
			s.statement(child)
		}
	case *syntax.IfClause:
		// Inspect both branches. Do not execute conditions or assume one branch.
		for _, child := range cmd.Cond {
			s.statement(child)
		}
		// Mutually exclusive branches start from the same post-condition state.
		// Afterwards retain both mutation sets as possible prior side effects.
		before := append([]string(nil), s.mutated...)
		for _, child := range cmd.Then {
			s.statement(child)
		}
		then := append([]string(nil), s.mutated[len(before):]...)
		s.mutated = before
		if cmd.Else != nil {
			s.statement(&syntax.Stmt{Cmd: cmd.Else})
		}
		s.mutated = append(s.mutated, then...)
	default:
		s.report.unknown("The shell construct has unresolved effects")
	}
}

func (s *analysis) word(word *syntax.Word) (string, bool) {
	if !s.step() {
		return "", false
	}
	if word == nil {
		s.report.unknown("A shell word is missing")
		return "", false
	}
	var value strings.Builder
	known := true
	var parts func([]syntax.WordPart, bool)
	parts = func(items []syntax.WordPart, quoted bool) {
		for _, item := range items {
			switch p := item.(type) {
			case *syntax.Lit:
				if strings.Contains(p.Value, "\\") || (!quoted && strings.ContainsAny(p.Value, "*?[]~{}")) {
					known = false
					s.report.unknown("Shell expansion requires additional analysis")
				}
				value.WriteString(p.Value)
			case *syntax.SglQuoted:
				if p.Dollar {
					known = false
					s.report.unknown("Escaped shell strings require additional analysis")
				}
				value.WriteString(p.Value)
			case *syntax.DblQuoted:
				parts(p.Parts, true)
			case *syntax.ParamExp:
				known = false
				if sensitive.MatchString(p.Param.Value) || s.tainted[p.Param.Value] {
					s.report.add(Effect{Kind: Disclose, Classification: CredentialExposure, Reason: "Sensitive environment data enters a command argument or output"})
				} else {
					s.report.unknown("A variable's value or effects are unresolved")
				}
			case *syntax.CmdSubst:
				known = false
				s.report.unknown("Command substitution has unresolved output")
				for _, child := range p.Stmts {
					s.statement(child)
				}
			default:
				known = false
				s.report.unknown("Dynamic shell evaluation has unresolved effects")
			}
		}
	}
	parts(word.Parts, false)
	s.inspectLiteral(value.String())
	return value.String(), known
}

func (s *analysis) step() bool {
	s.steps++
	if s.steps <= 4096 {
		return true
	}
	if !s.exhausted {
		s.exhausted = true
		s.report.unknown("The action exceeded the local structural analysis budget")
	}
	return false
}

func (s *analysis) call(call *syntax.CallExpr) {
	for _, assign := range call.Assigns {
		s.report.unknown("Assignment-dependent shell state requires additional analysis")
		if assign.Name != nil && assign.Value != nil {
			tainted := sensitive.MatchString(assign.Name.Value)
			syntax.Walk(assign.Value, func(n syntax.Node) bool {
				if p, ok := n.(*syntax.ParamExp); ok && (sensitive.MatchString(p.Param.Value) || s.tainted[p.Param.Value]) {
					tainted = true
				}
				return true
			})
			if tainted {
				s.tainted[assign.Name.Value] = true
			}
			s.word(assign.Value)
		}
	}
	if len(call.Args) == 0 {
		return
	}
	args := make([]string, 0, len(call.Args))
	known := true
	bracketTest := call.Args[0].Lit() == "["
	for i, word := range call.Args {
		// Standalone bracket-test delimiters are syntax, not glob patterns.
		if bracketTest && ((i == 0 && word.Lit() == "[") || (i == len(call.Args)-1 && word.Lit() == "]")) {
			args = append(args, word.Lit())
			continue
		}
		value, ok := s.word(word)
		known = known && ok
		args = append(args, value)
	}
	if !known {
		return
	}
	name := args[0]
	args = args[1:]
	// Shell initialization and PATH are authority-bearing. Refuse executables
	// resolved into the workspace or an arbitrary user-controlled directory.
	builtins := map[string]bool{"echo": true, "printf": true, "pwd": true, "true": true, "false": true, ":": true, "test": true, "[": true}
	if !builtins[name] {
		resolved, err := exec.LookPath(name)
		resolved = filepath.Clean(resolved)
		canonical, canonicalErr := filepath.EvalSymlinks(resolved)
		if err != nil || canonicalErr != nil || (filepath.Dir(canonical) != "/bin" && filepath.Dir(canonical) != "/usr/bin") {
			s.report.unknown("The executable is not a verified system utility")
			return
		}
		info, err := os.Stat(canonical)
		if err != nil || !trustedSystemFile(info) {
			s.report.unknown("The system utility cannot be verified")
			return
		}
		s.report.Evidence = append(s.report.Evidence, Evidence{Path: canonical, Exists: true, Info: info})
		name = filepath.Base(resolved)
	}
	switch name {
	case "true", "false", ":", "pwd":
		if len(args) > 0 {
			s.report.unknown("Unexpected utility arguments")
		}
	case "echo", "printf":
		// Literal data only; dynamic expansions were inspected above.
	case "test", "[":
		if len(args) > 0 && args[len(args)-1] == "]" {
			args = args[:len(args)-1]
		}
		if len(args) == 2 && (args[0] == "-e" || args[0] == "-f" || args[0] == "-s" || args[0] == "-d") {
			s.filesystem(Inspect, args[1], false)
		} else {
			s.report.unknown("The test expression is unsupported")
		}
	case "touch", "rm", "unlink", "cat", "head", "tail", "wc":
		kind := Read
		if name == "touch" {
			kind = Write
		}
		if name == "rm" || name == "unlink" {
			kind = Delete
		}
		recursive := false
		options := true
		var targets []string
		for _, arg := range args {
			if options && arg == "--" {
				options = false
				continue
			}
			if options && strings.HasPrefix(arg, "-") && arg != "-" {
				if name == "rm" {
					if arg == "--recursive" {
						recursive = true
						continue
					}
					if arg == "--force" {
						continue
					}
					valid := len(arg) > 1 && !strings.HasPrefix(arg, "--")
					for _, flag := range arg[1:] {
						if flag == 'r' || flag == 'R' {
							recursive = true
						} else if flag != 'f' && flag != 'v' && flag != 'i' {
							valid = false
						}
					}
					if valid {
						continue
					}
				}
				s.report.unknown("Utility option semantics are unsupported")
				continue
			}
			if arg == "-" {
				s.report.unknown("Standard input has unresolved provenance")
				continue
			}
			targets = append(targets, arg)
		}
		for _, target := range targets {
			s.filesystem(kind, target, recursive)
		}
		if len(targets) == 0 {
			s.report.unknown("The utility has no resolved file targets")
		}
	case "sh", "bash":
		if len(args) == 2 && args[0] == "-c" {
			s.shell(args[1])
			return
		}
		if len(args) != 1 || strings.HasPrefix(args[0], "-") {
			s.report.unknown("Shell invocation options require additional analysis")
			return
		}
		path, info, ok := s.target(args[0])
		if s.previouslyMutated(path) {
			s.report.unknown("An earlier operation can change the script before execution")
		}
		if !ok || info == nil || !info.Mode().IsRegular() || info.Size() > 64*1024 || !within(s.root, path) || protectedPath(path) {
			s.report.unknown("The script cannot be inspected as an ordinary workspace file")
			return
		}
		data, err := readBoundedFile(path, info)
		if err != nil {
			s.report.unknown("The script could not be read")
			return
		}
		s.report.Evidence = append(s.report.Evidence, Evidence{Path: path, Exists: true, Info: info, ContentDigest: digest(data)})
		s.report.add(Effect{Kind: Execute, Target: path, Classification: Ordinary, Reason: "The current shell script content was inspected"})
		s.shell(string(data))
	case "cp", "mv":
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		if len(args) != 2 || strings.HasPrefix(args[0], "-") {
			s.report.unknown("Copy or move options require additional analysis")
			return
		}
		s.filesystem(Read, args[0], false)
		if name == "mv" {
			s.filesystem(Delete, args[0], false)
		}
		// Directory destinations imply another path, so they stay unknown until
		// an analyzer can resolve that effective destination as well.
		s.filesystem(Write, args[1], false)
	case "curl":
		// Network credentials, redirects, config files and request side effects
		// are not inferred safe from a URL. Inspect literal upload sources while
		// retaining uncertainty for the entire invocation.
		s.report.add(Effect{Kind: Transmit, Classification: Unknown, Reason: "Network destination and request effects require additional analysis"})
		for i, arg := range args {
			if i > 0 && (args[i-1] == "-T" || args[i-1] == "--upload-file") {
				s.filesystem(Read, arg, false)
			}
			if strings.HasPrefix(arg, "@") {
				s.filesystem(Read, strings.TrimPrefix(arg, "@"), false)
			}
		}
	default:
		for _, analyzer := range s.engine.Analyzers {
			if effects, ok := analyzer.AnalyzeCall(Call{Executable: name, Args: args}); ok {
				if len(effects) == 0 {
					s.report.unknown("The installed analyzer returned no effect evidence")
				}
				for _, effect := range effects {
					if !effect.valid() {
						s.report.unknown("The installed analyzer returned invalid effect evidence")
						continue
					}
					s.report.add(effect)
				}
				return
			}
		}
		s.report.unknown("The executable's effects are not yet supported")
	}
}
