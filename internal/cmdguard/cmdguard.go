package cmdguard

import (
	"fmt"
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const (
	// MaxNestedWrapperDepth bounds recursive re-parsing of eval / sh -c / bash -c / env -S payloads.
	MaxNestedWrapperDepth = 3
)

// DefaultDeniedCommandPrefixes lists high-risk destructive, persistence, and exfiltration command prefixes
// blocked across compound Bash ASTs (including inside pipes, subshells, and unwrapped wrappers).
var DefaultDeniedCommandPrefixes = [][]string{
	{"rm", "-rf"},
	{"rm", "-fr"},
	{"mkfs"},
	{"dd"},
	{"chmod", "777"},
	{"chmod", "+s"},
	{"chown"},
	{"nc"},
	{"ncat"},
	{"socat"},
	{"ssh"},
	{"scp"},
	{"rsync"},
	{"iptables"},
	{"nft"},
	{"mount"},
	{"insmod"},
	{"modprobe"},
	{"useradd"},
	{"usermod"},
	{"passwd"},
	{"crontab"},
	{"pkill"},
	{"kill", "-9"},
	{"python", "-c"},
	{"python3", "-c"},
	{"perl", "-e"},
	{"ruby", "-e"},
}

var allowBlockedWrappers = map[string]bool{
	"env":      true,
	"sudo":     true,
	"command":  true,
	"builtin":  true,
	"exec":     true,
	"eval":     true,
	"sh":       true,
	"bash":     true,
	"dash":     true,
	"zsh":      true,
	"ash":      true,
	"xargs":    true,
	"nohup":    true,
	"timeout":  true,
	"stdbuf":   true,
	"nice":     true,
	"flock":    true,
	"parallel": true,
}

// ValidateAllowSimpleCommand enforces a strict single-simple-command allowlist using mvdan.cc/sh/v3/syntax.
// Rejects pipes, command lists (&&, ||, ;), redirections, backgrounding, negation, prefix assignments,
// subshells, parameter/command expansions, wrapper binaries, and flags before subcommands.
func ValidateAllowSimpleCommand(script string, allowedPrefixes [][]string) error {
	trimmed := strings.TrimSpace(script)
	if trimmed == "" {
		return fmt.Errorf("CMDGUARD_EMPTY_COMMAND: command is empty")
	}
	if len(allowedPrefixes) == 0 {
		return fmt.Errorf("CMDGUARD_NO_ALLOWLIST: allowlist is empty (fail-closed)")
	}

	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(trimmed), "cmdguard-allow")
	if err != nil {
		return fmt.Errorf("CMDGUARD_PARSE_ERROR: %w", err)
	}
	if len(file.Stmts) != 1 {
		return fmt.Errorf("CMDGUARD_COMPOUND_REJECTED: allowlist requires exactly 1 simple command, got %d statements", len(file.Stmts))
	}

	stmt := file.Stmts[0]
	if stmt.Negated || stmt.Background || stmt.Coprocess {
		return fmt.Errorf("CMDGUARD_MODIFIER_REJECTED: negated/background/coprocess commands are not permitted by simple allowlist")
	}
	if len(stmt.Redirs) > 0 {
		return fmt.Errorf("CMDGUARD_REDIRECTION_REJECTED: shell redirections are not permitted by simple allowlist")
	}

	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return fmt.Errorf("CMDGUARD_NON_SIMPLE_CMD: compound syntax (%T) is not permitted by simple allowlist", stmt.Cmd)
	}
	if len(call.Assigns) > 0 {
		return fmt.Errorf("CMDGUARD_PREFIX_ASSIGN_REJECTED: inline environment assignments are not permitted by simple allowlist")
	}
	if len(call.Args) == 0 {
		return fmt.Errorf("CMDGUARD_EMPTY_ARGV: command has no argv tokens")
	}

	argv := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		lit, staticOK := wordToStaticLiteral(w)
		if !staticOK {
			return fmt.Errorf("CMDGUARD_DYNAMIC_ARG_REJECTED: parameter/command/arithmetic expansion not permitted by simple allowlist")
		}
		argv = append(argv, lit)
	}

	cmdName := baseCmdName(argv[0])
	if allowBlockedWrappers[cmdName] {
		return fmt.Errorf("CMDGUARD_WRAPPER_REJECTED: wrapper binary %q is not permitted by simple allowlist", cmdName)
	}

	for _, prefix := range allowedPrefixes {
		if matchesExactPrefix(argv, prefix) {
			return nil
		}
	}
	return fmt.Errorf("CMDGUARD_ALLOWLIST_DENIED: command %q does not match any allowed simple-command prefix", argv[0])
}

// ValidateDenyCompound walks every CallExpr in a Bash AST, recursively unwraps wrappers
// (env, sudo, xargs, find -exec, command, builtin, exec, nohup, timeout, nice, stdbuf, flock, parallel)
// and recursively re-parses nested eval / sh -c / bash -c / env -S payloads up to MaxNestedWrapperDepth (3).
func ValidateDenyCompound(script string, deniedPrefixes [][]string) error {
	trimmed := strings.TrimSpace(script)
	if trimmed == "" {
		return nil
	}
	return validateDenyAtDepth(trimmed, deniedPrefixes, 0)
}

// ValidateAgentCommand enforces both the recursive compound denylist and the strict single-simple-command allowlist
// for N4 agent-submitted shell commands.
func ValidateAgentCommand(script string, allowedPrefixes [][]string) error {
	if err := ValidateDenyCompound(script, DefaultDeniedCommandPrefixes); err != nil {
		return err
	}
	return ValidateAllowSimpleCommand(script, allowedPrefixes)
}

// ValidateProvingScriptCommand validates VM_TWIN smoke/acceptance command snippets against the recursive
// compound denylist (blocking destructive, privilege-escalation, or wrapper-obfuscated payloads).
func ValidateProvingScriptCommand(script string) error {
	trimmed := strings.TrimSpace(script)
	if trimmed == "" {
		return nil
	}
	return ValidateDenyCompound(trimmed, DefaultDeniedCommandPrefixes)
}

func validateDenyAtDepth(script string, deniedPrefixes [][]string, depth int) error {
	if depth > MaxNestedWrapperDepth {
		return fmt.Errorf("CMDGUARD_MAX_WRAPPER_DEPTH_EXCEEDED: nested wrapper depth exceeds %d (fail-closed)", MaxNestedWrapperDepth)
	}
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(script), "cmdguard-deny")
	if err != nil {
		return fmt.Errorf("CMDGUARD_PARSE_ERROR: %w", err)
	}

	var firstErr error
	syntax.Walk(file, func(node syntax.Node) bool {
		if firstErr != nil {
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		argv := extractLooseArgv(call.Args)
		if err := inspectArgvChain(argv, deniedPrefixes, depth); err != nil {
			firstErr = err
			return false
		}
		return true
	})
	return firstErr
}

func inspectArgvChain(argv []string, deniedPrefixes [][]string, depth int) error {
	if len(argv) == 0 {
		return nil
	}
	for _, prefix := range deniedPrefixes {
		if matchesExactPrefix(argv, prefix) {
			return fmt.Errorf("CMDGUARD_DENIED_COMMAND: blocked command prefix %q", strings.Join(prefix, " "))
		}
	}

	cmd := baseCmdName(argv[0])
	switch cmd {
	case "eval":
		if len(argv) > 1 {
			nested := strings.Join(argv[1:], " ")
			return validateDenyAtDepth(nested, deniedPrefixes, depth+1)
		}
	case "sh", "bash", "dash", "zsh", "ash":
		if payload, ok := extractShellCPayload(argv[1:]); ok {
			return validateDenyAtDepth(payload, deniedPrefixes, depth+1)
		}
	case "env":
		if payload, ok := extractEnvSPayload(argv[1:]); ok {
			if err := validateDenyAtDepth(payload, deniedPrefixes, depth+1); err != nil {
				return err
			}
		}
		if inner := unwrapEnv(argv[1:]); len(inner) > 0 {
			return inspectArgvChain(inner, deniedPrefixes, depth)
		}
	case "sudo":
		if inner := unwrapSudo(argv[1:]); len(inner) > 0 {
			return inspectArgvChain(inner, deniedPrefixes, depth)
		}
	case "command", "builtin", "exec", "nohup":
		if inner := unwrapSimpleFlags(argv[1:]); len(inner) > 0 {
			return inspectArgvChain(inner, deniedPrefixes, depth)
		}
	case "timeout":
		if inner := unwrapTimeout(argv[1:]); len(inner) > 0 {
			return inspectArgvChain(inner, deniedPrefixes, depth)
		}
	case "nice", "stdbuf", "flock", "parallel":
		if inner := unwrapFlagsWithArg(argv[1:], map[string]bool{"-n": true, "-i": true, "-o": true, "-e": true, "-w": true, "-j": true}); len(inner) > 0 {
			return inspectArgvChain(inner, deniedPrefixes, depth)
		}
	case "xargs":
		if inner := unwrapXargs(argv[1:]); len(inner) > 0 {
			return inspectArgvChain(inner, deniedPrefixes, depth)
		}
	case "find":
		for _, execArgv := range extractFindExecCommands(argv[1:]) {
			if err := inspectArgvChain(execArgv, deniedPrefixes, depth); err != nil {
				return err
			}
		}
	}
	return nil
}

func wordToStaticLiteral(w *syntax.Word) (string, bool) {
	if w == nil || len(w.Parts) == 0 {
		return "", false
	}
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, dp := range p.Parts {
				lit, ok := dp.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(unescapeBashDblQuoted(lit.Value))
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

func unescapeBashDblQuoted(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '"', '\\', '$', '`':
				b.WriteByte(s[i+1])
				i++
				continue
			case '\n':
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func extractLooseArgv(words []*syntax.Word) []string {
	out := make([]string, 0, len(words))
	for _, w := range words {
		if lit, ok := wordToStaticLiteral(w); ok {
			out = append(out, lit)
		} else {
			// Preserve best-effort string representation for non-literal words
			var buf strings.Builder
			_ = syntax.NewPrinter().Print(&buf, w)
			out = append(out, buf.String())
		}
	}
	return out
}

func baseCmdName(tok string) string {
	t := strings.TrimSpace(tok)
	if t == "" {
		return ""
	}
	if strings.Contains(t, "/") {
		return path.Base(t)
	}
	return t
}

func matchesExactPrefix(argv, prefix []string) bool {
	if len(prefix) == 0 || len(argv) < len(prefix) {
		return false
	}
	if baseCmdName(argv[0]) != prefix[0] {
		return false
	}
	for i := 1; i < len(prefix); i++ {
		if argv[i] != prefix[i] {
			return false
		}
	}
	return true
}

func extractShellCPayload(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return "", false
		}
		if a == "-c" || (strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsRune(a[1:], 'c')) {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		}
	}
	return "", false
}

func extractEnvSPayload(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-S" || a == "--split-string" {
			if i+1 < len(args) {
				return args[i+1], true
			}
		}
		if strings.HasPrefix(a, "--split-string=") {
			return strings.TrimPrefix(a, "--split-string="), true
		}
		if strings.HasPrefix(a, "-S") && len(a) > 2 {
			return a[2:], true
		}
	}
	return "", false
}

func unwrapEnv(args []string) []string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return args[i+1:]
		}
		if a == "-u" || a == "-C" || a == "-S" || a == "--unset" || a == "--chdir" || a == "--split-string" {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if strings.Contains(a, "=") {
			continue
		}
		return args[i:]
	}
	return nil
}

func unwrapSudo(args []string) []string {
	valueFlags := map[string]bool{"-u": true, "-g": true, "-C": true, "-h": true, "-p": true, "-r": true, "-t": true, "-U": true, "-D": true}
	return unwrapFlagsWithArg(args, valueFlags)
}

func unwrapXargs(args []string) []string {
	valueFlags := map[string]bool{"-a": true, "-d": true, "-E": true, "-I": true, "-L": true, "-n": true, "-P": true, "-s": true}
	return unwrapFlagsWithArg(args, valueFlags)
}

func unwrapTimeout(args []string) []string {
	valueFlags := map[string]bool{"-k": true, "-s": true, "--kill-after": true, "--signal": true}
	rest := unwrapFlagsWithArg(args, valueFlags)
	// First positional argument to timeout is DURATION; command follows.
	if len(rest) > 1 {
		return rest[1:]
	}
	return nil
}

func unwrapSimpleFlags(args []string) []string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			return args[i+1:]
		}
		if strings.HasPrefix(args[i], "-") {
			continue
		}
		return args[i:]
	}
	return nil
}

func unwrapFlagsWithArg(args []string, valueFlags map[string]bool) []string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return args[i+1:]
		}
		if valueFlags[a] {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return args[i:]
	}
	return nil
}

func extractFindExecCommands(args []string) [][]string {
	var cmds [][]string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-exec", "-execdir", "-ok", "-okdir":
			start := i + 1
			end := start
			for end < len(args) && args[end] != ";" && args[end] != "+" {
				end++
			}
			if end > start {
				cmds = append(cmds, args[start:end])
			}
			i = end
		}
	}
	return cmds
}
