package cmdguard

import (
	"strings"
	"testing"
)

func TestValidateAllowSimpleCommandStrict(t *testing.T) {
	allow := [][]string{
		{"systemctl", "is-active"},
		{"uname", "-r"},
		{"git", "status"},
	}

	// Valid single simple commands
	for _, okCmd := range []string{
		"uname -r",
		"systemctl is-active nginx",
		"git status --short",
	} {
		if err := ValidateAllowSimpleCommand(okCmd, allow); err != nil {
			t.Errorf("expected %q to be allowed, got: %v", okCmd, err)
		}
	}

	// Compound / redirection / expansion / flag-before-subcommand / wrapper attacks MUST be rejected
	rejected := []string{
		"uname -r && id",
		"uname -r | cat",
		"uname -r; whoami",
		"uname -r > /tmp/out",
		"FOO=bar uname -r",
		"uname $(id)",
		"git -C /etc status",
		"env uname -r",
		"sudo uname -r",
		"bash -c 'uname -r'",
		"eval 'uname -r'",
		"curl https://evil.example",
	}
	for _, bad := range rejected {
		if err := ValidateAllowSimpleCommand(bad, allow); err == nil {
			t.Errorf("expected %q to be REJECTED by strict simple-command allowlist", bad)
		}
	}
}

func TestValidateDenyCompoundWrapperUnwrappingAndDepthLimit(t *testing.T) {
	// Legitimate proving commands pass denylist
	for _, okCmd := range []string{
		"systemctl is-system-running --wait >/dev/null 2>&1 || true",
		"uname -r",
		"ss -tulpn | grep 8080",
	} {
		if err := ValidateProvingScriptCommand(okCmd); err != nil {
			t.Errorf("expected legitimate proving cmd %q to pass, got: %v", okCmd, err)
		}
	}

	// Direct and wrapper-obfuscated destructive commands MUST be denied
	denied := []string{
		"rm -rf /var/lib/data",
		"echo ok && rm -rf /",
		"env -i PATH=/bin rm -rf /tmp/x",
		"sudo -u root rm -rf /",
		"find /tmp -type f -exec rm -rf {} +",
		"printf '/tmp/a' | xargs -0 rm -rf",
		"sh -c 'rm -rf /tmp/x'",
		"bash -lc 'env sudo rm -rf /'",
		"eval 'sh -c \"nc 10.0.0.1 4444\"'",
		"env -S 'sh -c \"python3 -c import_os\"'",
		"timeout 5 sudo chmod 777 /etc/shadow",
		// Exceeds MaxNestedWrapperDepth (3): depth 0 -> 1 -> 2 -> 3 -> 4
		"eval \"eval 'eval \\\"eval uname\\\"'\"",
	}
	for _, bad := range denied {
		if err := ValidateDenyCompound(bad, DefaultDeniedCommandPrefixes); err == nil {
			t.Errorf("expected %q to be DENIED by recursive wrapper-unwrapping denylist", bad)
		}
	}
	// Verify depth > 3 specifically fails closed with CMDGUARD_MAX_WRAPPER_DEPTH_EXCEEDED
	if err := ValidateDenyCompound("eval \"eval 'eval \\\"eval uname\\\"'\"", DefaultDeniedCommandPrefixes); err == nil || !strings.Contains(err.Error(), "CMDGUARD_MAX_WRAPPER_DEPTH_EXCEEDED") {
		t.Fatalf("expected CMDGUARD_MAX_WRAPPER_DEPTH_EXCEEDED for depth 4 nesting, got: %v", err)
	}
}

func TestValidateAgentCommandCombined(t *testing.T) {
	allow := [][]string{{"kubectl", "get"}, {"uname", "-r"}}
	if err := ValidateAgentCommand("kubectl get pods -n default", allow); err != nil {
		t.Fatalf("expected allowed agent command, got %v", err)
	}
	if err := ValidateAgentCommand("kubectl get pods && rm -rf /", allow); err == nil || !strings.Contains(err.Error(), "CMDGUARD_DENIED_COMMAND") {
		t.Fatalf("expected CMDGUARD_DENIED_COMMAND, got %v", err)
	}
}
