package extractor

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// IsolationCheckResult records the outcome of one startup isolation self-test check.
type IsolationCheckResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// IsolationSelfTestReport aggregates all startup isolation checks for warrant-extractor.
type IsolationSelfTestReport struct {
	Passed bool                   `json:"passed"`
	Checks []IsolationCheckResult `json:"checks"`
}

// IsolationSelfTestConfig controls startup isolation probes for warrant-extractor.
type IsolationSelfTestConfig struct {
	EgressProbeAddr      string
	PostgresProbeAddr    string
	ForbiddenSecretPaths []string
	ProbeTimeout         time.Duration
	Getenv               func(string) string
}

// DefaultIsolationSelfTestConfigFromEnv builds the default startup isolation probe configuration.
func DefaultIsolationSelfTestConfigFromEnv() IsolationSelfTestConfig {
	egressProbe := strings.TrimSpace(os.Getenv("WARRANT_ISOLATION_EGRESS_PROBE"))
	if egressProbe == "" {
		egressProbe = "1.1.1.1:443"
	}
	pgProbe := strings.TrimSpace(os.Getenv("WARRANT_ISOLATION_PG_PROBE"))
	if pgProbe == "" {
		pgProbe = "postgres:5432"
	}
	forbidden := []string{}
	if kp := strings.TrimSpace(os.Getenv("WARRANT_KERNEL_KEY_PATH")); kp != "" {
		forbidden = append(forbidden, kp)
	}
	return IsolationSelfTestConfig{
		EgressProbeAddr:      egressProbe,
		PostgresProbeAddr:    pgProbe,
		ForbiddenSecretPaths: forbidden,
		ProbeTimeout:         750 * time.Millisecond,
		Getenv:               os.Getenv,
	}
}

// ShouldEnforceIsolationSelfTestFromEnv reports whether warrant-extractor must fail closed on startup isolation checks.
func ShouldEnforceIsolationSelfTestFromEnv() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WARRANT_EXTRACTOR_ENFORCE_ISOLATION")))
	switch v {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	default:
		return strings.EqualFold(strings.TrimSpace(os.Getenv("WARRANT_CLUSTER_DRIVER")), "kubernetes")
	}
}

// RunIsolationSelfTest empirically verifies that warrant-extractor cannot reach external egress,
// cannot reach PostgreSQL, and cannot read forbidden control-plane secret files.
func RunIsolationSelfTest(ctx context.Context, cfg IsolationSelfTestConfig) (*IsolationSelfTestReport, error) {
	timeout := cfg.ProbeTimeout
	if timeout <= 0 {
		timeout = 750 * time.Millisecond
	}
	getenv := cfg.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	_ = getenv

	rep := &IsolationSelfTestReport{Passed: true}
	var failures []string

	// Check 1: Zero external egress
	if addr := strings.TrimSpace(cfg.EgressProbeAddr); addr != "" {
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			rep.Passed = false
			msg := fmt.Sprintf("egress probe unexpectedly connected to %s", addr)
			failures = append(failures, msg)
			rep.Checks = append(rep.Checks, IsolationCheckResult{Name: "zero_egress", Passed: false, Detail: msg})
		} else {
			rep.Checks = append(rep.Checks, IsolationCheckResult{Name: "zero_egress", Passed: true, Detail: "egress blocked: " + err.Error()})
		}
	}

	// Check 2: No direct PostgreSQL reachability
	if addr := strings.TrimSpace(cfg.PostgresProbeAddr); addr != "" {
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			rep.Passed = false
			msg := fmt.Sprintf("postgres probe unexpectedly connected to %s", addr)
			failures = append(failures, msg)
			rep.Checks = append(rep.Checks, IsolationCheckResult{Name: "no_postgres_access", Passed: false, Detail: msg})
		} else {
			rep.Checks = append(rep.Checks, IsolationCheckResult{Name: "no_postgres_access", Passed: true, Detail: "postgres unreachable: " + err.Error()})
		}
	}

	// Check 3: Forbidden secret paths must be unreadable
	for _, p := range cfg.ForbiddenSecretPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := os.ReadFile(p); err == nil {
			rep.Passed = false
			msg := fmt.Sprintf("forbidden secret file %q is readable by warrant-extractor", p)
			failures = append(failures, msg)
			rep.Checks = append(rep.Checks, IsolationCheckResult{Name: "secret_unreadable:" + p, Passed: false, Detail: msg})
		} else {
			rep.Checks = append(rep.Checks, IsolationCheckResult{Name: "secret_unreadable:" + p, Passed: true, Detail: "unreadable as expected"})
		}
	}

	if !rep.Passed {
		return rep, fmt.Errorf("isolation self-test failed: %s", strings.Join(failures, "; "))
	}
	return rep, nil
}
