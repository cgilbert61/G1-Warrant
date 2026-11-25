package agentcp

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxExchangesPerRemediation = 64
	defaultMaxExchangesPerWindow      = 256
	defaultBudgetWindow               = 10 * time.Minute
)

// ActionBudgetTracker enforces hierarchical per-remediation and rolling-window token exchange ceilings
// in N4 (inspired by ARTEX's hierarchical task/intent budgets) so a runaway or compromised worker
// cannot exhaust control-plane capacity or loop infinitely.
type ActionBudgetTracker struct {
	mu                sync.Mutex
	maxPerRemediation int
	maxPerWindow      int
	window            time.Duration
	perRemediation    map[string]int
	perAgentWindow    map[string][]time.Time
}

// NewActionBudgetTracker constructs an ActionBudgetTracker with explicit ceilings and rolling window.
func NewActionBudgetTracker(maxPerRemediation, maxPerWindow int, window time.Duration) *ActionBudgetTracker {
	if window <= 0 {
		window = defaultBudgetWindow
	}
	return &ActionBudgetTracker{
		maxPerRemediation: maxPerRemediation,
		maxPerWindow:      maxPerWindow,
		window:            window,
		perRemediation:    make(map[string]int),
		perAgentWindow:    make(map[string][]time.Time),
	}
}

// NewActionBudgetTrackerFromEnv loads optional ceilings from WARRANT_AGENT_MAX_EXCHANGES_PER_REMEDIATION
// and WARRANT_AGENT_MAX_EXCHANGES_PER_WINDOW (falling back to safe defaults).
func NewActionBudgetTrackerFromEnv() *ActionBudgetTracker {
	maxRem := envIntOrDefault("WARRANT_AGENT_MAX_EXCHANGES_PER_REMEDIATION", defaultMaxExchangesPerRemediation)
	maxWin := envIntOrDefault("WARRANT_AGENT_MAX_EXCHANGES_PER_WINDOW", defaultMaxExchangesPerWindow)
	winSec := envIntOrDefault("WARRANT_AGENT_BUDGET_WINDOW_SECONDS", int(defaultBudgetWindow.Seconds()))
	return NewActionBudgetTracker(maxRem, maxWin, time.Duration(winSec)*time.Second)
}

// SetLimits updates per-remediation and rolling-window exchange ceilings at runtime.
func (b *ActionBudgetTracker) SetLimits(maxPerRemediation, maxPerWindow int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.maxPerRemediation = maxPerRemediation
	b.maxPerWindow = maxPerWindow
}

// Snapshot returns current counts and configured ceilings for (agentID, remediationID) at time now.
func (b *ActionBudgetTracker) Snapshot(agentID, remediationID string, now time.Time) (remCount, maxRem, winCount, maxWin int) {
	if b == nil {
		return 0, 0, 0, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if remediationID != "" {
		remCount = b.perRemediation[remediationKey(agentID, remediationID)]
	}
	winCount = b.pruneWindowLocked(agentID, now)
	return remCount, b.maxPerRemediation, winCount, b.maxPerWindow
}

// Record records a completed token exchange for (agentID, remediationID) at time now.
func (b *ActionBudgetTracker) Record(agentID, remediationID string, now time.Time) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if remediationID != "" {
		b.perRemediation[remediationKey(agentID, remediationID)]++
	}
	b.pruneWindowLocked(agentID, now)
	b.perAgentWindow[agentID] = append(b.perAgentWindow[agentID], now)
}

func (b *ActionBudgetTracker) pruneWindowLocked(agentID string, now time.Time) int {
	ts := b.perAgentWindow[agentID]
	if len(ts) == 0 {
		return 0
	}
	cutoff := now.Add(-b.window)
	kept := ts[:0]
	for _, t := range ts {
		if !t.Before(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(b.perAgentWindow, agentID)
		return 0
	}
	b.perAgentWindow[agentID] = kept
	return len(kept)
}

func remediationKey(agentID, remediationID string) string {
	return agentID + "|" + remediationID
}

func envIntOrDefault(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return def
	}
	return v
}
