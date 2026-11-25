package agentcp

import (
	"testing"
	"time"
)

func TestActionBudgetTrackerPerRemediationAndRollingWindow(t *testing.T) {
	now := time.Now().UTC()
	tr := NewActionBudgetTracker(2, 3, 5*time.Minute)

	rem, maxRem, win, maxWin := tr.Snapshot("agent-1", "rem-1", now)
	if rem != 0 || maxRem != 2 || win != 0 || maxWin != 3 {
		t.Fatalf("unexpected initial snapshot: rem=%d/%d win=%d/%d", rem, maxRem, win, maxWin)
	}

	tr.Record("agent-1", "rem-1", now)
	tr.Record("agent-1", "rem-1", now.Add(10*time.Second))
	rem, _, win, _ = tr.Snapshot("agent-1", "rem-1", now.Add(20*time.Second))
	if rem != 2 || win != 2 {
		t.Fatalf("expected rem=2 win=2, got rem=%d win=%d", rem, win)
	}

	// Advancing beyond rolling window expires window count while preserving remediation count
	rem, _, win, _ = tr.Snapshot("agent-1", "rem-1", now.Add(6*time.Minute))
	if rem != 2 || win != 0 {
		t.Fatalf("expected rem=2 win=0 after window expiry, got rem=%d win=%d", rem, win)
	}

	// Runtime limit update
	tr.SetLimits(5, 10)
	_, maxRem, _, maxWin = tr.Snapshot("agent-1", "rem-1", now.Add(6*time.Minute))
	if maxRem != 5 || maxWin != 10 {
		t.Fatalf("expected updated limits 5/10, got %d/%d", maxRem, maxWin)
	}
}
