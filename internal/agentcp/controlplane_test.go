package agentcp

import (
	"testing"

	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
)

func TestMintTaskWarrant_EnforcesTTLCeilingAndAttribution(t *testing.T) {
	signer := crypto.NewSeededDevEd25519Signer("test-seed")
	cp := NewControlPlane(nil, signer, "http://extractor:8090", nil)

	// Reject TTL > 300s
	if _, _, err := cp.MintTaskWarrant("wrt-1", "rem-1", "worker", "svc-a", "ROLLOUT", "s1", "s2", 301); err == nil {
		t.Fatal("expected TTL > 300s to be rejected")
	}
	// Reject unattributed task
	if _, _, err := cp.MintTaskWarrant("", "rem-1", "worker", "svc-a", "ROLLOUT", "s1", "s2", 60); err == nil {
		t.Fatal("expected missing warrant_id to be rejected")
	}
	// Valid 60s task token
	env, payload, err := cp.MintTaskWarrant("wrt-1", "rem-1", "worker", "svc-a", "ROLLOUT", "s1", "s2", 60)
	if err != nil || env == nil || payload.TTLSeconds != 60 {
		t.Fatalf("expected valid task warrant, got err=%v", err)
	}
}

func TestInspectDiffForForbiddenPaths_BlocksNestedBuildAgentFilesTraversalAndSymlinks(t *testing.T) {
	nestedDiff := `diff --git a/services/api/Dockerfile.prod b/services/api/Dockerfile.prod
+++ b/services/api/Dockerfile.prod
+RUN echo hi
diff --git a/cmd/worker/Makefile b/cmd/worker/Makefile
+++ b/cmd/worker/Makefile
diff --git a/packages/web/AGENTS.md b/packages/web/AGENTS.md
+++ b/packages/web/AGENTS.md
diff --git a/apps/auth/GNUmakefile b/apps/auth/GNUmakefile
+++ b/apps/auth/GNUmakefile
diff --git a/sub/pkg/.cursor/rules.md b/sub/pkg/.cursor/rules.md
+++ b/sub/pkg/.cursor/rules.md
diff --git a/src/safe/../../CLAUDE.md b/src/safe/../../CLAUDE.md
+++ b/src/safe/../../CLAUDE.md
diff --git a/src/link_escape b/src/link_escape
new file mode 120000
+++ b/src/link_escape
`
	violations := InspectDiffForForbiddenPaths(nestedDiff, nil)
	if len(violations) < 7 {
		t.Fatalf("expected all 7 nested/traversal/symlink cases blocked, got %d: %v", len(violations), violations)
	}

	// Clean application Go source diff must have zero violations
	cleanDiff := `diff --git a/services/api/handler.go b/services/api/handler.go
--- a/services/api/handler.go
+++ b/services/api/handler.go
@@ -10,1 +10,1 @@
-return oldVal
+return sanitizedVal
`
	if clean := InspectDiffForForbiddenPaths(cleanDiff, []string{"services/api/handler.go"}); len(clean) != 0 {
		t.Fatalf("expected 0 violations on clean source diff, got %v", clean)
	}
}
