package extractor

import "testing"

func FuzzParseUntrustedSARIF(f *testing.F) {
	f.Add([]byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"trivy","rules":[]}},"results":[{"ruleId":"CVE-2026-0001","level":"error"}]}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not-json`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseUntrustedSARIF(raw, "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	})
}

func FuzzParseUntrustedDiff(f *testing.F) {
	f.Add([]byte("--- a/main.go\n+++ b/main.go\n@@ -1,2 +1,2 @@\n-old\n+new\n"))
	f.Add([]byte("--- a/schema.sql\n+++ b/schema.sql\n@@ -1 +1 @@\n+DROP TABLE users;\n"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseUntrustedDiff(raw, "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	})
}

func FuzzParseUntrustedSecretFindings(f *testing.F) {
	f.Add([]byte(`[{"RuleID":"aws-access-token","File":"config.env","StartLine":3}]`))
	f.Add([]byte(`{"findings":[]}`))
	f.Add([]byte(`[]`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseUntrustedSecretFindings(raw, "sha256:0000000000000000000000000000000000000000000000000000000000000000", "svc-fuzz")
	})
}
