package e2e

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/server"
	"github.com/cgilbert61/G1-Warrant/internal/verify"
	"github.com/cgilbert61/G1-Warrant/pkg/warrantsdk"
)

// TestInvariant17_V121RemediationWN1ToWN5 proves end-to-end closure of R2 items WN-1..WN-5:
//  1. WN-1 (Tier-Honest OSCAL Closure Prose & Derived Provenance Verification):
//     - Passive-only closure (NO_PROBE_PASSIVE_ONLY) emits "N3 Passive Artifact Provenance & SBOM Absence Verification"
//       with has-signed-probe=false and provenance-verified=true, never claiming twin exploit replay or EXPLOIT_BLOCKED.
//     - Probed differential twin closure emits "N3 Isolated Ephemeral Twin Exploit Replay" with has-signed-probe=true.
//     - DeriveVerifiedArtifactProvenance derives provenance strictly from recorded ARTIFACT_PROVENANCE_VERIFIED traces
//       matching item.PatchedDigest; missing or mismatched provenance fails closed (PASSIVE_CLOSURE_MISSING_PROVENANCE).
//  2. WN-2 (Cross-Language RFC 8785 JCS IEEE-754 Number Formatting & Shared DSSE Vector):
//     - Verifies the shared Python-minted DSSE envelope over IEEE-754 boundary numbers (1e-6, 1e-7, 1e20, 1e21, -0.0).
//  3. WN-3 (Offline Verifier Signed-Payload Identity Extraction & Outer-Wrapper Reconciliation):
//     - Extracts attestation_id, cve_id, service_id, and warrant_id from the signed OSCAL 1.1.2 POA&M payload,
//       succeeds when outer wrapper fields are stripped, and fails closed (UNSIGNED_WRAPPER_MISMATCH) on tampering.
//  4. WN-4 (Fail-Closed KeyRing Verification & Explicit Embedded-Ring Opt-In TrustBasis):
//     - Fails closed (UNTRUSTED_KEYRING_EMPTY) when no external keyring is passed even if kernel_public_key_ring is
//       embedded in the exported bundle; allows embedded ring only behind AllowEmbeddedKeyRingOptIn=true and surfaces
//       TrustBasis in the verification output.
func TestInvariant17_V121RemediationWN1ToWN5(t *testing.T) {
	h := setupIsolatedHarness(t)
	ctx := h.ctx

	aliceBundle := personaToSignerBundle(h.alice)
	cli := warrantsdk.NewClient(h.httpSrv.URL, warrantsdk.WithSignerBundle(aliceBundle))

	mintDualWarrant(t, h, "wrt-inv17", []string{"payments-ledger-api"}, h.alice, h.bob)

	// -------------------------------------------------------------------------
	// 1. WN-1A: Passive-Only Closure Prose Honesty (NO_PROBE_PASSIVE_ONLY)
	// -------------------------------------------------------------------------
	vulnDigest1 := "sha256:a100000000000000000000000000000000000000000000000000000000000001"
	patchedDigest1 := "sha256:a177777777777777777777777777777777777777777777777777777777777701"
	sarifPassive := server.BuildDeterministicSARIF(
		"CVE-2026-97101", "CWE-000", 8.4, false, "payments-ledger-api",
		vulnDigest1, patchedDigest1, "", "HTTP2_RAPID_RESET", 8080,
	)
	passiveItems, err := h.orch.ExecuteSARIFRemediation(ctx, sarifPassive, "STATELESS_CLEAN")
	if err != nil || len(passiveItems) != 1 {
		t.Fatalf("ExecuteSARIFRemediation(passive) failed: items=%+v err=%v", passiveItems, err)
	}
	passiveItem := passiveItems[0]
	if passiveItem.Stage != models.StageAttestedClosed || passiveItem.AssuranceTier != models.AssuranceTier1PassiveDigestSBOM {
		t.Fatalf("expected passive closure at ASSURANCE_TIER_1_PASSIVE_DIGEST_SBOM, got stage=%s tier=%s blocker=%s",
			passiveItem.Stage, passiveItem.AssuranceTier, passiveItem.BlockerCode)
	}

	type oscalExportWire struct {
		DSSEEnvelope        warrantsdk.Envelope              `json:"dsse_envelope"`
		EntryHash           string                           `json:"entry_hash"`
		KernelPublicKeyRing []warrantsdk.KernelPublicKeyRecord `json:"kernel_public_key_ring"`
	}

	passiveOSCALRaw, err := cli.ExportOSCALBundle(ctx, passiveItem.AttestationID)
	if err != nil {
		t.Fatalf("ExportOSCALBundle(passive): %v", err)
	}
	var passiveExport oscalExportWire
	if err := json.Unmarshal(passiveOSCALRaw, &passiveExport); err != nil {
		t.Fatalf("unmarshal passive OSCAL export: %v", err)
	}
	passivePayloadBytes, err := passiveExport.DSSEEnvelope.DecodePayload()
	if err != nil {
		t.Fatalf("decode passive DSSE payload: %v", err)
	}
	passivePayloadStr := string(passivePayloadBytes)
	if !strings.Contains(passivePayloadStr, "N3 Passive Artifact Provenance & SBOM Absence Verification") {
		t.Fatalf("expected passive OSCAL observation title, got: %s", passivePayloadStr)
	}
	if !strings.Contains(passivePayloadStr, `"name":"has-signed-probe","value":"false"`) {
		t.Fatalf("expected has-signed-probe=false in passive OSCAL payload")
	}
	if !strings.Contains(passivePayloadStr, `"name":"provenance-verified","value":"true"`) {
		t.Fatalf("expected derived provenance-verified=true in passive OSCAL payload")
	}
	if strings.Contains(passivePayloadStr, "Isolated Ephemeral Twin Exploit Replay") ||
		strings.Contains(passivePayloadStr, "verified in isolated twin") ||
		strings.Contains(passivePayloadStr, "EXPLOIT_BLOCKED") {
		t.Fatalf("WN-1 OVERCLAIM VIOLATION: passive OSCAL payload claimed twin exploit replay: %s", passivePayloadStr)
	}

	// -------------------------------------------------------------------------
	// 2. WN-1B: Probed Differential Twin Closure Prose (hasSignedProbe == true)
	// -------------------------------------------------------------------------
	patchedDigest2 := "sha256:a177777777777777777777777777777777777777777777777777777777777702"
	sarifProbed := server.BuildDeterministicSARIF(
		"CVE-2026-97102", "CWE-787", 9.8, true, "payments-ledger-api",
		patchedDigest1, patchedDigest2, "tls_heartbeat_ext_parse_vuln", "TLS_HEARTBEAT", 8443,
	)
	probedItems, err := h.orch.ExecuteSARIFRemediation(ctx, sarifProbed, "STATELESS_CLEAN")
	if err != nil || len(probedItems) != 1 {
		t.Fatalf("ExecuteSARIFRemediation(probed) failed: items=%+v err=%v", probedItems, err)
	}
	probedItem := probedItems[0]
	if probedItem.Stage != models.StageAttestedClosed || probedItem.AssuranceTier != models.AssuranceTier2DifferentialTwin {
		t.Fatalf("expected probed closure at ASSURANCE_TIER_2_DIFFERENTIAL_TWIN, got stage=%s tier=%s",
			probedItem.Stage, probedItem.AssuranceTier)
	}
	probedOSCALRaw, err := cli.ExportOSCALBundle(ctx, probedItem.AttestationID)
	if err != nil {
		t.Fatalf("ExportOSCALBundle(probed): %v", err)
	}
	var probedExport oscalExportWire
	_ = json.Unmarshal(probedOSCALRaw, &probedExport)
	probedPayloadBytes, _ := probedExport.DSSEEnvelope.DecodePayload()
	probedPayloadStr := string(probedPayloadBytes)
	if !strings.Contains(probedPayloadStr, "N3 Isolated Ephemeral Twin Exploit Replay") ||
		!strings.Contains(probedPayloadStr, `"name":"has-signed-probe","value":"true"`) ||
		!strings.Contains(probedPayloadStr, "EXPLOIT_BLOCKED") {
		t.Fatalf("expected probed OSCAL payload to record differential twin replay, got: %s", probedPayloadStr)
	}

	// -------------------------------------------------------------------------
	// 3. WN-1C: Derived Artifact Provenance (No Hardcoded ProvenanceVerified=true)
	// -------------------------------------------------------------------------
	unverifiedItem := &models.RemediationItem{
		RemediationID:    "rem-unverified-prov-wn1",
		CVEID:            "CVE-2026-97103",
		CWEID:            "CWE-000",
		CVSSScore:        8.1,
		ServiceID:        "payments-ledger-api",
		VulnerableDigest: patchedDigest2,
		PatchedDigest:    "sha256:deadbeef00000000000000000000000000000000000000000000000000000099",
		WarrantID:        "wrt-inv17",
		TwinReplayStatus: "NO_PROBE_PASSIVE_ONLY",
		Stage:            models.StageVerifyingLocking,
		StatusHealth:     models.HealthNormal,
	}
	if err := h.store.UpsertRemediation(ctx, unverifiedItem); err != nil {
		t.Fatalf("UpsertRemediation(unverified): %v", err)
	}
	provOK, provHash := h.orch.N3Verify.DeriveVerifiedArtifactProvenance(ctx, unverifiedItem)
	if provOK || provHash != "" {
		t.Fatalf("expected DeriveVerifiedArtifactProvenance=false when no ARTIFACT_PROVENANCE_VERIFIED trace exists, got ok=%t hash=%s", provOK, provHash)
	}
	svcPay, _ := h.store.GetEstateService(ctx, "payments-ledger-api")
	_, mintErr := h.orch.N5Ledger.MintOSCALAttestation(ctx, unverifiedItem, svcPay, &verify.VerificationBundle{
		HasSignedProbe:            false,
		UnpatchedTwinStatus:       "SKIPPED_NO_SIGNED_PROBE",
		ProvenanceVerified:        true, // even if caller tries to pass true, N5 re-derives from recorded trace!
		VulnerablePkgAbsentInSBOM: true,
		PodManifest: []models.PodDigestEntry{
			{PodName: "pay-0", RunningDigest: unverifiedItem.PatchedDigest},
		},
		Lockout: models.AdmissionLockout{PolicyName: "vap-test-wn1", BannedDigest: unverifiedItem.VulnerableDigest},
	})
	if mintErr == nil || !strings.Contains(mintErr.Error(), "PASSIVE_CLOSURE_MISSING_PROVENANCE") {
		t.Fatalf("expected N5 MintOSCALAttestation to fail closed with PASSIVE_CLOSURE_MISSING_PROVENANCE when trace is absent, got: %v", mintErr)
	}

	// -------------------------------------------------------------------------
	// 4. WN-2: Shared Cross-Language RFC 8785 JCS + DSSE Ed25519 Vector Check
	// -------------------------------------------------------------------------
	vecRaw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "rfc8785_jcs_vectors.json"))
	if err != nil {
		t.Fatalf("read shared rfc8785_jcs_vectors.json: %v", err)
	}
	var vecSuite struct {
		CrossLanguageDSSE struct {
			PublicKeyB64 string              `json:"public_key_b64"`
			DSSEEnvelope warrantsdk.Envelope `json:"dsse_envelope"`
		} `json:"cross_language_dsse_vector"`
	}
	if err := json.Unmarshal(vecRaw, &vecSuite); err != nil {
		t.Fatalf("unmarshal shared vectors: %v", err)
	}
	vecBundleBytes, _ := json.Marshal(map[string]any{
		"dsse_envelope": vecSuite.CrossLanguageDSSE.DSSEEnvelope,
	})
	vecRes, err := warrantsdk.VerifyOSCALBundleOffline(vecBundleBytes, vecSuite.CrossLanguageDSSE.PublicKeyB64)
	if err != nil || !vecRes.Valid || vecRes.CVEID != "CVE-2026-41001" {
		t.Fatalf("WN-2 cross-language DSSE verification failed: res=%+v err=%v", vecRes, err)
	}

	// -------------------------------------------------------------------------
	// 5. WN-3 & WN-4: Signed-Payload Identity Reconciliation & Fail-Closed Keyring
	// -------------------------------------------------------------------------
	kernelPubB64 := base64.StdEncoding.EncodeToString(h.orch.N5Ledger.KernelPublicKey().PublicKeyBytes)
	pinnedRes, err := warrantsdk.VerifyOSCALBundleOffline(probedOSCALRaw, kernelPubB64)
	if err != nil || !pinnedRes.Valid || pinnedRes.TrustBasis != warrantsdk.TrustBasisExternalPinnedPubKey {
		t.Fatalf("VerifyOSCALBundleOffline(probed) failed: res=%+v err=%v", pinnedRes, err)
	}
	if pinnedRes.AttestationID != probedItem.AttestationID ||
		pinnedRes.CVEID != "CVE-2026-97102" ||
		pinnedRes.ServiceID != "payments-ledger-api" ||
		pinnedRes.WarrantID != "wrt-inv17" {
		t.Fatalf("unexpected extracted identity from signed OSCAL POA&M payload: %+v", pinnedRes)
	}

	// WN-3A: Stripped outer wrapper still derives all identity fields from signed OSCAL POA&M payload
	strippedExportBytes, _ := json.Marshal(map[string]any{
		"dsse_envelope": probedExport.DSSEEnvelope,
		"entry_hash":    probedExport.EntryHash,
	})
	strippedRes, err := warrantsdk.VerifyOSCALBundleOffline(strippedExportBytes, kernelPubB64)
	if err != nil || strippedRes.CVEID != "CVE-2026-97102" || strippedRes.ServiceID != "payments-ledger-api" || strippedRes.WarrantID != "wrt-inv17" {
		t.Fatalf("expected stripped OSCAL export to populate identity from signed POA&M, got %+v err=%v", strippedRes, err)
	}

	// WN-3B: Spoofing unsigned outer wrapper field MUST fail closed
	var tamperedMap map[string]any
	_ = json.Unmarshal(probedOSCALRaw, &tamperedMap)
	tamperedMap["service_id"] = "spoofed-unsigned-service"
	tamperedBytes, _ := json.Marshal(tamperedMap)
	if _, err := warrantsdk.VerifyOSCALBundleOffline(tamperedBytes, kernelPubB64); err == nil || !strings.Contains(err.Error(), "UNSIGNED_WRAPPER_MISMATCH") {
		t.Fatalf("expected UNSIGNED_WRAPPER_MISMATCH on spoofed outer service_id, got: %v", err)
	}

	// WN-4A: Empty external keyring MUST fail closed even though probedOSCALRaw embeds kernel_public_key_ring
	if len(probedExport.KernelPublicKeyRing) == 0 {
		t.Fatal("expected exported OSCAL bundle to embed kernel_public_key_ring for self-contained archival")
	}
	if _, err := warrantsdk.VerifyOSCALBundleWithKeyRing(probedOSCALRaw, nil); err == nil || !strings.Contains(err.Error(), "UNTRUSTED_KEYRING_EMPTY") {
		t.Fatalf("WN-4 VIOLATION: expected VerifyOSCALBundleWithKeyRing(raw, nil) to fail closed with UNTRUSTED_KEYRING_EMPTY, got: %v", err)
	}

	// WN-4B: External keyring succeeds with EXTERNAL_KEYRING trust basis
	extRing, err := cli.KernelPublicKeyRing(ctx)
	if err != nil {
		t.Fatalf("KernelPublicKeyRing: %v", err)
	}
	extRingRes, err := warrantsdk.VerifyOSCALBundleWithKeyRing(probedOSCALRaw, extRing)
	if err != nil || extRingRes.TrustBasis != warrantsdk.TrustBasisExternalKeyRing {
		t.Fatalf("expected TrustBasisExternalKeyRing, got res=%+v err=%v", extRingRes, err)
	}

	// WN-4C: Explicit opt-in embedded keyring succeeds and names EMBEDDED_BUNDLE_KEYRING_UNTRUSTED_OPT_IN
	optInRes, err := warrantsdk.VerifyOSCALBundleWithKeyRingOpts(probedOSCALRaw, nil, warrantsdk.KeyRingVerificationOptions{
		AllowEmbeddedKeyRingOptIn: true,
	})
	if err != nil || optInRes.TrustBasis != warrantsdk.TrustBasisEmbeddedKeyRingOptIn {
		t.Fatalf("expected TrustBasisEmbeddedKeyRingOptIn, got res=%+v err=%v", optInRes, err)
	}
}
