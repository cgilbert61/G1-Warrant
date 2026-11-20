package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/g1163rt-labs/g1-warrant/internal/gate"
	"github.com/g1163rt-labs/g1-warrant/internal/models"
)

// BuildDeterministicSARIF constructs a valid Wiz/GitHub SARIF 2.1.0 report for seeding and UI simulation triggers.
func BuildDeterministicSARIF(cveID, cweID string, cvss float64, isKEV bool, serviceID, vulnDigest, patchedDigest, vulnSymbol, vector string, port int) []byte {
	doc := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":           "WizFederalScanner",
						"semanticVersion": "4.12.0",
						"rules": []map[string]any{
							{
								"id": cveID,
								"shortDescription": map[string]string{
									"text": "Untrusted scanner description stripped by warrant-extractor",
								},
							},
						},
					},
				},
				"results": []map[string]any{
					{
						"ruleId": cveID,
						"message": map[string]string{
							"text": "Untrusted finding prose stripped by warrant-extractor",
						},
						"locations": []map[string]any{
							{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]string{
										"uri": "usr/lib/libservice.so",
									},
								},
							},
						},
						"properties": map[string]any{
							"cve":               cveID,
							"cwe":               cweID,
							"cvss":              cvss,
							"cisa_kev":          isKEV,
							"service_id":        serviceID,
							"purl":              fmt.Sprintf("pkg:oci/%s@%s", serviceID, vulnDigest),
							"vulnerable_digest": vulnDigest,
							"patched_digest":    patchedDigest,
							"vulnerable_symbol": vulnSymbol,
							"exploit_vector":    vector,
							"affected_port":     port,
						},
					},
				},
			},
		},
	}
	raw, _ := json.Marshal(doc)
	return raw
}

// SeedEnterpriseEstate idempotently seeds principals, dual-signed Standing Warrants,
// the 6-service enterprise estate, historical OSCAL closures, an aging containment bridge,
// and an active Four-Eyes stateful patch exception.
func (o *ControlPlaneOrchestrator) SeedEnterpriseEstate(ctx context.Context) error {
	if os.Getenv("WARRANT_ENABLE_TEST_SMARTCARDS") != "true" {
		log.Printf("WARRANT_ENABLE_TEST_SMARTCARDS is not enabled; skipping built-in sandbox smartcard seed.")
		return nil
	}
	// 1. Register local sandbox PIV/Smartcard principals + Kernel + Publisher (only when WARRANT_ENABLE_TEST_SMARTCARDS=true)
	personas := crypto.BuiltinTestPersonas()
	var alice, bob, elena, marcus crypto.TestSmartcardPersona
	for _, p := range personas {
		if err := o.Store.UpsertPrincipal(ctx, models.Principal{
			PrincipalID:       p.PrincipalID,
			Email:             p.Email,
			DisplayName:       p.DisplayName,
			Role:              p.Role,
			KeyID:             p.KeyID,
			Alg:               p.Alg,
			PublicKeyB64:      p.PublicKeyB64,
			KeyFingerprint:    p.KeyFingerprint,
			AuthenticatorMode: "FIPS_PIV_SMARTCARD",
		}); err != nil {
			return fmt.Errorf("seed principal %s: %w", p.PrincipalID, err)
		}
		switch p.PrincipalID {
		case "usr-alice-so":
			alice = p
		case "usr-bob-ao":
			bob = p
		case "usr-elena-so":
			elena = p
		case "usr-marcus-ao":
			marcus = p
		}
	}

	defaultSBOMMap := map[string][]string{
		"payments-ledger-api":     {"pkg:golang/golang.org/x/net@0.16.0", "pkg:golang/golang.org/x/crypto@0.14.0"},
		"identity-sso-gateway":    {"pkg:golang/google.golang.org/grpc@1.56.2"},
		"fedramp-audit-ingestor":  {"pkg:golang/github.com/open-policy-agent/opa@0.55.0"},
		"checkout-cart-svc":       {"pkg:npm/express@4.18.2"},
		"fulfillment-worker":      {"pkg:pypi/urllib3@2.0.5"},
		"legacy-billing-monolith": {"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
	}

	existingServices, err := o.Store.ListEstateServices(ctx)
	if err != nil {
		return err
	}
	if len(existingServices) > 0 {
		for _, svc := range existingServices {
			if len(svc.SBOMPURLs) == 0 {
				if sbom, ok := defaultSBOMMap[svc.ServiceID]; ok {
					svc.SBOMPURLs = sbom
					_ = o.Store.UpsertEstateService(ctx, svc)
				}
			}
		}
		log.Printf("G1-Warrant estate already seeded (%d workloads); skipping initial seed.", len(existingServices))
		return nil
	}

	// 2. Register the 6 Enterprise Estate Workloads (4 Autonomous-Eligible, 2 Unready)
	stdSyscalls := []string{"accept4", "close", "epoll_ctl", "epoll_wait", "fcntl", "fstat", "futex", "getsockopt", "mmap", "munmap", "nanosleep", "openat", "read", "recvfrom", "rt_sigaction", "rt_sigprocmask", "sendto", "setsockopt", "socket", "write"}
	estate := []models.EstateService{
		{
			ServiceID:                  "payments-ledger-api",
			DisplayName:                "Payments Settlement & Core Ledger API",
			Namespace:                  "fin-core",
			Tier:                       "TIER_1_CRITICAL",
			WarrantClass:               "KEV-TIER1-STATELESS",
			CurrentDigest:              "sha256:a100000000000000000000000000000000000000000000000000000000000001",
			CurrentPURL:                "pkg:oci/payments-ledger-api@sha256:a100000000000000000000000000000000000000000000000000000000000001",
			SBOMPURLs:                  defaultSBOMMap["payments-ledger-api"],
			Replicas:                   6,
			TestCoveragePct:            94.2,
			OtelHealthProbes:           true,
			ReadonlyShadowReplica:      true,
			RollbackAutomationVerified: true,
			ReadOnlyRootFilesystem:     true,
			NoExecTmpMounts:            true,
			AllowedEgressServices:      []string{"postgres-ledger.fin-core.svc.cluster.local", "kube-dns.kube-system.svc.cluster.local"},
			BaselineSyscalls:           stdSyscalls,
		},
		{
			ServiceID:                  "identity-sso-gateway",
			DisplayName:                "Federal PIV / OIDC SSO Federation Gateway",
			Namespace:                  "sec-authn",
			Tier:                       "TIER_1_CRITICAL",
			WarrantClass:               "KEV-TIER1-STATELESS",
			CurrentDigest:              "sha256:b200000000000000000000000000000000000000000000000000000000000002",
			CurrentPURL:                "pkg:oci/identity-sso-gateway@sha256:b200000000000000000000000000000000000000000000000000000000000002",
			SBOMPURLs:                  defaultSBOMMap["identity-sso-gateway"],
			Replicas:                   4,
			TestCoveragePct:            91.8,
			OtelHealthProbes:           true,
			ReadonlyShadowReplica:      true,
			RollbackAutomationVerified: true,
			ReadOnlyRootFilesystem:     true,
			NoExecTmpMounts:            true,
			AllowedEgressServices:      []string{"piv-ocsp.sec-authn.svc.cluster.local", "kube-dns.kube-system.svc.cluster.local"},
			BaselineSyscalls:           stdSyscalls,
		},
		{
			ServiceID:                  "fedramp-audit-ingestor",
			DisplayName:                "FedRAMP High Telemetry & Audit Stream Ingestor",
			Namespace:                  "gov-audit",
			Tier:                       "TIER_1_CRITICAL",
			WarrantClass:               "KEV-TIER1-STATELESS",
			CurrentDigest:              "sha256:c300000000000000000000000000000000000000000000000000000000000003",
			CurrentPURL:                "pkg:oci/fedramp-audit-ingestor@sha256:c300000000000000000000000000000000000000000000000000000000000003",
			SBOMPURLs:                  defaultSBOMMap["fedramp-audit-ingestor"],
			Replicas:                   4,
			TestCoveragePct:            89.5,
			OtelHealthProbes:           true,
			ReadonlyShadowReplica:      true,
			RollbackAutomationVerified: true,
			ReadOnlyRootFilesystem:     true,
			NoExecTmpMounts:            true,
			AllowedEgressServices:      []string{"audit-worm-sink.gov-audit.svc.cluster.local", "kube-dns.kube-system.svc.cluster.local"},
			BaselineSyscalls:           stdSyscalls,
		},
		{
			ServiceID:                  "checkout-cart-svc",
			DisplayName:                "Checkout & Order Orchestration Service",
			Namespace:                  "commerce-edge",
			Tier:                       "TIER_2_PRODUCTION",
			WarrantClass:               "KEV-TIER2-COMMERCE",
			CurrentDigest:              "sha256:d400000000000000000000000000000000000000000000000000000000000004",
			CurrentPURL:                "pkg:oci/checkout-cart-svc@sha256:d400000000000000000000000000000000000000000000000000000000000004",
			SBOMPURLs:                  defaultSBOMMap["checkout-cart-svc"],
			Replicas:                   6,
			TestCoveragePct:            86.0,
			OtelHealthProbes:           true,
			ReadonlyShadowReplica:      true,
			RollbackAutomationVerified: true,
			ReadOnlyRootFilesystem:     true,
			NoExecTmpMounts:            true,
			AllowedEgressServices:      []string{"payments-ledger-api.fin-core.svc.cluster.local", "kube-dns.kube-system.svc.cluster.local"},
			BaselineSyscalls:           stdSyscalls,
		},
		{
			ServiceID:                  "fulfillment-worker",
			DisplayName:                "Warehouse Fulfillment Async Queue Worker",
			Namespace:                  "ops-fulfill",
			Tier:                       "TIER_2_PRODUCTION",
			WarrantClass:               "KEV-TIER2-COMMERCE",
			CurrentDigest:              "sha256:e500000000000000000000000000000000000000000000000000000000000005",
			CurrentPURL:                "pkg:oci/fulfillment-worker@sha256:e500000000000000000000000000000000000000000000000000000000000005",
			SBOMPURLs:                  defaultSBOMMap["fulfillment-worker"],
			Replicas:                   3,
			TestCoveragePct:            71.4,
			OtelHealthProbes:           true,
			ReadonlyShadowReplica:      false,
			RollbackAutomationVerified: true,
			ReadOnlyRootFilesystem:     true,
			NoExecTmpMounts:            true,
			AllowedEgressServices:      []string{"queue-broker.ops-fulfill.svc.cluster.local", "kube-dns.kube-system.svc.cluster.local"},
			BaselineSyscalls:           stdSyscalls,
		},
		{
			ServiceID:                  "legacy-billing-monolith",
			DisplayName:                "Legacy Batch Invoice & Billing Monolith",
			Namespace:                  "fin-legacy",
			Tier:                       "TIER_3_LEGACY",
			WarrantClass:               "LEGACY-CONTAINMENT-ONLY",
			CurrentDigest:              "sha256:f600000000000000000000000000000000000000000000000000000000000006",
			CurrentPURL:                "pkg:oci/legacy-billing-monolith@sha256:f600000000000000000000000000000000000000000000000000000000000006",
			SBOMPURLs:                  defaultSBOMMap["legacy-billing-monolith"],
			Replicas:                   2,
			TestCoveragePct:            54.0,
			OtelHealthProbes:           false,
			ReadonlyShadowReplica:      false,
			RollbackAutomationVerified: false,
			ReadOnlyRootFilesystem:     false,
			NoExecTmpMounts:            false,
			AllowedEgressServices:      []string{"kube-dns.kube-system.svc.cluster.local"},
			BaselineSyscalls:           stdSyscalls,
		},
	}

	for i := range estate {
		gate.GradeServiceReadiness(&estate[i])
		if err := o.Store.UpsertEstateService(ctx, estate[i]); err != nil {
			return err
		}
	}

	// 3. Mint two genuine 2-of-2 DSSE Standing Warrants (AC-5 verified)
	now := time.Now().UTC()
	w1Payload := models.WarrantPayload{
		WarrantID:              "wrt-tier1-kev-001",
		WarrantClass:           "KEV-TIER1-STATELESS",
		ScopeServices:          []string{"payments-ledger-api", "identity-sso-gateway", "fedramp-audit-ingestor"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		AutoRemediateCWEs:      []string{"CWE-209", "CWE-918", "CWE-434"},
		MaxBlastRadiusReplicas: 8,
		AllowStatefulPatches:   false,
		SLABridgeMinutes:       60,
		MaxP99LatencyMs:        110.0,
		IssuedAt:               now.Add(-48 * time.Hour).Format(time.RFC3339),
		ExpiresAt:              now.Add(60 * 24 * time.Hour).Format(time.RFC3339),
	}
	env1, _, err := crypto.NewUnsignedEnvelope(crypto.PayloadTypeWarrant, w1Payload)
	if err != nil {
		return err
	}
	_ = env1.SignEd25519(1, alice.ToPrincipalKey(), alice.PrivateKey)
	_ = env1.SignEd25519(2, bob.ToPrincipalKey(), bob.PrivateKey)
	if _, err := o.N1Warrant.SubmitDualSignedWarrant(ctx, *env1); err != nil {
		return fmt.Errorf("seed warrant 1: %w", err)
	}

	w2Payload := models.WarrantPayload{
		WarrantID:              "wrt-tier2-commerce-002",
		WarrantClass:           "KEV-TIER2-COMMERCE",
		ScopeServices:          []string{"checkout-cart-svc", "fulfillment-worker", "legacy-billing-monolith"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		AutoRemediateCWEs:      []string{"CWE-209", "CWE-918", "CWE-434"},
		MaxBlastRadiusReplicas: 10,
		AllowStatefulPatches:   false,
		AllowGuardedCanary:     true,
		MinCanarySamples:       500,
		StageDwellSeconds:      300,
		SLABridgeMinutes:       60,
		MaxP99LatencyMs:        130.0,
		IssuedAt:               now.Add(-24 * time.Hour).Format(time.RFC3339),
		ExpiresAt:              now.Add(45 * 24 * time.Hour).Format(time.RFC3339),
	}
	env2, _, err := crypto.NewUnsignedEnvelope(crypto.PayloadTypeWarrant, w2Payload)
	if err != nil {
		return err
	}
	_ = env2.SignEd25519(1, elena.ToPrincipalKey(), elena.PrivateKey)
	_ = env2.SignEd25519(2, marcus.ToPrincipalKey(), marcus.PrivateKey)
	if _, err := o.N1Warrant.SubmitDualSignedWarrant(ctx, *env2); err != nil {
		return fmt.Errorf("seed warrant 2: %w", err)
	}

	// 3c. Seed SECRET-ROTATION-STATELESS Standing Warrant for rapid credential/SA-token revocation (<5s response)
	w3Payload := models.WarrantPayload{
		WarrantID:              "wrt-secret-rot-003",
		WarrantClass:           models.WarrantClassSecretRotation,
		ScopeServices:          []string{"payments-ledger-api", "identity-sso-gateway", "checkout-cart-svc", "fulfillment-worker"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		AllowSecretRotation:    true,
		MaxBlastRadiusReplicas: 12,
		SLABridgeMinutes:       15,
		MaxP99LatencyMs:        120.0,
		IssuedAt:               now.Add(-12 * time.Hour).Format(time.RFC3339),
		ExpiresAt:              now.Add(60 * 24 * time.Hour).Format(time.RFC3339),
	}
	env3, _, err := crypto.NewUnsignedEnvelope(crypto.PayloadTypeWarrant, w3Payload)
	if err != nil {
		return err
	}
	_ = env3.SignEd25519(1, alice.ToPrincipalKey(), alice.PrivateKey)
	_ = env3.SignEd25519(2, bob.ToPrincipalKey(), bob.PrivateKey)
	if _, err := o.N1Warrant.SubmitDualSignedWarrant(ctx, *env3); err != nil {
		return fmt.Errorf("seed secret-rotation warrant 3: %w", err)
	}

	// 4. Execute real end-to-end KEV closures + active containment bridge + Four-Eyes exception against live extractor & fleet-sim
	// 4a. Closed KEV POA&M #1: fedramp-audit-ingestor (CVE-2026-31090)
	sarif1 := BuildDeterministicSARIF(
		"CVE-2026-31090", "CWE-400", 9.8, true, "fedramp-audit-ingestor",
		"sha256:c300000000000000000000000000000000000000000000000000000000000003",
		"sha256:c399999999999999999999999999999999999999999999999999999999999903",
		"", "HTTP2_RAPID_RESET", 8443,
	)
	if _, err := o.ExecuteSARIFRemediation(ctx, sarif1, "STATELESS_CLEAN"); err != nil {
		log.Printf("seed closure 1 warning: %v", err)
	}

	// 4b. Closed KEV POA&M #2: checkout-cart-svc (CVE-2026-29844)
	sarif2 := BuildDeterministicSARIF(
		"CVE-2026-29844", "CWE-502", 9.1, true, "checkout-cart-svc",
		"sha256:d400000000000000000000000000000000000000000000000000000000000004",
		"sha256:d499999999999999999999999999999999999999999999999999999999999904",
		"proto_unmarshal_unbounded_depth", "PROTO_DESERIALIZE", 8080,
	)
	if _, err := o.ExecuteSARIFRemediation(ctx, sarif2, "STATELESS_CLEAN"); err != nil {
		log.Printf("seed closure 2 warning: %v", err)
	}

	// 4c. Aging Ripening Shield Bridge: legacy-billing-monolith (CVE-2026-27401, Awaiting Upstream Vendor Patch)
	sarif3 := BuildDeterministicSARIF(
		"CVE-2026-27401", "CWE-917", 9.6, true, "legacy-billing-monolith",
		"sha256:f600000000000000000000000000000000000000000000000000000000000006",
		"", "legacy_jndi_lookup_dispatch", "JNDI_LOOKUP", 8080,
	)
	if items, err := o.ExecuteSARIFRemediation(ctx, sarif3, "UPSTREAM_VENDOR_PENDING"); err == nil && len(items) > 0 {
		// Backdate bridge armed_at to 51 minutes ago (against 60m SLA) so ripening Amber->Crimson SLA indicator is immediately visible
		aged := time.Now().UTC().Add(-51 * time.Minute)
		_, _ = o.Store.Pool().Exec(ctx, `UPDATE containment_bridges SET armed_at = $1 WHERE bridge_id = $2`, aged, items[0].BridgeID)
		_, _ = o.Store.Pool().Exec(ctx, `UPDATE remediation_items SET bridged_at = $1, created_at = $1 WHERE remediation_id = $2`, aged, items[0].RemediationID)
	}

	// 4d. Active Four-Eyes Stateful DDL Exception: identity-sso-gateway (CVE-2026-33912)
	sarif4 := BuildDeterministicSARIF(
		"CVE-2026-33912", "CWE-287", 8.8, false, "identity-sso-gateway",
		"sha256:b200000000000000000000000000000000000000000000000000000000000002",
		"sha256:b288888888888888888888888888888888888888888888888888888888888802",
		"saml_dsig_xpath_eval_v1", "HTTP_PATH_TRAVERSAL", 8443,
	)
	if _, err := o.ExecuteSARIFRemediation(ctx, sarif4, "STATEFUL_DDL"); err != nil {
		log.Printf("seed stateful exception note: %v", err)
	}

	log.Printf("G1-Warrant 6-service enterprise estate seeded deterministically.")
	return nil
}
