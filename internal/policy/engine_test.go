package policy

import (
	"context"
	"testing"
)

func TestPolicyEngine_AC5GateAndVerify(t *testing.T) {
	ctx := context.Background()
	eng, err := NewEngine(ctx)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ac5Dec, err := eng.EvalAC5(ctx, AC5Input{
		Slot1: SignerInput{
			PrincipalID:    "usr-alice-so",
			Email:          "alice@g1163rt.sec",
			KeyFingerprint: "fp-1",
			Role:           "SERVICE_OWNER",
		},
		Slot2: SignerInput{
			PrincipalID:    "usr-bob-ao",
			Email:          "bob@g1163rt.sec",
			KeyFingerprint: "fp-2",
			Role:           "AUTHORIZING_OFFICIAL",
		},
		NowUnix:                1700000000,
		ExpiresUnix:            1800000000,
		ScopeServices:          []string{"payments-ledger-api"},
		TargetService:          "payments-ledger-api",
		MaxCVSS:                10.0,
		FindingCVSS:            9.8,
		MaxBlastRadiusReplicas: 10,
		TargetReplicas:         4,
	})
	if err != nil || !ac5Dec.Allow {
		t.Fatalf("expected AC5 allow, got dec=%+v err=%v", ac5Dec, err)
	}

	gateDec, err := eng.EvalGate(ctx, GateInput{
		FreezeMode:      "OPERATIONAL",
		ShadowEvaluated: true,
		Service: GateServiceInput{
			TestCoveragePct:            88.0,
			OtelHealthProbes:           true,
			ReadonlyShadowReplica:      true,
			RollbackAutomationVerified: true,
			ReadOnlyRootFilesystem:     true,
			NoExecTmpMounts:            true,
		},
		Patch: GatePatchInput{
			DDLMigrations:         0,
			ORMModelMutations:     0,
			SerializationBreaks:   0,
			APIBackwardCompatible: true,
		},
		Shadow: GateShadowInput{
			SchemaBreakingDiffs: 0,
			StatusCodeDriftPct:  0.0,
			P99LatencyMs:        35.0,
			MaxP99LatencyMs:     100.0,
			BaselineSyscalls:    []string{"read", "write", "futex"},
			CanarySyscalls:      []string{"read", "write", "futex", "execve"},
		},
	})
	if err != nil {
		t.Fatalf("EvalGate failed: %v", err)
	}
	if !gateDec.TriggerCanaryRollback || len(gateDec.UnauthorizedSyscalls) != 1 || gateDec.UnauthorizedSyscalls[0] != "execve" {
		t.Fatalf("expected execve rollback trigger, got %+v", gateDec)
	}

	// 1. Differential Twin Positive Control (Tier 2 Assurance)
	verDec, err := eng.EvalVerify(ctx, VerifyInput{
		HasSignedProbe:           true,
		UnpatchedTwinStatus:      "EXPLOIT_SUCCEEDED",
		TwinReplayStatus:         "EXPLOIT_BLOCKED",
		ProvenanceVerified:       true,
		AttestedPods:             4,
		TotalPods:                4,
		VulnerableSymbolsLoaded:  0,
		AdmissionLockoutEnforced: true,
		WarrantReverified:        true,
	})
	if err != nil || !verDec.AllowBridgeRetirement || !verDec.AllowAttestationMint || verDec.AssuranceTier != "ASSURANCE_TIER_2_DIFFERENTIAL_TWIN" {
		t.Fatalf("expected Tier 2 differential twin closure allow, got %+v err=%v", verDec, err)
	}

	// 2. Broken PoC False-Negative Trap: probe failed against unpatched twin -> MUST block closure!
	brokenDec, err := eng.EvalVerify(ctx, VerifyInput{
		HasSignedProbe:           true,
		UnpatchedTwinStatus:      "EXPLOIT_BLOCKED",
		TwinReplayStatus:         "EXPLOIT_BLOCKED",
		ProvenanceVerified:       true,
		AttestedPods:             4,
		TotalPods:                4,
		VulnerableSymbolsLoaded:  0,
		AdmissionLockoutEnforced: true,
		WarrantReverified:        true,
	})
	if err != nil || brokenDec.AllowAttestationMint {
		t.Fatalf("expected broken probe failing positive control to block closure, got %+v err=%v", brokenDec, err)
	}

	// 3. Passive Provenance + 100% Pod Digest Closure (Tier 1 Assurance when no weaponized PoC exists)
	passiveDec, err := eng.EvalVerify(ctx, VerifyInput{
		HasSignedProbe:           false,
		TwinReplayStatus:         "NO_PROBE_PASSIVE_ONLY",
		ProvenanceVerified:       true,
		AttestedPods:             4,
		TotalPods:                4,
		VulnerableSymbolsLoaded:  0,
		AdmissionLockoutEnforced: true,
		WarrantReverified:        true,
	})
	if err != nil || !passiveDec.AllowAttestationMint || passiveDec.AssuranceTier != "ASSURANCE_TIER_1_PASSIVE_DIGEST_SBOM" {
		t.Fatalf("expected Tier 1 passive digest closure allow, got %+v err=%v", passiveDec, err)
	}
}
