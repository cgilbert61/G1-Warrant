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

	verDec, err := eng.EvalVerify(ctx, VerifyInput{
		TwinReplayStatus:         "EXPLOIT_BLOCKED",
		AttestedPods:             4,
		TotalPods:                4,
		VulnerableSymbolsLoaded:  0,
		AdmissionLockoutEnforced: true,
		WarrantReverified:        true,
	})
	if err != nil || !verDec.AllowBridgeRetirement || !verDec.AllowAttestationMint {
		t.Fatalf("expected verify closure allow, got %+v err=%v", verDec, err)
	}
}
