import type { CeilingException, ContainmentBridge, EligibilityCheckItem, TraceEvent } from '../types';

export function formatDurationSeconds(sec: number): string {
  const s = Math.max(0, Math.floor(sec));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const remS = s % 60;
  if (m < 60) return `${m}m ${remS.toString().padStart(2, '0')}s`;
  const h = Math.floor(m / 60);
  const remM = m % 60;
  return `${h}h ${remM.toString().padStart(2, '0')}m`;
}

export function shortHash(h?: string, len = 14): string {
  if (!h) return '—';
  if (h.startsWith('sha256:')) {
    return 'sha256:' + h.slice(7, 7 + len);
  }
  return h.slice(0, len);
}

/**
 * Deterministic Ripening SLA Color Engine (Section 5 Color Rules):
 * Dynamically shifts active Shield bridge styling from Amber -> Deep Orange -> Ripening Crimson
 * based on bridge uptime relative to SLA minutes.
 */
export function computeRipeningBridgeStyle(armedAtISO: string, slaMinutes: number, nowMs: number, status?: string): {
  ratio: number;
  uptimeSec: number;
  badgeClass: string;
  barClass: string;
  label: string;
} {
  if (status === 'RETIRED') {
    return {
      ratio: 0,
      uptimeSec: 0,
      badgeClass: 'bg-slate-50 border-slate-200 text-slate-700',
      barClass: 'bg-slate-500',
      label: 'RETIRED AFTER LOCKOUT',
    };
  }
  const armedMs = new Date(armedAtISO).getTime();
  const uptimeSec = Math.max(0, Math.floor((nowMs - armedMs) / 1000));
  const slaSec = Math.max(60, slaMinutes * 60);
  const ratio = uptimeSec / slaSec;

  if (status === 'REARMED_DRIFT' || ratio >= 0.95) {
    return {
      ratio,
      uptimeSec,
      badgeClass: 'bridge-sla-box bridge-sla-critical font-semibold',
      barClass: 'bg-red-700',
      label: status === 'REARMED_DRIFT' ? 'RE-ARMED ON DRIFT' : 'SLA BREACH IMMINENT',
    };
  }
  if (ratio >= 0.7) {
    return {
      ratio,
      uptimeSec,
      badgeClass: 'bridge-sla-box bridge-sla-warn font-semibold',
      barClass: 'bg-amber-700',
      label: 'SLA >= 70% ELAPSED',
    };
  }
  if (ratio >= 0.4) {
    return {
      ratio,
      uptimeSec,
      badgeClass: 'bridge-sla-box bridge-sla-neutral font-medium',
      barClass: 'bg-slate-700',
      label: 'AGING CONTAINMENT',
    };
  }
  return {
    ratio,
    uptimeSec,
    badgeClass: 'bridge-sla-box bridge-sla-neutral font-medium',
    barClass: 'bg-slate-600',
    label: 'SHIELD ARMED',
  };
}

/**
 * Deterministic Ceiling Exception Impact String Template (View 2 Cockpit - Zero LLM Prose).
 */
export function formatExceptionImpactTemplate(ex: CeilingException): string {
  const compat = ex.api_backward_compatible ? 'WIRE_COMPATIBLE' : 'WIRE_BREAKING';
  const syscalls = ex.syscall_diff_summary || 'NONE';
  return `Target=${ex.service_id} (${ex.cve_id}) | Trigger=${ex.trigger_code} | DDL=${ex.ddl_count}, ORM=${ex.orm_mutations}, SerBreak=${ex.serialization_breaks} (${compat}) | Shadow=${ex.shadow_replay_status} | SyscallDelta=${syscalls} | ActiveBridge=${ex.active_bridge_id || 'NONE'}`;
}

export function formatBlockerTemplate(code?: string): string {
  if (!code) return 'AUTONOMOUS_PROGRESSION_NOMINAL';
  const map: Record<string, string> = {
    AWAITING_UPSTREAM_VENDOR_PATCH: 'Bridge Armed — Holding Containment Pending Upstream Signed Patch Artifact',
    NO_ACTIVE_WARRANT_FAIL_CLOSED: 'Fail-Closed — No Active Standing Warrant Covers Target Service/CVSS',
    N1_WARRANT_REVERIFY_FAILED: 'Fail-Closed — Warrant Signer Key/Role Revoked in N1 Registry',
    FREEZE_HOLD: 'Asymmetric Emergency Freeze (HOLD) — Canaries Paused; Shield Bridges Active',
    FREEZE_ROLLBACK: 'Asymmetric Emergency Freeze (ROLLBACK) — Canaries Rolled Back; Shield Bridges Active',
    UNMAPPED_FINDING_REQUIRES_CLASS_BINDING:
      'Fail-Visible WN-7 Advisory — Unmapped Vendor Detection Held Behind Containment Bridge Pending Warrant Class Binding',
    PARTIAL_FLEET_CLOSURE:
      'Honest Partial Closure (WN-8) — Partial OSCAL Minted; Containment Bridge Held Active Until Remaining Assets Land/Reboot',
    DISTRIBUTOR_DISPATCH_ONLY:
      'Assurance Tier 0 (WN-8 Dispatch-Only) — Distributor Lacks Per-Asset Confirmation; Containment Bridge Held Active',
  };
  return map[code] || `Gate Policy Trigger: ${code}`;
}

export function formatActionTemplate(item: EligibilityCheckItem): string {
  const actions: Record<string, string> = {
    NONE: 'Meets N2 autonomous bar',
    INCREASE_INTEGRATION_TEST_COVERAGE_TO_80_PCT: 'Raise deterministic integration test line coverage >= 80.0%',
    WIRE_OTEL_GRPC_HTTP_SLI_PROBES: 'Export OpenTelemetry HTTP/gRPC p99 & 5xx health probes to N2',
    PROVISION_READONLY_SHADOW_DB_REPLICA_AND_SINK: 'Bind read-only DB shadow replica + outbound HTTP mutation sink',
    VERIFY_DETERMINISTIC_SUB_10S_ROLLBACK_HOOK: 'Pass automated <10s Kubernetes image rollback drill',
  };
  return actions[item.action_code] || item.action_code;
}

export function formatTraceStepSummary(t: TraceEvent): string {
  const kv = Object.entries(t.fields || {})
    .map(([k, v]) => `${k}=${v}`)
    .join(' · ');
  return kv ? `[${t.engine}] ${t.step_code} -> ${t.outcome} (${kv})` : `[${t.engine}] ${t.step_code} -> ${t.outcome}`;
}

export function formatBridgeBlockerReason(b: ContainmentBridge): string {
  const map: Record<string, string> = {
    AWAITING_UPSTREAM_VENDOR_PATCH: 'Awaiting Upstream Vendor Patch (KEV Contained at L7)',
    AUTONOMOUS_CANARY_IN_PROGRESS: 'Active Containment During Differential Canary Rollout',
    CONTAINED_AWAITING_DISTRIBUTOR_DISPATCH:
      'Shield Armed — Contained Pending Governed WN-8 Distributor Dispatch',
    PATCH_ATTESTED_AND_LOCKED_OUT: 'Retired Following Twin Replay + ValidatingAdmissionPolicy Lockout',
    RUNTIME_DRIFT_BANNED_DIGEST_REARMED: 'Auto Re-Armed by N3 Watcher Due to Runtime Digest Drift',
    NO_VALID_STANDING_WARRANT_FAIL_CLOSED: 'Fail-Closed Containment — Awaiting Co-Signed Standing Warrant',
    UNMAPPED_FINDING_REQUIRES_CLASS_BINDING:
      'Fail-Visible Unmapped Vendor Detection (WN-7) — Contained Pending Explicit Warrant Authorization',
    PARTIAL_FLEET_CLOSURE_BRIDGE_HELD:
      'WN-8 Partial Fleet Landing — Bridge Held Active Until Reboot-Waiting / Pending Assets Converge',
    DISTRIBUTOR_DISPATCH_ONLY_BRIDGE_HELD:
      'WN-8 Dispatch-Only Distributor — Bridge Held Active Until Out-of-Band Per-Asset Verification',
    DRIFT_RECONCILED_AND_REVERIFIED:
      'Retired Following Rogue Pod Eviction & N3 Clean-Digest Re-Verification',
    RETIRED_BY_SUPERSEDING_ATTESTED_CLOSURE:
      'Retired — Superseded by Verified Attested Closure on Workload',
    SUPERSEDED_DUPLICATE_CONTAINMENT_BRIDGE:
      'Retired — Consolidated into Canonical Active Workload Containment Bridge',
  };
  return map[b.blocker_reason_code] || b.blocker_reason_code;
}
