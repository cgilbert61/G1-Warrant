import React, { useState } from 'react';
import { Shield, Lock, AlertTriangle, Code2, X, RotateCcw, Server } from 'lucide-react';
import type {
  AdmissionLockout,
  ContainmentBridge,
  DeploymentOrder,
  DeploymentResult,
  DistributorDescriptor,
  DriftIncident,
} from '../types';
import {
  computeRipeningBridgeStyle,
  formatBridgeBlockerReason,
  formatDurationSeconds,
  shortHash,
} from '../lib/templates';

interface View4ContainmentLockoutProps {
  bridges: ContainmentBridge[];
  lockouts: AdmissionLockout[];
  drifts: DriftIncident[];
  distributors?: DistributorDescriptor[];
  deploymentOrders?: DeploymentOrder[];
  deploymentResults?: DeploymentResult[];
  nowMs: number;
  onRollbackOrder?: (orderId: string, reason: string) => Promise<void>;
}

export const View4ContainmentLockout: React.FC<View4ContainmentLockoutProps> = ({
  bridges,
  lockouts,
  drifts,
  distributors = [],
  deploymentOrders = [],
  deploymentResults = [],
  nowMs,
  onRollbackOrder,
}) => {
  const [manifestModal, setManifestModal] = useState<{ title: string; primary: string; secondary?: string } | null>(
    null
  );
  const [rollbackBusyOrder, setRollbackBusyOrder] = useState<string | null>(null);
  const [rollbackErr, setRollbackErr] = useState<string | null>(null);

  return (
    <div className="space-y-6">
      {/* Real-Time Runtime Drift Alert Banner */}
      {drifts.length > 0 && (
        <div
          role="alert"
          className="bg-red-600 text-white border border-red-800 rounded p-4 shadow-sm flex flex-wrap items-center justify-between gap-3"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-6 h-6 shrink-0 mt-0.5" />
            <div>
              <div className="text-xs font-bold uppercase tracking-wider">
                N3 RUNTIME DRIFT ALERT — BANNED DIGEST INSTANTIATED &amp; AUTO-CONTAINED
              </div>
              <div className="text-xs font-mono mt-1">
                Rogue Pod <strong>{drifts[0].rogue_pod_name}</strong> ({drifts[0].service_id}) instantiated banned{' '}
                {shortHash(drifts[0].detected_digest, 18)} ({drifts[0].cve_id}). Cilium Bridge{' '}
                <strong>{drifts[0].rearmed_bridge_id}</strong> automatically re-armed in{' '}
                <strong>{drifts[0].detection_latency_ms}ms</strong>.
              </div>
            </div>
          </div>
          <span className="font-mono text-xs px-2.5 py-1 rounded bg-red-950/60 border border-red-300 font-bold">
            {drifts.length} DRIFT VIOLATION(S) RECORDED
          </span>
        </div>
      )}

      {/* Active & Historical Containment Bridges Table */}
      <section className="bg-white border border-slate-200 rounded p-4 space-y-3">
        <div className="flex items-center justify-between border-b border-slate-200 pb-2">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-amber-600" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900">
              Multi-Substrate Containment Bridges Matrix (K8s Cilium/Envoy · AWS SG+IMDSv2 · Azure NSG · GCP FW · Linux nftables · Windows WFP)
            </h2>
          </div>
          <span className="text-xs font-mono text-slate-600">
            {bridges.filter((b) => b.status !== 'RETIRED').length} Active / {bridges.length} Total
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-100 border-y border-slate-300 font-mono text-[11px] uppercase text-slate-700">
                <th className="p-2.5">Bridge ID / Type</th>
                <th className="p-2.5">Target Workload</th>
                <th className="p-2.5">Holding CVE</th>
                <th className="p-2.5">Ripening Age vs. SLA</th>
                <th className="p-2.5">Deterministic Blocker Reason</th>
                <th className="p-2.5">Manifests</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {bridges.map((b) => {
                const st = computeRipeningBridgeStyle(b.armed_at, b.sla_minutes, nowMs, b.status);
                return (
                  <tr key={b.bridge_id} className="hover:bg-slate-50">
                    <td className="p-2.5 font-mono">
                      <div className="font-bold text-slate-900">{b.bridge_id}</div>
                      <div className="text-[11px] text-slate-500">
                        {b.bridge_type}
                        {b.substrate_family && b.substrate_family !== 'KUBERNETES' ? ` · ${b.substrate_family}` : ''}
                      </div>
                    </td>
                    <td className="p-2.5 font-mono font-semibold text-slate-900">{b.service_id}</td>
                    <td className="p-2.5 font-mono font-bold text-slate-900">{b.cve_id}</td>
                    <td className="p-2.5">
                      <div className={`inline-flex items-center gap-2 px-2.5 py-1 rounded border font-mono text-[11px] ${st.badgeClass}`}>
                        <span>{st.label}</span>
                        {b.status !== 'RETIRED' && (
                          <span className="font-bold tabular-nums">
                            {formatDurationSeconds(st.uptimeSec)} / {b.sla_minutes}m
                          </span>
                        )}
                      </div>
                      {b.rearmed_count > 0 && (
                        <div className="text-[10px] font-mono text-red-700 font-bold mt-0.5">
                          Re-armed {b.rearmed_count}x on drift
                        </div>
                      )}
                    </td>
                    <td className="p-2.5 text-slate-700">{formatBridgeBlockerReason(b)}</td>
                    <td className="p-2.5">
                      <button
                        type="button"
                        onClick={() => {
                          const isNonK8s = b.substrate_family && b.substrate_family !== 'KUBERNETES';
                          setManifestModal({
                            title: isNonK8s
                              ? `Multi-Substrate Shield (${b.substrate_family} · ${b.bridge_type}) — ${b.bridge_id} (${b.service_id})`
                              : `Declarative Containment Manifests — ${b.bridge_id} (${b.service_id})`,
                            primary: b.native_shield_manifest || b.cilium_manifest_yaml,
                            secondary: isNonK8s
                              ? `# Symmetric Stage 04 Retirement Spec\n${b.native_retire_spec || b.k8s_netpol_yaml}\n# Canonical Bridge Summary JSON\n${b.envoy_filter_json}`
                              : `# Kubernetes NetworkPolicy\n${b.k8s_netpol_yaml}\n# Envoy HTTP RBAC + mTLS Filter JSON\n${b.envoy_filter_json}`,
                          });
                        }}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-300 bg-white hover:bg-slate-100 font-mono text-[11px] font-semibold text-slate-800"
                      >
                        <Code2 className="w-3.5 h-3.5" /> {b.substrate_family && b.substrate_family !== 'KUBERNETES' ? 'Inspect Rules' : 'Inspect YAML'}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* Bottom Split: Permanent Admission Lockout Register + Live Runtime Drift Monitor */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <section className="xl:col-span-2 bg-white border border-slate-200 rounded p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-200 pb-2">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-emerald-700" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900">
                Permanent Admission Lockout Register (ValidatingAdmissionPolicy + Gatekeeper)
              </h2>
            </div>
            <span className="text-xs font-mono text-slate-500">{lockouts.length} Digests Permanently Banned</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-100 border-y border-slate-300 font-mono text-[11px] uppercase text-slate-700">
                  <th className="p-2.5">Policy Name</th>
                  <th className="p-2.5">Workload &amp; CVE</th>
                  <th className="p-2.5">Permanently Banned SHA-256 Digest</th>
                  <th className="p-2.5">Drift Hits</th>
                  <th className="p-2.5">Policy Code</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {lockouts.map((lo) => (
                  <tr key={lo.lockout_id} className="hover:bg-slate-50">
                    <td className="p-2.5 font-mono font-bold text-emerald-900">{lo.policy_name}</td>
                    <td className="p-2.5 font-mono">
                      <div className="font-semibold text-slate-900">{lo.service_id}</div>
                      <div className="text-[11px] text-slate-500">{lo.cve_id}</div>
                    </td>
                    <td className="p-2.5 font-mono text-[11px] text-red-900 break-all">{lo.banned_digest}</td>
                    <td className="p-2.5 font-mono font-bold">
                      <span className={lo.drift_count > 0 ? 'text-red-700' : 'text-emerald-800'}>{lo.drift_count}</span>
                    </td>
                    <td className="p-2.5">
                      <button
                        type="button"
                        onClick={() =>
                          setManifestModal({
                            title: `ValidatingAdmissionPolicy & Gatekeeper Rego — ${lo.policy_name}`,
                            primary: lo.vap_manifest_yaml,
                            secondary: lo.gatekeeper_rego,
                          })
                        }
                        className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-300 bg-white hover:bg-slate-100 font-mono text-[11px] font-semibold"
                      >
                        <Code2 className="w-3 h-3" /> Policy
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Runtime Drift Monitor */}
        <section className="bg-white border border-slate-200 rounded p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-200 pb-2">
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900">
              N3 Continuous Runtime Drift Monitor
            </h2>
            <span className="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-800">
              <span className="w-2 h-2 rounded-full bg-emerald-600 animate-ping" /> 200ms Watch
            </span>
          </div>
          <p className="text-xs text-slate-600">
            Watches live cluster pods against banned SHA-256 digests and re-applies Cilium containment bridges within sub-second latency if autoscaler/CI drift occurs.
          </p>
          {drifts.length === 0 ? (
            <div className="p-4 rounded bg-emerald-50 border border-emerald-200 text-emerald-900 text-xs font-mono">
              ZERO RUNTIME DRIFT VIOLATIONS — 100% of live pods comply with Admission Lockout Register.
            </div>
          ) : (
            <div className="space-y-2">
              {drifts.map((d) => (
                <div key={d.incident_id} className="p-3 rounded border border-red-400 bg-red-50 text-xs font-mono space-y-1">
                  <div className="flex justify-between font-bold text-red-950">
                    <span>{d.rogue_pod_name}</span>
                    <span>{d.detection_latency_ms}ms Re-Arm</span>
                  </div>
                  <div className="text-[11px] text-red-900">
                    {d.service_id} · {d.cve_id} · Bridge {d.rearmed_bridge_id}
                  </div>
                  <div className="text-[10px] text-slate-600 truncate">Digest: {d.detected_digest}</div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* WN-8 Governed Distributor Orders & WORM Pre-Recorded Native Rollback Ledger */}
      <section className="bg-white border border-slate-200 rounded p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-2">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-slate-800" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900">
              WN-8 Distributor Translation Orders &amp; Pre-Recorded Native Rollback Specs ({distributors.length} Registered Translators)
            </h2>
          </div>
          <span className="text-xs font-mono text-slate-500">
            {deploymentOrders.length} WORM Order(s) · {deploymentResults.length} Result Snapshot(s)
          </span>
        </div>

        {rollbackErr && (
          <div role="alert" className="p-2.5 rounded border border-red-300 bg-red-50 text-xs font-mono text-red-900">
            ROLLBACK_ERROR: {rollbackErr}
          </div>
        )}

        {deploymentOrders.length === 0 ? (
          <div className="p-3 rounded bg-slate-50 border border-slate-200 text-xs font-mono text-slate-600">
            No outbound WN-8 DeploymentOrders dispatched yet. Registered distributor families ({distributors.length} translators): K8s/Cilium, GitOps (ArgoCD/Flux), Microsoft Estate (Intune/MECM/WSUS), Linux (AWX/Satellite), macOS (Jamf Pro), Cloud (AWS SSM/Azure Update/GCP OS Config), and Multi-Platform (Tanium/Ivanti/Automox).
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-100 border-y border-slate-300 font-mono text-[11px] uppercase text-slate-700">
                  <th className="p-2.5">Order ID / Distributor</th>
                  <th className="p-2.5">Workload · CVE · Warrant</th>
                  <th className="p-2.5">Target Assets</th>
                  <th className="p-2.5">Pre-Recorded Native Rollback</th>
                  <th className="p-2.5">Latest Landing Status</th>
                  <th className="p-2.5">Symmetric Rollback</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {deploymentOrders.map((ord) => {
                  const latestRes = deploymentResults.find((r) => r.order_id === ord.order_id);
                  return (
                    <tr key={ord.order_id} className="hover:bg-slate-50">
                      <td className="p-2.5 font-mono">
                        <div className="font-bold text-slate-900">{ord.order_id}</div>
                        <div className="text-[11px] text-slate-600">{ord.distributor_id}</div>
                      </td>
                      <td className="p-2.5 font-mono">
                        <div className="font-semibold text-slate-900">
                          {ord.service_id} · {ord.fix_identity?.cve_id || '—'}
                        </div>
                        <div className="text-[11px] text-slate-500">Warrant: {ord.warrant_id}</div>
                      </td>
                      <td className="p-2.5 font-mono text-[11px] text-slate-700">
                        {ord.target_assets.length} asset(s) · Wave {ord.wave_number}/{ord.total_waves}
                      </td>
                      <td className="p-2.5 font-mono text-[11px] text-slate-800">
                        <div className="font-semibold">{ord.rollback_instruction.strategy}</div>
                        <div className="text-[10px] text-slate-500 truncate max-w-[240px]">
                          {ord.rollback_instruction.uninstall_kb ||
                            ord.rollback_instruction.previous_package_nevra ||
                            shortHash(ord.rollback_instruction.previous_digest, 16)}
                        </div>
                      </td>
                      <td className="p-2.5 font-mono text-[11px]">
                        {latestRes ? (
                          <div>
                            <span className="font-bold text-slate-900">
                              Landed {latestRes.landed_count}/{latestRes.targeted_count}
                            </span>{' '}
                            <span className="text-slate-600">
                              (RebootWait {latestRes.reboot_waiting_count} · Fail {latestRes.failed_count})
                            </span>
                          </div>
                        ) : (
                          <span className="text-slate-500">Wave {ord.wave_number} Dispatched</span>
                        )}
                      </td>
                      <td className="p-2.5">
                        {onRollbackOrder && (
                          <button
                            type="button"
                            disabled={rollbackBusyOrder === ord.order_id}
                            onClick={async () => {
                              setRollbackBusyOrder(ord.order_id);
                              setRollbackErr(null);
                              try {
                                await onRollbackOrder(ord.order_id, 'CONSOLE_DISTRIBUTOR_ROLLBACK');
                              } catch (err) {
                                setRollbackErr(err instanceof Error ? err.message : 'Rollback failed');
                              } finally {
                                setRollbackBusyOrder(null);
                              }
                            }}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded border border-red-300 bg-red-50 hover:bg-red-100 font-mono text-[11px] font-semibold text-red-950 disabled:opacity-50"
                          >
                            <RotateCcw className="w-3 h-3" />
                            {rollbackBusyOrder === ord.order_id ? 'Rolling Back...' : 'Execute Rollback'}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {manifestModal && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="manifest-inspector-title"
          className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4"
          onClick={() => setManifestModal(null)}
        >
          <div
            className="bg-white border border-slate-300 rounded-md shadow-xl max-w-3xl w-full p-5 space-y-3 max-h-[85vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-200 pb-2">
              <h3 id="manifest-inspector-title" className="text-xs font-bold uppercase tracking-wider text-slate-900">{manifestModal.title}</h3>
              <button
                type="button"
                aria-label="Close manifest inspector modal"
                onClick={() => setManifestModal(null)}
                className="text-slate-500 hover:text-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <pre className="p-3 rounded bg-slate-900 text-emerald-200 text-xs font-mono overflow-x-auto">
              {manifestModal.primary}
            </pre>
            {manifestModal.secondary && (
              <pre className="p-3 rounded bg-slate-900 text-slate-200 text-xs font-mono overflow-x-auto">
                {manifestModal.secondary}
              </pre>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
