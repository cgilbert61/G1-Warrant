import React, { useState } from 'react';
import { GitCompare, Server, CheckCircle2, XCircle, Search, AlertOctagon } from 'lucide-react';
import type { EstateService, RemediationItem, ShadowComparisonReport } from '../types';
import { formatActionTemplate, shortHash } from '../lib/templates';

interface View3ShadowEstateProps {
  shadowRuns: ShadowComparisonReport[];
  estate: EstateService[];
  remediations: RemediationItem[];
}

export const View3ShadowEstate: React.FC<View3ShadowEstateProps> = ({
  shadowRuns,
  estate,
  remediations,
}) => {
  const [activeTab, setActiveTab] = useState<'SHADOW' | 'ESTATE'>('SHADOW');
  const [selectedRunId, setSelectedRunId] = useState<string>(shadowRuns[0]?.run_id || '');
  const [searchQuery, setSearchQuery] = useState('');

  const selectedRun = shadowRuns.find((r) => r.run_id === selectedRunId) || shadowRuns[0] || null;
  const linkedRemediation = selectedRun
    ? remediations.find((rem) => rem.remediation_id === selectedRun.remediation_id)
    : undefined;

  const filteredEstate = estate.filter(
    (s) =>
      s.service_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.display_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.namespace.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 border-b border-slate-300 pb-2">
        <button
          type="button"
          onClick={() => setActiveTab('SHADOW')}
          className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-t text-xs font-bold uppercase tracking-wider border-b-2 ${
            activeTab === 'SHADOW'
              ? 'border-slate-900 text-slate-900 bg-white'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <GitCompare className="w-4 h-4" /> Tab A — Differential Shadow Inspector
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('ESTATE')}
          className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-t text-xs font-bold uppercase tracking-wider border-b-2 ${
            activeTab === 'ESTATE'
              ? 'border-slate-900 text-slate-900 bg-white'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Server className="w-4 h-4" /> Tab B — Estate Readiness Scorecard ({estate.filter((s) => s.eligible).length}/
          {estate.length} Eligible)
        </button>
      </div>

      {activeTab === 'SHADOW' ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* Left Pane: Canary & Rollback Run Selector */}
          <div className="lg:col-span-4 bg-white border border-slate-200 rounded p-3 space-y-2 max-h-[700px] overflow-y-auto">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-800 border-b border-slate-200 pb-2">
              Shadow &amp; Canary Runs ({shadowRuns.length})
            </div>
            {shadowRuns.length === 0 && (
              <div className="text-xs font-mono text-slate-500 py-6 text-center">No shadow runs recorded yet.</div>
            )}
            {shadowRuns.map((run) => {
              const active = selectedRun?.run_id === run.run_id;
              return (
                <button
                  key={run.run_id}
                  type="button"
                  onClick={() => setSelectedRunId(run.run_id)}
                  className={`w-full text-left p-2.5 rounded border space-y-1 transition ${
                    active
                      ? 'border-slate-900 bg-slate-100'
                      : run.passed
                      ? 'border-slate-200 bg-white hover:bg-slate-50'
                      : 'border-red-300 bg-red-50/50 hover:bg-red-50'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="font-bold text-slate-900">{run.service_id}</span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                        run.passed
                          ? 'bg-emerald-50 border-emerald-300 text-emerald-900'
                          : 'bg-red-600 border-red-700 text-white'
                      }`}
                    >
                      {run.passed ? `PASS (${run.stage_weight}%)` : `ROLLED BACK (${run.stage_weight}%)`}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-600 flex justify-between">
                    <span>{run.remediation_id}</span>
                    <span>p99: {run.canary_latency.p99_ms.toFixed(1)}ms</span>
                  </div>
                  {!run.passed && run.failure_code && (
                    <div className="text-[10px] font-mono text-red-900 font-semibold truncate">
                      {run.failure_code}
                    </div>
                  )}
                </button>
              );
            })}
          </div>

          {/* Right Pane: Split-Pane Differential Inspector */}
          <div className="lg:col-span-8 space-y-4">
            {!selectedRun ? (
              <div className="bg-white border border-slate-200 rounded p-8 text-center text-xs font-mono text-slate-500">
                Select a Shadow/Canary run on the left to inspect differential telemetry.
              </div>
            ) : (
              <>
                {/* 1. Patch Statelessness & Shadow Isolation Breakdown */}
                <div className="bg-white border border-slate-200 rounded p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-2">
                    <div>
                      <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900">
                        N2 Patch Statelessness &amp; Shadow Isolation Contract
                      </h3>
                      <div className="text-[11px] font-mono text-slate-500">
                        Run {selectedRun.run_id} · Service {selectedRun.service_id} · Stage {selectedRun.stage_weight}%
                      </div>
                    </div>
                    {!selectedRun.passed && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-red-600 text-white text-xs font-mono font-bold">
                        <AlertOctagon className="w-3.5 h-3.5" /> {selectedRun.failure_code}
                      </span>
                    )}
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                    <div className="p-2 rounded bg-slate-50 border border-slate-200">
                      <div className="text-[10px] text-slate-500">DDL Migrations</div>
                      <div className="font-bold text-slate-900">
                        {linkedRemediation?.patch_metadata?.ddl_migrations ?? 0}
                      </div>
                    </div>
                    <div className="p-2 rounded bg-slate-50 border border-slate-200">
                      <div className="text-[10px] text-slate-500">ORM Model Mutations</div>
                      <div className="font-bold text-slate-900">
                        {linkedRemediation?.patch_metadata?.orm_model_mutations ?? 0}
                      </div>
                    </div>
                    <div className="p-2 rounded bg-slate-50 border border-slate-200">
                      <div className="text-[10px] text-slate-500">Read-Only Shadow DB</div>
                      <div className="font-bold text-emerald-800">
                        {selectedRun.readonly_db_bound ? 'BOUND (RO)' : 'UNBOUND'}
                      </div>
                    </div>
                    <div className="p-2 rounded bg-slate-50 border border-slate-200">
                      <div className="text-[10px] text-slate-500">Outbound Mutation Sink</div>
                      <div className="font-bold text-emerald-800">
                        {selectedRun.outbound_mutation_sink_active ? 'ISOLATED' : 'INACTIVE'}
                      </div>
                    </div>
                  </div>
                </div>

                {/* 2. Normalized HTTP JSON Schema Diff */}
                <div className="bg-white border border-slate-200 rounded p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-2">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900">
                      Normalized HTTP JSON Schema Diff (RFC 8785 JCS · Volatiles Masked)
                    </h3>
                    <span className="text-xs font-mono text-slate-600">
                      Breaking Diffs: <strong>{selectedRun.schema_breaking_diffs}</strong> · Status Drift:{' '}
                      <strong>{selectedRun.status_code_drift_pct.toFixed(2)}%</strong>
                    </span>
                  </div>

                  <div className="flex flex-wrap gap-1.5">
                    {(selectedRun.volatile_fields_masked || []).map((vf) => (
                      <span
                        key={vf}
                        className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 border border-slate-300 text-slate-700"
                      >
                        Masked: {vf}
                      </span>
                    ))}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                    <div>
                      <div className="text-[11px] font-bold text-slate-600 mb-1">Baseline JCS Normalized Sample</div>
                      <pre className="p-2.5 rounded bg-slate-900 text-slate-100 overflow-x-auto text-[11px] whitespace-pre-wrap break-all">
                        {selectedRun.normalized_baseline_sample}
                      </pre>
                    </div>
                    <div>
                      <div className="text-[11px] font-bold text-slate-600 mb-1">Canary JCS Normalized Sample</div>
                      <pre className="p-2.5 rounded bg-slate-900 text-emerald-200 overflow-x-auto text-[11px] whitespace-pre-wrap break-all">
                        {selectedRun.normalized_canary_sample}
                      </pre>
                    </div>
                  </div>
                </div>

                {/* 3. Latency Histogram Comparison + Syscall Capability-Set Diff */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-white border border-slate-200 rounded p-4 space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 border-b border-slate-200 pb-2">
                      Latency Distribution (Ceiling: {selectedRun.max_p99_latency_ms}ms)
                    </h3>
                    {(['p50_ms', 'p95_ms', 'p99_ms'] as const).map((metric) => {
                      const bVal = selectedRun.baseline_latency[metric];
                      const cVal = selectedRun.canary_latency[metric];
                      const maxScale = Math.max(selectedRun.max_p99_latency_ms, cVal, 100);
                      return (
                        <div key={metric} className="space-y-1 text-xs font-mono">
                          <div className="flex justify-between">
                            <span className="uppercase font-bold text-slate-700">{metric.replace('_ms', '')}</span>
                            <span>
                              Base {bVal.toFixed(1)}ms vs Canary <strong>{cVal.toFixed(1)}ms</strong>
                            </span>
                          </div>
                          <div className="space-y-1">
                            <div className="w-full h-2 bg-slate-100 rounded overflow-hidden">
                              <div
                                className="h-full bg-slate-500"
                                style={{ width: `${Math.min(100, (bVal / maxScale) * 100)}%` }}
                              />
                            </div>
                            <div className="w-full h-2 bg-slate-100 rounded overflow-hidden">
                              <div
                                className={`h-full ${
                                  cVal > selectedRun.max_p99_latency_ms ? 'bg-red-600' : 'bg-emerald-600'
                                }`}
                                style={{ width: `${Math.min(100, (cVal / maxScale) * 100)}%` }}
                              />
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  <div className="bg-white border border-slate-200 rounded p-4 space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 border-b border-slate-200 pb-2">
                      Linux Syscall Capability-Set Diff (eBPF / Seccomp)
                    </h3>
                    <div className="text-xs text-slate-600">
                      Unauthorized new syscall classes trigger instant canary rollback; benign call-count variance is ignored.
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedRun.canary_syscalls.map((sc) => {
                        const unauthorized = (selectedRun.unauthorized_syscalls || []).includes(sc);
                        return (
                          <span
                            key={sc}
                            className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
                              unauthorized
                                ? 'bg-red-600 border-red-700 text-white font-bold'
                                : 'bg-slate-50 border-slate-200 text-slate-800'
                            }`}
                          >
                            {unauthorized ? `UNAUTHORIZED: ${sc}` : sc}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      ) : (
        /* TAB B: Estate Readiness Scorecard */
        <section className="bg-white border border-slate-200 rounded p-4 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900">
                N2 Estate Autonomous Eligibility Scorecard
              </h2>
              <p className="text-xs text-slate-600">
                Database-backed services qualify for full autonomous rollout when meeting test coverage, OTel probe, read-only shadow, and rollback bars (with stateless patches).
              </p>
            </div>
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
              <input
                id="estate-service-filter"
                aria-label="Filter estate service or namespace"
                type="search"
                placeholder="Filter service or namespace..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1.5 border border-slate-300 rounded text-xs font-mono"
              />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-100 border-y border-slate-300 font-mono text-[11px] uppercase text-slate-700">
                  <th className="p-2.5">Workload / Namespace</th>
                  <th className="p-2.5">Tier &amp; Class</th>
                  <th className="p-2.5">Running Digest</th>
                  <th className="p-2.5">Coverage (&gt;=80%)</th>
                  <th className="p-2.5">OTel Probes</th>
                  <th className="p-2.5">Shadow RO</th>
                  <th className="p-2.5">Rollback Drill</th>
                  <th className="p-2.5">Autonomous Status &amp; Actionable Checklist</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {filteredEstate.map((svc) => (
                  <tr key={svc.service_id} className="hover:bg-slate-50 align-top">
                    <td className="p-2.5">
                      <div className="font-mono font-bold text-slate-900">{svc.service_id}</div>
                      <div className="text-[11px] text-slate-600">
                        {svc.display_name} · ns:<code className="font-mono">{svc.namespace}</code> ({svc.replicas} pods)
                      </div>
                    </td>
                    <td className="p-2.5 font-mono text-[11px]">
                      <div className="font-semibold">{svc.tier}</div>
                      <div className="text-slate-500">{svc.warrant_class}</div>
                    </td>
                    <td className="p-2.5 font-mono text-[11px] text-slate-700">{shortHash(svc.current_digest, 14)}</td>
                    <td className="p-2.5 font-mono font-bold">
                      <span className={svc.test_coverage_pct >= 80 ? 'text-emerald-800' : 'text-red-700'}>
                        {svc.test_coverage_pct.toFixed(1)}%
                      </span>
                    </td>
                    <td className="p-2.5">
                      {svc.otel_health_probes ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-700" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-600" />
                      )}
                    </td>
                    <td className="p-2.5">
                      {svc.readonly_shadow_replica ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-700" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-600" />
                      )}
                    </td>
                    <td className="p-2.5">
                      {svc.rollback_automation_verified ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-700" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-600" />
                      )}
                    </td>
                    <td className="p-2.5 space-y-1">
                      {svc.eligible ? (
                        <span className="inline-block px-2 py-0.5 rounded border border-emerald-300 bg-emerald-50 text-emerald-900 font-mono text-[11px] font-bold">
                          ELIGIBLE FOR AUTONOMOUS ROLLOUT
                        </span>
                      ) : (
                        <div className="space-y-1">
                          <span className="inline-block px-2 py-0.5 rounded border border-amber-400 bg-amber-50 text-amber-950 font-mono text-[11px] font-bold">
                            GATED — FOUR-EYES REQUIRED
                          </span>
                          <ul className="text-[11px] text-slate-700 list-disc pl-4">
                            {(svc.eligibility_checklist || [])
                              .filter((c) => !c.passed)
                              .map((c) => (
                                <li key={c.criterion_code}>{formatActionTemplate(c)}</li>
                              ))}
                          </ul>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
};
