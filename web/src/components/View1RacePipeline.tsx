import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Download,
  Play,
  Activity,
  X,
  Clock,
  ShieldCheck,
  RotateCcw,
} from 'lucide-react';
import type { ContainmentBridge, DriftIncident, RemediationItem, TraceEvent } from '../types';
import {
  computeRipeningBridgeStyle,
  formatBlockerTemplate,
  formatDurationSeconds,
  formatTraceStepSummary,
  shortHash,
} from '../lib/templates';

interface View1RacePipelineProps {
  remediations: RemediationItem[];
  bridges: ContainmentBridge[];
  drifts: DriftIncident[];
  pendingExceptionsCount: number;
  isLiveFeedMode?: boolean;
  nowMs: number;
  onSimulate: (scenario: 'inject-kev' | 'bad-syscall' | 'stateful-ddl' | 'runtime-drift') => Promise<void>;
  onSubmitIntake?: (
    vendor: 'qualys' | 'tenable' | 'rapid7' | 'sarif',
    rawPayload: string,
    intakeToken: string,
    targetService: string,
    distributorId: string
  ) => Promise<RemediationItem[]>;
  onEmergencyRollback: (remediationId: string, reason: string) => Promise<void>;
  onJumpToExceptions: () => void;
}

const STAGES: Array<{
  key: RemediationItem['stage'];
  num: string;
  label: string;
  subtitle: string;
}> = [
  { key: 'INTAKE_REPRO', num: '01', label: 'Intake & Repro', subtitle: 'SARIF -> Zero-Egress Extractor' },
  { key: 'BRIDGED_CONTAINED', num: '02', label: 'Bridged / Contained', subtitle: 'Cilium L7 + Envoy mTLS SLA' },
  { key: 'SHADOW_CANARY', num: '03', label: 'Shadow & Canary', subtitle: '0% -> 10% -> 50% -> 100%' },
  { key: 'VERIFYING_LOCKING', num: '04', label: 'Verifying & Locking', subtitle: 'Twin Replay + Digest Lockout' },
  { key: 'ATTESTED_CLOSED', num: '05', label: 'Attested & Closed', subtitle: 'DSSE + NIST OSCAL 1.1.2 POA&M' },
];

export const View1RacePipeline: React.FC<View1RacePipelineProps> = ({
  remediations,
  bridges,
  drifts,
  pendingExceptionsCount,
  isLiveFeedMode = false,
  nowMs,
  onSimulate,
  onSubmitIntake,
  onEmergencyRollback,
  onJumpToExceptions,
}) => {
  const [selectedItem, setSelectedItem] = useState<RemediationItem | null>(null);
  const [traces, setTraces] = useState<TraceEvent[]>([]);
  const [loadingTraces, setLoadingTraces] = useState(false);
  const [simRunning, setSimRunning] = useState<string | null>(null);
  const [simError, setSimError] = useState<string | null>(null);
  const [rollbackBusy, setRollbackBusy] = useState(false);
  const [rollbackError, setRollbackError] = useState<string | null>(null);
  const [rollbackNotice, setRollbackNotice] = useState<string | null>(null);

  const [showIntakePanel, setShowIntakePanel] = useState(false);
  const [intakeVendor, setIntakeVendor] = useState<'qualys' | 'tenable' | 'rapid7' | 'sarif'>('qualys');
  const [intakeToken, setIntakeToken] = useState<string>(() => sessionStorage.getItem('g1_intake_token') || '');
  const [intakeService, setIntakeService] = useState('payments-ledger-api');
  const [intakeDistributor, setIntakeDistributor] = useState('');
  const [intakePayload, setIntakePayload] = useState(
    '{"hosts":[{"service_id":"payments-ledger-api","asset_key":"win-pay-01","ip":"10.42.8.15","detections":[{"qid":379501,"severity":5,"cvss3_base":9.8,"status":"Active","cisa_kev":true,"cves":["CVE-2026-71001"]},{"qid":99401,"severity":5,"cvss3_base":9.1,"status":"New","cves":[]}]}]}'
  );
  const [intakeBusy, setIntakeBusy] = useState(false);
  const [intakeError, setIntakeError] = useState<string | null>(null);
  const [intakeSuccess, setIntakeSuccess] = useState<string | null>(null);

  const loadSamplePayload = (vendor: 'qualys' | 'tenable' | 'rapid7' | 'sarif') => {
    setIntakeVendor(vendor);
    if (vendor === 'qualys') {
      setIntakePayload(
        '{"hosts":[{"service_id":"payments-ledger-api","asset_key":"win-pay-01","ip":"10.42.8.15","detections":[{"qid":379501,"severity":5,"cvss3_base":9.8,"status":"Active","cisa_kev":true,"cves":["CVE-2026-71001"]},{"qid":99401,"severity":5,"cvss3_base":9.1,"status":"New","cves":[]}]}]}'
      );
    } else if (vendor === 'tenable') {
      setIntakePayload(
        '{"findings":[{"state":"OPEN","severity":"critical","asset":{"ipv4":"10.42.8.22","hostname":"payments-ledger-api"},"plugin":{"id":195201,"cve":["CVE-2026-71002"],"cwe":["CWE-787"],"cvss3_base_score":9.6,"cisa_known_exploited":true}}]}'
      );
    } else if (vendor === 'rapid7') {
      setIntakePayload(
        '{"resources":[{"id":5001,"hostName":"identity-sso-gateway","ip":"10.42.9.10","vulnerabilities":[{"id":"r7-cve-2026-71003","status":"vulnerable","cves":["CVE-2026-71003"],"cwe":"CWE-287","cisaKev":true,"cvss":{"v3":{"score":9.3}}}]}]}'
      );
    } else {
      setIntakePayload(
        '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[{"ruleId":"CVE-2026-71004","level":"error","properties":{"cve_id":"CVE-2026-71004","cwe_id":"CWE-787","cvss_score":9.8,"is_kev":true,"service_id":"payments-ledger-api","exploit_vector":"TLS_HEARTBEAT","affected_port":8443}}]}]}'
      );
    }
  };

  const handleTokenOnlyIntakeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!onSubmitIntake) return;
    setIntakeBusy(true);
    setIntakeError(null);
    setIntakeSuccess(null);
    try {
      sessionStorage.setItem('g1_intake_token', intakeToken);
      const items = await onSubmitIntake(intakeVendor, intakePayload, intakeToken, intakeService, intakeDistributor);
      setIntakeSuccess(
        `Ingested ${items.length} typed finding(s) via token-only /api/v1/intake/${intakeVendor} (0 human signatures required).`
      );
    } catch (err) {
      setIntakeError(err instanceof Error ? err.message : 'Scanner intake failed');
    } finally {
      setIntakeBusy(false);
    }
  };

  useEffect(() => {
    if (!selectedItem) return;
    setLoadingTraces(true);
    fetch(`/api/v1/pipeline/${selectedItem.remediation_id}/traces`)
      .then((r) => r.json())
      .then((data) => setTraces(Array.isArray(data) ? data : []))
      .catch(() => setTraces([]))
      .finally(() => setLoadingTraces(false));
  }, [selectedItem]);

  const runSim = async (sc: 'inject-kev' | 'bad-syscall' | 'stateful-ddl' | 'runtime-drift') => {
    setSimRunning(sc);
    setSimError(null);
    try {
      await onSimulate(sc);
    } catch (err) {
      setSimError(err instanceof Error ? err.message : 'Simulation trigger failed');
    } finally {
      setSimRunning(null);
    }
  };

  const rollbacks = remediations.filter((r) => r.status_health === 'ROLLBACK_FAILED');
  const driftItems = remediations.filter((r) => r.status_health === 'DRIFT_VIOLATION');
  const agingBridges = bridges.filter((b) => {
    if (b.status === 'RETIRED') return false;
    const st = computeRipeningBridgeStyle(b.armed_at, b.sla_minutes, nowMs, b.status);
    return st.ratio >= 0.7;
  });

  const renderTick = (label: string, val: boolean | null) => {
    if (val === true) {
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-medium text-emerald-800 bg-emerald-50 border border-emerald-200 px-1.5 py-0.5 rounded">
          <CheckCircle2 className="w-3 h-3" /> {label}
        </span>
      );
    }
    if (val === false) {
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-red-900 bg-red-50 border border-red-300 px-1.5 py-0.5 rounded">
          <XCircle className="w-3 h-3" /> {label}
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 text-[10px] text-slate-500 bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded">
        {label}
      </span>
    );
  };

  return (
    <div className="space-y-4">
      {/* Top Exceptions, Failures & Live Simulation Trigger Strip */}
      <section aria-label="Exceptions and Simulation Strip" className="bg-white border border-slate-200 rounded p-3.5 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-700 mr-1">
              Exceptions &amp; Failures Strip:
            </span>

            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-xs font-mono font-medium ${
                rollbacks.length > 0
                  ? 'bg-slate-100 border-slate-300 text-slate-800'
                  : 'bg-slate-50 border-slate-200 text-slate-600'
              }`}
            >
              <RotateCcw className="w-3.5 h-3.5 text-slate-500" />
              Safety Rollbacks: {rollbacks.length}
            </span>

            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-xs font-mono font-medium ${
                driftItems.length > 0 || drifts.length > 0
                  ? 'bg-red-50 border-red-200 text-red-900'
                  : 'bg-slate-50 border-slate-200 text-slate-600'
              }`}
            >
              <AlertTriangle className="w-3.5 h-3.5" />
              Drift Re-Arms: {drifts.length}
            </span>

            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-xs font-mono font-medium ${
                agingBridges.length > 0
                  ? 'bg-amber-50 border-amber-200 text-amber-900'
                  : 'bg-slate-50 border-slate-200 text-slate-600'
              }`}
            >
              <Clock className="w-3.5 h-3.5" />
              Ripening Bridges (&gt;=70% SLA): {agingBridges.length}
            </span>

            <button
              type="button"
              onClick={onJumpToExceptions}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-xs font-mono font-medium ${
                pendingExceptionsCount > 0
                  ? 'bg-amber-50 border-amber-200 text-amber-900 hover:bg-amber-100'
                  : 'bg-slate-50 border-slate-200 text-slate-600'
              }`}
            >
              Four-Eyes Hygiene Queue: {pendingExceptionsCount}
            </button>
          </div>

          {/* Token-Only Finder Intake Button + Optional Simulator Fault Drills */}
          <div className="flex flex-wrap items-center gap-2">
            {onSubmitIntake && (
              <button
                type="button"
                onClick={() => setShowIntakePanel((v) => !v)}
                aria-expanded={showIntakePanel}
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded border border-slate-800 bg-slate-800 hover:bg-slate-900 text-white text-xs font-semibold"
              >
                <span>{showIntakePanel ? 'Close Scanner Intake' : 'Ingest Scanner Export (Token-Only)'}</span>
              </button>
            )}

            {!isLiveFeedMode ? (
              <div className="flex flex-wrap items-center gap-1.5 pl-2 border-l border-slate-200">
                <span className="text-[11px] font-mono uppercase text-slate-600 mr-1">Simulator Fault Drills:</span>
                <button
                  type="button"
                  disabled={simRunning !== null}
                  onClick={() => runSim('inject-kev')}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-800 text-xs font-medium disabled:opacity-50"
                >
                  <Play className="w-3 h-3 text-slate-600" />
                  {simRunning === 'inject-kev' ? 'Running Drill...' : 'Drill: KEV Closure'}
                </button>
                <button
                  type="button"
                  disabled={simRunning !== null}
                  onClick={() => runSim('bad-syscall')}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-800 text-xs font-medium disabled:opacity-50"
                >
                  {simRunning === 'bad-syscall' ? 'Testing Canary...' : 'Drill: Bad Syscall'}
                </button>
                <button
                  type="button"
                  disabled={simRunning !== null}
                  onClick={() => runSim('stateful-ddl')}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-800 text-xs font-medium disabled:opacity-50"
                >
                  {simRunning === 'stateful-ddl' ? 'Routing...' : 'Drill: Stateful DDL'}
                </button>
                <button
                  type="button"
                  disabled={simRunning !== null}
                  onClick={() => runSim('runtime-drift')}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-800 text-xs font-medium disabled:opacity-50"
                >
                  {simRunning === 'runtime-drift' ? 'Injecting Drift...' : 'Drill: Runtime Drift'}
                </button>
              </div>
            ) : (
              <div className="text-[11px] font-mono font-medium px-2.5 py-1 rounded border border-slate-200 bg-slate-50 text-slate-700">
                LIVE FEED POSTURE ACTIVE · FAULT-INJECTION DRILLS DISABLED
              </div>
            )}
          </div>
        </div>

        {showIntakePanel && onSubmitIntake && (
          <form
            onSubmit={handleTokenOnlyIntakeSubmit}
            aria-label="Token-Only Scanner Export Intake Form"
            className="border-t border-slate-200 pt-3 mt-2 space-y-2.5 bg-slate-50 p-3 rounded"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-xs font-bold text-slate-900">
                WN-7 Zero-Signature Scanner Intake (`POST /api/v1/intake/{intakeVendor}` · `X-Warrant-Intake-Token` Only)
              </div>
              <span className="text-[11px] font-mono text-slate-600">
                Zero Dual-Key · Zero WebAuthn · Zero Standing Warrant Prerequisite at Arrival
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-2.5">
              <div>
                <label htmlFor="intake-vendor-select" className="block text-[11px] font-semibold text-slate-700 mb-1">
                  Scanner Format
                </label>
                <select
                  id="intake-vendor-select"
                  value={intakeVendor}
                  onChange={(e) => loadSamplePayload(e.target.value as 'qualys' | 'tenable' | 'rapid7' | 'sarif')}
                  className="w-full text-xs border border-slate-300 rounded px-2 py-1.5 bg-white text-slate-900"
                >
                  <option value="qualys">Qualys VMDR (XML / JSON)</option>
                  <option value="tenable">Tenable.io / Tenable.sc (JSON)</option>
                  <option value="rapid7">Rapid7 InsightVM v3 (JSON)</option>
                  <option value="sarif">SARIF 2.1.0 (Trivy / Semgrep)</option>
                </select>
              </div>

              <div>
                <label htmlFor="intake-token-input" className="block text-[11px] font-semibold text-slate-700 mb-1">
                  {isLiveFeedMode ? 'X-Warrant-Intake-Token (Required in Live Mode)' : 'X-Warrant-Intake-Token'}
                </label>
                <input
                  id="intake-token-input"
                  type="password"
                  value={intakeToken}
                  onChange={(e) => setIntakeToken(e.target.value)}
                  placeholder={
                    isLiveFeedMode
                      ? 'Required: paste WARRANT_INTAKE_TOKEN from .env'
                      : 'Optional in offline sandbox; required in live/K8s'
                  }
                  className="w-full text-xs font-mono border border-slate-300 rounded px-2 py-1.5 bg-white text-slate-900"
                />
              </div>

              <div>
                <label htmlFor="intake-service-input" className="block text-[11px] font-semibold text-slate-700 mb-1">
                  Target Service Override
                </label>
                <input
                  id="intake-service-input"
                  type="text"
                  value={intakeService}
                  onChange={(e) => setIntakeService(e.target.value)}
                  className="w-full text-xs font-mono border border-slate-300 rounded px-2 py-1.5 bg-white text-slate-900"
                />
              </div>

              <div>
                <label htmlFor="intake-file-upload" className="block text-[11px] font-semibold text-slate-700 mb-1">
                  Load Export File (XML/JSON)
                </label>
                <input
                  id="intake-file-upload"
                  type="file"
                  accept=".xml,.json,.sarif"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (!f) return;
                    f.text().then((txt) => setIntakePayload(txt));
                  }}
                  className="w-full text-xs text-slate-700"
                />
              </div>
            </div>

            <div>
              <label htmlFor="intake-payload-textarea" className="block text-[11px] font-semibold text-slate-700 mb-1">
                Raw Untrusted Scanner Export (Terminates in Zero-Egress warrant-extractor)
              </label>
              <textarea
                id="intake-payload-textarea"
                rows={3}
                value={intakePayload}
                onChange={(e) => setIntakePayload(e.target.value)}
                className="w-full text-[11px] font-mono border border-slate-300 rounded p-2 bg-white text-slate-900"
              />
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <label htmlFor="intake-distributor-input" className="text-[11px] font-semibold text-slate-700">
                  Optional Distributor ID:
                </label>
                <input
                  id="intake-distributor-input"
                  type="text"
                  value={intakeDistributor}
                  onChange={(e) => setIntakeDistributor(e.target.value)}
                  placeholder="e.g. ms-intune, ansible-awx (leave blank to hold at Bridged)"
                  className="text-xs font-mono border border-slate-300 rounded px-2 py-1 bg-white text-slate-900 w-72"
                />
              </div>
              <button
                type="submit"
                disabled={intakeBusy || !intakePayload.trim()}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-900 text-white text-xs font-semibold disabled:opacity-50"
              >
                {intakeBusy ? 'Sanitizing & Ingesting...' : `Submit ${intakeVendor.toUpperCase()} Intake`}
              </button>
            </div>

            {intakeError && (
              <div role="alert" className="text-xs font-mono bg-red-50 border border-red-300 text-red-900 px-3 py-1.5 rounded">
                INTAKE_ERROR: {intakeError}
              </div>
            )}
            {intakeSuccess && (
              <div role="status" className="text-xs font-mono bg-emerald-50 border border-emerald-300 text-emerald-950 px-3 py-1.5 rounded">
                {intakeSuccess}
              </div>
            )}
          </form>
        )}

        {simError && (
          <div role="alert" className="text-xs font-mono bg-red-50 border border-red-300 text-red-900 px-3 py-1.5 rounded">
            DRILL_NOTICE: {simError}
          </div>
        )}
      </section>

      {/* 5-Stage Horizontal Race Pipeline */}
      <section aria-label="5-Stage Autonomous Race Pipeline" className="grid grid-cols-1 lg:grid-cols-5 gap-3">
        {STAGES.map((stage) => {
          const items = remediations.filter((r) => r.stage === stage.key);
          return (
            <div key={stage.key} className="bg-slate-100/80 border border-slate-200 rounded flex flex-col min-h-[540px]">
              <div className="bg-white border-b border-slate-200 p-3 rounded-t flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-[11px] font-mono font-bold text-slate-400">{stage.num}</span>
                    <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900">{stage.label}</h2>
                  </div>
                  <div className="text-[11px] text-slate-500 mt-0.5">{stage.subtitle}</div>
                </div>
                <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-slate-100 border border-slate-300 text-slate-800">
                  {items.length}
                </span>
              </div>

              <div className="p-2.5 space-y-2.5 flex-1 overflow-y-auto">
                {items.length === 0 && (
                  <div className="text-center py-10 text-xs text-slate-400 font-mono">NO WORKLOADS IN STAGE</div>
                )}

                {items.map((item) => {
                  const isRed =
                    item.status_health === 'ROLLBACK_FAILED' ||
                    item.status_health === 'DRIFT_VIOLATION' ||
                    item.status_health === 'FROZEN';
                  const isEmerald = item.stage === 'ATTESTED_CLOSED';
                  const bridgeStyle = item.bridged_at
                    ? computeRipeningBridgeStyle(
                        item.bridged_at,
                        item.bridge_sla_minutes || 60,
                        nowMs,
                        isEmerald ? 'RETIRED' : item.status_health === 'DRIFT_VIOLATION' ? 'REARMED_DRIFT' : 'ARMED'
                      )
                    : null;

                  let cardBorder = 'border-slate-200 bg-white';
                  if (isRed) cardBorder = 'border-slate-200 border-l-2 border-l-red-700 bg-white';
                  else if (isEmerald) cardBorder = 'border-slate-200 border-l-2 border-l-emerald-700 bg-white';
                  else if (item.stage === 'BRIDGED_CONTAINED') cardBorder = 'border-slate-200 border-l-2 border-l-slate-700 bg-white';

                  return (
                    <div
                      key={item.remediation_id}
                      onClick={() => setSelectedItem(item)}
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') setSelectedItem(item);
                      }}
                      className={`border rounded p-3 hover:border-slate-300 transition cursor-pointer space-y-2 text-left ${cardBorder}`}
                    >
                      <div className="flex items-start justify-between gap-1">
                        <div>
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="text-xs font-mono font-bold text-slate-900">{item.cve_id}</span>
                            {item.is_kev && (
                              <span className="text-[10px] font-mono font-semibold px-1.5 py-0.2 bg-red-50 border border-red-200 text-red-800 rounded">
                                CISA KEV
                              </span>
                            )}
                            {item.finder_vendor && (
                              <span className="text-[10px] font-mono font-semibold px-1.5 py-0.2 bg-slate-100 border border-slate-200 text-slate-700 rounded">
                                {item.finder_vendor}
                              </span>
                            )}
                            {item.cve_mapping_status === 'UNMAPPED_VENDOR_ADVISORY' && (
                              <span className="text-[10px] font-mono font-semibold px-1.5 py-0.2 bg-amber-50 border border-amber-200 text-amber-800 rounded">
                                UNMAPPED ({item.vendor_detection_id || 'VENDOR'})
                              </span>
                            )}
                          </div>
                          <div className="text-xs font-semibold text-slate-800 mt-0.5">{item.service_id}</div>
                        </div>
                        <span className="text-[11px] font-mono font-semibold px-1.5 py-0.5 rounded bg-slate-50 border border-slate-200 text-slate-700">
                          CVSS {item.cvss_score.toFixed(1)}
                        </span>
                      </div>

                      <div className="text-[11px] font-mono text-slate-600 truncate" title={item.package_purl}>
                        {item.package_purl}
                      </div>

                      {item.distributor_id && (
                        <div className="text-[10px] font-mono bg-slate-50 border border-slate-200 rounded px-2 py-1 space-y-0.5">
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-slate-800">WN-8: {item.distributor_id}</span>
                            {item.closure_completeness && (
                              <span
                                className={`px-1.5 py-0.2 rounded font-bold ${
                                  item.closure_completeness === 'FULL'
                                    ? 'bg-emerald-100 text-emerald-900'
                                    : item.closure_completeness === 'PARTIAL'
                                    ? 'bg-amber-100 text-amber-950'
                                    : 'bg-slate-200 text-slate-800'
                                }`}
                              >
                                {item.closure_completeness}
                              </span>
                            )}
                          </div>
                          {(item.targeted_asset_count || 0) > 0 && (
                            <div className="text-slate-600">
                              Landed {item.landed_asset_count || 0}/{item.targeted_asset_count} · RebootWait{' '}
                              {item.reboot_waiting_count || 0} · Pend {item.pending_asset_count || 0} · Fail{' '}
                              {item.failed_asset_count || 0}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Stage-specific deterministic telemetry */}
                      {item.bridged_at && item.stage !== 'ATTESTED_CLOSED' && bridgeStyle && (
                        <div className={`text-[11px] font-mono px-2 py-1 rounded border ${bridgeStyle.badgeClass}`}>
                          <div className="flex items-center justify-between">
                            <span>{bridgeStyle.label}</span>
                            <span className="tabular-nums font-bold">
                              {formatDurationSeconds(bridgeStyle.uptimeSec)} / {item.bridge_sla_minutes}m
                            </span>
                          </div>
                          <div className="w-full h-1.5 bg-slate-900/15 rounded overflow-hidden mt-1">
                            <div
                              className={`h-full ${bridgeStyle.barClass}`}
                              style={{ width: `${Math.min(100, bridgeStyle.ratio * 100)}%` }}
                            />
                          </div>
                        </div>
                      )}

                      {(item.stage === 'SHADOW_CANARY' || item.status_health === 'ROLLBACK_FAILED') && (
                        <div className="space-y-1.5 pt-1 border-t border-slate-200/80">
                          <div className="flex items-center justify-between text-[11px] font-mono">
                            <span>Canary Weight</span>
                            <span className="font-bold">{item.canary_weight}%</span>
                          </div>
                          <div className="flex flex-wrap gap-1">
                            {renderTick('Stateless', item.stateless_passed)}
                            {renderTick('Schema Diff', item.schema_diff_passed)}
                            {renderTick('Syscall Set', item.syscall_diff_passed)}
                          </div>
                        </div>
                      )}

                      {(item.stage === 'VERIFYING_LOCKING' || item.stage === 'ATTESTED_CLOSED') && (
                        <div className="space-y-1 pt-1 border-t border-slate-200/80 text-[11px] font-mono">
                          <div className="flex items-center justify-between">
                            <span className="text-slate-600">Twin Replay:</span>
                            <span className="font-semibold text-emerald-800">{item.twin_replay_status}</span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-slate-600">Pod Digest Sweep:</span>
                            <span className="font-semibold text-emerald-800">
                              {item.pod_sweep_matched}/{item.pod_sweep_total} Match
                            </span>
                          </div>
                          {item.lockout_policy_id && (
                            <div className="text-[10px] text-slate-600 truncate">
                              Lockout: <span className="font-semibold text-slate-900">{item.lockout_policy_id}</span>
                            </div>
                          )}
                        </div>
                      )}

                      {item.blocker_code && (
                        <div className="text-[11px] bg-slate-50 border border-slate-200 text-slate-700 px-2 py-1 rounded font-mono">
                          {formatBlockerTemplate(item.blocker_code)}
                        </div>
                      )}

                      {isEmerald && item.attestation_id && (
                        <div className="pt-1 flex items-center justify-between border-t border-slate-200">
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-800">
                            <ShieldCheck className="w-3.5 h-3.5" /> Attested &amp; Locked
                          </span>
                          <a
                            href={`/api/v1/attestations/${item.attestation_id}/oscal`}
                            onClick={(e) => e.stopPropagation()}
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-900 text-white text-[11px] font-mono font-semibold"
                          >
                            <Download className="w-3 h-3" /> [OSCAL]
                          </a>
                        </div>
                      )}

                      <div className="text-[10px] text-slate-400 font-mono flex items-center justify-between pt-0.5">
                        <span>{item.remediation_id}</span>
                        <span className="underline text-slate-600">Inspect Trace →</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </section>

      {/* Slide-Out Millisecond Execution Trace Drawer */}
      {selectedItem && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Deterministic Execution Trace Drawer"
          className="fixed inset-0 z-50 bg-slate-900/50 flex justify-end"
          onClick={() => setSelectedItem(null)}
        >
          <div
            className="bg-white w-full max-w-2xl h-full shadow-2xl border-l border-slate-300 flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
              <div>
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-slate-800" />
                  <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900">
                    Deterministic Ledger Execution Trace
                  </h3>
                </div>
                <div className="text-xs font-mono text-slate-600 mt-0.5">
                  {selectedItem.remediation_id} · {selectedItem.cve_id} · {selectedItem.service_id} · Warrant:{' '}
                  {selectedItem.warrant_id || 'UNBOUND'}
                </div>
              </div>
              <button
                type="button"
                aria-label="Close execution trace drawer"
                onClick={() => setSelectedItem(null)}
                className="p-1 rounded hover:bg-slate-200 text-slate-600"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-4 bg-slate-100 border-b border-slate-200 grid grid-cols-2 gap-2 text-xs font-mono">
              <div>
                <span className="text-slate-500">Vulnerable Digest:</span>{' '}
                <span className="font-semibold text-red-900">{shortHash(selectedItem.vulnerable_digest, 18)}</span>
              </div>
              <div>
                <span className="text-slate-500">Patched Digest:</span>{' '}
                <span className="font-semibold text-emerald-900">{shortHash(selectedItem.patched_digest, 18)}</span>
              </div>
              <div>
                <span className="text-slate-500">Active Stage:</span>{' '}
                <span className="font-bold">{selectedItem.stage}</span>
              </div>
              <div>
                <span className="text-slate-500">Lockout Policy:</span>{' '}
                <span className="font-bold">{selectedItem.lockout_policy_id || 'PENDING'}</span>
              </div>
              {selectedItem.stage === 'ATTESTED_CLOSED' && selectedItem.status_health !== 'QUARANTINED_ROLLBACK' && (
                <div className="col-span-2 pt-2 border-t border-slate-200 flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[11px] text-slate-700 font-sans">
                    Post-closure functional regression? Execute atomic 3-step Contain-Before-Unban rollback:
                  </span>
                  <button
                    type="button"
                    disabled={rollbackBusy}
                    onClick={async () => {
                      setRollbackBusy(true);
                      setRollbackError(null);
                      setRollbackNotice(null);
                      try {
                        await onEmergencyRollback(
                          selectedItem.remediation_id,
                          'CONSOLE_QUARANTINED_CONTAIN_BEFORE_UNBAN_ROLLBACK'
                        );
                        setRollbackNotice('Executed atomic 3-step Quarantined Rollback (Shield re-armed before digest unban).');
                      } catch (err) {
                        setRollbackError(err instanceof Error ? err.message : 'Quarantined rollback failed');
                      } finally {
                        setRollbackBusy(false);
                      }
                    }}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-red-700 bg-red-600 hover:bg-red-700 text-white text-xs font-bold disabled:opacity-50"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    {rollbackBusy ? 'Rolling Back...' : 'Quarantined Rollback'}
                  </button>
                </div>
              )}
              {rollbackError && (
                <div role="alert" className="col-span-2 p-2 rounded border border-red-400 bg-red-50 text-red-950 text-xs font-mono">
                  {rollbackError}
                </div>
              )}
              {rollbackNotice && (
                <div role="status" className="col-span-2 p-2 rounded border border-emerald-400 bg-emerald-50 text-emerald-950 text-xs font-mono">
                  {rollbackNotice}
                </div>
              )}
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-2.5">
              {loadingTraces ? (
                <div className="text-xs font-mono text-slate-500 py-8 text-center">Loading deterministic trace...</div>
              ) : traces.length === 0 ? (
                <div className="text-xs font-mono text-slate-500 py-8 text-center">No trace events recorded.</div>
              ) : (
                traces.map((t, idx) => (
                  <div key={t.trace_id} className="border border-slate-200 rounded p-3 bg-white space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[11px] font-bold px-1.5 py-0.5 rounded bg-slate-900 text-white">
                          #{idx + 1} · {t.engine}
                        </span>
                        <span className="font-mono font-bold text-slate-900">{t.step_code}</span>
                      </div>
                      <span
                        className={`font-mono text-[11px] font-bold px-2 py-0.5 rounded border ${
                          t.outcome === 'PASS' || t.outcome === 'ATTESTED'
                            ? 'bg-emerald-50 border-emerald-300 text-emerald-900'
                            : 'bg-red-50 border-red-300 text-red-900'
                        }`}
                      >
                        {t.outcome}
                      </span>
                    </div>

                    <div className="text-xs text-slate-700">{formatTraceStepSummary(t)}</div>

                    <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-500 pt-1 border-t border-slate-100">
                      <span>ts: {new Date(t.occurred_at).toISOString()}</span>
                      <span>actor: {t.actor_or_token}</span>
                      <span>sha256: {t.evidence_hash.slice(0, 16)}…</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
