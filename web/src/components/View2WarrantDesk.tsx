import React, { useEffect, useState } from 'react';
import { FileCheck2, Gauge, UserX, Usb, CheckCircle2, AlertTriangle, PlugZap, Server } from 'lucide-react';
import type {
  AgentIdentity,
  ApprovalPressureStat,
  BootstrapState,
  CeilingException,
  CommissioningFunction,
  DeclaredCloneSource,
  DSSEEnvelope,
  EstateProposalResponse,
  EstateSelectableServer,
  EstateService,
  EstateSourceDescriptor,
  PendingSponsorTransfer,
  Principal,
  TestSmartcardPersona,
  VendorConnectorConfigStatus,
  WarrantRecord,
} from '../types';
import { formatExceptionImpactTemplate, shortHash } from '../lib/templates';
import { enrollWebAuthnAuthenticator } from '../lib/crypto';
import { DualKeyCeremonyPanel } from './DualKeyCeremonyPanel';
import { AgentGovernancePanel } from './AgentGovernancePanel';

interface WebAuthnEnrollPayload {
  display_name: string;
  email: string;
  role: 'SERVICE_OWNER' | 'AUTHORIZING_OFFICIAL';
  credential_id: string;
  attestation_object: string;
  public_key_spki: string;
  [key: string]: unknown;
}

interface View2WarrantDeskProps {
  warrants: WarrantRecord[];
  exceptions: CeilingException[];
  pressure: ApprovalPressureStat[];
  estate: EstateService[];
  principals: Principal[];
  bootstrapState?: BootstrapState;
  commissioningFunctions?: CommissioningFunction[];
  agents?: AgentIdentity[];
  pendingSponsorTransfers?: PendingSponsorTransfer[];
  estateSources?: EstateSourceDescriptor[];
  vendorConnectors?: VendorConnectorConfigStatus[];
  preferredProposeSource?: string;
  onOpenVendorConnectors?: () => void;
  onRefreshBootstrap?: () => Promise<void>;
  nowMs?: number;
  testPersonas: TestSmartcardPersona[];
  rpId: string;
  smartcardBarEnabled: boolean;
  isMobileViewport: boolean;
  onCreateWarrant: (env: DSSEEnvelope) => Promise<void>;
  onRevokeSigner: (principalId: string, keyFp: string) => Promise<void>;
  onResolveException: (exceptionId: string, decision: 'APPROVED' | 'REJECTED', env: DSSEEnvelope) => Promise<void>;
  onEnrollWebAuthn: (
    payload: WebAuthnEnrollPayload,
    adminToken?: string,
    dualEnv?: DSSEEnvelope
  ) => Promise<void>;
  onRevokeAgent?: (agentId: string, reasonCode: string) => Promise<void>;
  onEmitIGAEvent?: (eventType: string, principalId: string) => Promise<void>;
  onTransferSponsors?: (fn: CommissioningFunction, newPrimarySO: string, newPrimaryAO: string) => Promise<void>;
}

export const View2WarrantDesk: React.FC<View2WarrantDeskProps> = ({
  warrants,
  exceptions,
  pressure,
  estate,
  principals,
  bootstrapState,
  commissioningFunctions = [],
  agents = [],
  pendingSponsorTransfers = [],
  estateSources = [],
  vendorConnectors = [],
  preferredProposeSource,
  onOpenVendorConnectors,
  onRefreshBootstrap,
  nowMs = Date.now(),
  testPersonas,
  rpId,
  smartcardBarEnabled,
  isMobileViewport,
  onCreateWarrant,
  onRevokeSigner,
  onResolveException,
  onEnrollWebAuthn,
  onRevokeAgent,
  onEmitIGAEvent,
  onTransferSponsors,
}) => {
  const [warrantClass, setWarrantClass] = useState('KEV-TIER1-STATELESS');
  const [selectedServices, setSelectedServices] = useState<string[]>(['payments-ledger-api', 'identity-sso-gateway']);
  const [maxCvss, setMaxCvss] = useState(10.0);
  const [maxReplicas, setMaxReplicas] = useState(8);
  const [slaMinutes, setSlaMinutes] = useState(60);
  const [maxP99Ms, setMaxP99Ms] = useState(120);
  const [ttlDays, setTtlDays] = useState(30);
  const [verifyMsg, setVerifyMsg] = useState<Record<string, string>>({});
  const [revokeError, setRevokeError] = useState<string | null>(null);

  // v1.4.0 / v1.4.1 Estate Loader Proposal, Vendor Configurator & Server-to-Twin Selection state
  const [proposeSource, setProposeSource] = useState('k8s-cilium-native');
  const [corroborateScanner, setCorroborateScanner] = useState('');
  const [estateReadTokenInput, setEstateReadTokenInput] = useState('');
  const [driftPolicy, setDriftPolicy] = useState<'RECORD_ONLY' | 'FAIL_CLOSED'>('RECORD_ONLY');
  const [driftTolerancePct, setDriftTolerancePct] = useState(10.0);
  const [estateProposal, setEstateProposal] = useState<EstateProposalResponse | null>(null);
  const [selectedServerIds, setSelectedServerIds] = useState<string[]>([]);
  const [confirmedCloneSources, setConfirmedCloneSources] = useState<DeclaredCloneSource[]>([]);
  const [manualCloneSystem, setManualCloneSystem] = useState('');
  const [manualCloneImage, setManualCloneImage] = useState('');
  const [proposalLoading, setProposalLoading] = useState(false);
  const [proposalError, setProposalError] = useState<string | null>(null);

  useEffect(() => {
    if (preferredProposeSource && preferredProposeSource.trim() !== '') {
      setProposeSource(preferredProposeSource.trim());
    }
  }, [preferredProposeSource]);

  const buildCloneSourcesFromSelectedServers = (
    prop: EstateProposalResponse,
    chosenIds: string[]
  ): DeclaredCloneSource[] => {
    const servers = prop.selectable_servers || [];
    const chosenSet = new Set(chosenIds);
    const nowIso = new Date().toISOString();
    const out: DeclaredCloneSource[] = [];
    for (const sv of servers) {
      if (!chosenSet.has(sv.server_id)) continue;
      out.push({
        source_system: prop.primary_snapshot.source_system,
        image_identity: sv.twin_image_identity,
        platform_family: sv.platform_family,
        selected_server_id: sv.server_id,
        selected_server_hostname: sv.hostname,
        snapshot_sha256: prop.proposed_estate_snapshot_sha256,
        query_identity: prop.primary_snapshot.query_identity,
        source_mode: 'ESTATE_LOADER',
        image_created_at: sv.image_created_at,
        image_age_seconds_at_sign: sv.image_age_seconds,
        declared_at: nowIso,
      });
    }
    return out;
  };

  const handleFetchEstateProposal = async (overrideSource?: string) => {
    const targetSrc = overrideSource || proposeSource;
    setProposalLoading(true);
    setProposalError(null);
    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (estateReadTokenInput.trim() !== '') {
        headers['X-Warrant-Estate-Read-Token'] = estateReadTokenInput.trim();
      }
      const res = await fetch('/api/v1/estate-loader/propose', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          source_system: targetSrc,
          corroborating_scanner: corroborateScanner || undefined,
          warrant_class: warrantClass,
          scope_services: selectedServices,
          estate_drift_policy: driftPolicy,
          estate_drift_tolerance_pct: driftTolerancePct,
        }),
      });
      const body = await res.json();
      if (!res.ok) {
        throw new Error(body.error || body.reason || `HTTP ${res.status}`);
      }
      const prop = body as EstateProposalResponse;
      setEstateProposal(prop);
      const servers: EstateSelectableServer[] = prop.selectable_servers || [];
      if (servers.length > 0) {
        const defaultIds = [servers[0].server_id];
        setSelectedServerIds(defaultIds);
        setConfirmedCloneSources(buildCloneSourcesFromSelectedServers(prop, defaultIds));
      } else {
        setSelectedServerIds([]);
        setConfirmedCloneSources(prop.proposed_clone_sources || []);
      }
      if (prop.recommended_drift_policy) {
        setDriftPolicy(prop.recommended_drift_policy);
      }
    } catch (err) {
      setEstateProposal(null);
      setSelectedServerIds([]);
      setConfirmedCloneSources([]);
      setProposalError(err instanceof Error ? err.message : 'Estate read failed');
    } finally {
      setProposalLoading(false);
    }
  };

  const handleConnectDemoAndBrowse = async () => {
    setProposalLoading(true);
    setProposalError(null);
    try {
      const res = await fetch('/api/v1/estate-loader/connectors/demo-mock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ system_id: proposeSource }),
      });
      const body = await res.json();
      if (!res.ok) {
        throw new Error(body.error || body.reason || `HTTP ${res.status}`);
      }
      if (onRefreshBootstrap) {
        await onRefreshBootstrap();
      }
      await handleFetchEstateProposal(proposeSource);
    } catch (err) {
      setProposalLoading(false);
      setProposalError(err instanceof Error ? err.message : 'Demo Estate connection failed');
    }
  };

  const toggleSelectedServer = (serverId: string) => {
    if (!estateProposal) return;
    setSelectedServerIds((prev) => {
      const next = prev.includes(serverId) ? prev.filter((id) => id !== serverId) : [...prev, serverId];
      setConfirmedCloneSources(buildCloneSourcesFromSelectedServers(estateProposal, next));
      return next;
    });
  };

  const selectAllOrFirstServers = (all: boolean) => {
    if (!estateProposal || !estateProposal.selectable_servers) return;
    const ids = all
      ? estateProposal.selectable_servers.map((s) => s.server_id)
      : estateProposal.selectable_servers.slice(0, 1).map((s) => s.server_id);
    setSelectedServerIds(ids);
    setConfirmedCloneSources(buildCloneSourcesFromSelectedServers(estateProposal, ids));
  };

  const toggleConfirmedCloneSource = (imgId: string) => {
    if (!estateProposal) return;
    setConfirmedCloneSources((prev) => {
      const exists = prev.some((c) => c.image_identity === imgId);
      if (exists) {
        return prev.filter((c) => c.image_identity !== imgId);
      }
      const found = estateProposal.proposed_clone_sources.find((c) => c.image_identity === imgId);
      return found ? [...prev, found] : prev;
    });
  };

  const handleApplyManualCloneOverride = () => {
    if (!manualCloneSystem.trim() || !manualCloneImage.trim()) return;
    setEstateProposal(null);
    setSelectedServerIds([]);
    setProposalError(null);
    setConfirmedCloneSources([
      {
        source_system: manualCloneSystem.trim(),
        image_identity: manualCloneImage.trim(),
        source_mode: 'MANUAL',
        declared_at: new Date().toISOString(),
      },
    ]);
  };

  const selectedConnector = vendorConnectors.find((c) => c.source_system === proposeSource);

  // WebAuthn Hardware Enrollment form
  const [hwName, setHwName] = useState('Hardware Signer');
  const [hwEmail, setHwEmail] = useState('yubikey.so@g1163rt.sec');
  const [hwRole, setHwRole] = useState<'SERVICE_OWNER' | 'AUTHORIZING_OFFICIAL'>('SERVICE_OWNER');
  const [hwAdminToken, setHwAdminToken] = useState('');
  const [pendingHwPayload, setPendingHwPayload] = useState<WebAuthnEnrollPayload | null>(null);
  const [hwStatus, setHwStatus] = useState<string | null>(null);
  const [hwError, setHwError] = useState<string | null>(null);

  const toggleService = (svcId: string) => {
    setSelectedServices((prev) =>
      prev.includes(svcId) ? prev.filter((s) => s !== svcId) : [...prev, svcId]
    );
  };

  const handleReverify = async (warrantId: string) => {
    try {
      const res = await fetch(`/api/v1/warrants/${warrantId}/verify`, { method: 'POST' });
      const data = await res.json();
      setVerifyMsg((prev) => ({
        ...prev,
        [warrantId]: data.valid ? 'PASS: N1 2-of-2 DSSE + OPA AC-5 + Live Revocation Check OK' : `FAIL-CLOSED: ${data.reason || data.error}`,
      }));
    } catch (err) {
      setVerifyMsg((prev) => ({
        ...prev,
        [warrantId]: `ERROR: ${err instanceof Error ? err.message : 'Verification request failed'}`,
      }));
    }
  };

  const handleHardwareEnroll = async (e: React.FormEvent) => {
    e.preventDefault();
    setHwStatus(null);
    setHwError(null);
    try {
      const cred = await enrollWebAuthnAuthenticator(hwName, hwEmail, hwRole, rpId);
      const payload: WebAuthnEnrollPayload = {
        display_name: hwName,
        email: hwEmail,
        role: hwRole,
        ...cred,
      };
      if (bootstrapState?.sealed && testPersonas.length === 0) {
        setPendingHwPayload(payload);
        setHwStatus('Hardware attestation captured. Co-sign 2-of-2 ENROLL_PRINCIPAL below to commit post-seal enrollment.');
        return;
      }
      await onEnrollWebAuthn(payload, hwAdminToken);
      setHwStatus(`Enrolled W3C WebAuthn hardware authenticator for ${hwEmail} (${hwRole})`);
    } catch (err) {
      setHwError(err instanceof Error ? err.message : 'Enrollment failed');
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Row: Approval Pressure Analytics Gauge + Four-Eyes Ceiling Exception Cockpit */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <section className="bg-white border border-slate-200 rounded p-4 space-y-3">
          <div className="flex items-center gap-2 border-b border-slate-200 pb-2">
            <Gauge className="w-4 h-4 text-slate-800" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900">
              N1 Approval Pressure Analytics
            </h2>
          </div>
          <p className="text-xs text-slate-600">
            Tracks pending exception depth &amp; 24h override velocity per Warrant Class to flag miscalibrated scopes and prevent human rubber-stamping.
          </p>
          <div className="space-y-2.5">
            {pressure.map((st) => (
              <div key={st.warrant_class} className="border border-slate-200 rounded p-2.5 bg-slate-50 space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-mono font-bold text-slate-900">{st.warrant_class}</span>
                  <span
                    className={`font-mono text-[11px] font-bold px-2 py-0.5 rounded border ${
                      st.pressure_status === 'PRESSURE_HIGH'
                        ? 'bg-red-100 border-red-400 text-red-950'
                        : st.pressure_status === 'ELEVATED'
                        ? 'bg-amber-100 border-amber-400 text-amber-950'
                        : 'bg-emerald-50 border-emerald-300 text-emerald-900'
                    }`}
                  >
                    {st.pressure_status}
                  </span>
                </div>
                <div className="w-full h-1.5 bg-slate-200 rounded overflow-hidden">
                  <div
                    className={`h-full ${
                      st.pressure_status === 'PRESSURE_HIGH'
                        ? 'bg-red-600'
                        : st.pressure_status === 'ELEVATED'
                        ? 'bg-amber-500'
                        : 'bg-emerald-600'
                    }`}
                    style={{ width: `${Math.max(6, st.pressure_score)}%` }}
                  />
                </div>
                <div className="flex justify-between text-[11px] font-mono text-slate-600">
                  <span>Active Warrants: {st.active_warrants}</span>
                  <span>Pending: {st.pending_exceptions}</span>
                  <span>24h Overrides: {st.overrides_last_24h}</span>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Ceiling Exception Cockpit */}
        <section className="xl:col-span-2 bg-white border border-slate-200 rounded p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-200 pb-2">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-600" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900">
                Four-Eyes Ceiling Exception Cockpit (Stateful / Unready / Above-Ceiling)
              </h2>
            </div>
            <span className="text-xs font-mono font-semibold text-slate-600">
              {exceptions.filter((e) => e.status === 'PENDING_DUAL_KEY').length} Pending Dual-Key
            </span>
          </div>

          {exceptions.length === 0 ? (
            <div className="text-xs font-mono text-slate-500 py-8 text-center">No ceiling exceptions queued.</div>
          ) : (
            <div className="space-y-3">
              {exceptions.map((ex) => (
                <div
                  key={ex.exception_id}
                  className={`border rounded p-3 space-y-3 ${
                    ex.status === 'PENDING_DUAL_KEY'
                      ? 'border-amber-400 bg-amber-50/30'
                      : 'border-slate-200 bg-slate-50'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="text-xs font-mono font-bold text-slate-900">
                      {ex.exception_id} · Remediation {ex.remediation_id}
                    </div>
                    <span
                      className={`text-[11px] font-mono font-bold px-2 py-0.5 rounded border ${
                        ex.status === 'PENDING_DUAL_KEY'
                          ? 'bg-amber-100 border-amber-400 text-amber-950'
                          : ex.status === 'APPROVED'
                          ? 'bg-emerald-50 border-emerald-300 text-emerald-900'
                          : 'bg-red-50 border-red-300 text-red-900'
                      }`}
                    >
                      {ex.status}
                    </span>
                  </div>

                  <div className="bg-white border border-slate-200 rounded p-2.5 text-xs font-mono text-slate-800">
                    {formatExceptionImpactTemplate(ex)}
                  </div>

                  {ex.status === 'PENDING_DUAL_KEY' && (
                    <DualKeyCeremonyPanel
                      title={`Authorize or Reject Exception ${ex.exception_id}`}
                      payloadType="application/vnd.g1163rt.exception-resolution.v1+json"
                      buildPayload={() => {
                        const now = new Date();
                        const exp = new Date(now.getTime() + 15 * 60 * 1000);
                        const suffix = Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
                        return {
                          envelope_id: `exc-ui-${suffix}`,
                          exception_id: ex.exception_id,
                          remediation_id: ex.remediation_id,
                          service_id: ex.service_id,
                          cve_id: ex.cve_id,
                          issued_at: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
                          expires_at: exp.toISOString().replace(/\.\d{3}Z$/, 'Z'),
                        };
                      }}
                      testPersonas={testPersonas}
                      principals={principals}
                      rpId={rpId}
                      smartcardBarEnabled={smartcardBarEnabled}
                      isMobileViewport={isMobileViewport}
                      submitLabel="CO-SIGN & APPROVE ROLLOUT"
                      onSubmitEnvelope={(env) => onResolveException(ex.exception_id, 'APPROVED', env)}
                      secondaryLabel="CO-SIGN & REJECT (KEEP BRIDGE)"
                      onSecondaryEnvelope={(env) => onResolveException(ex.exception_id, 'REJECTED', env)}
                    />
                  )}
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* Middle Row: Draft & Co-Sign Standing Warrant Composer + Native WebAuthn Registration */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <section className="xl:col-span-2 bg-white border border-slate-200 rounded p-4 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-200 pb-2">
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900">
              Standing Warrant Draft &amp; 2-of-2 Co-Sign Composer (OPA Rego AC-5 Governed)
            </h2>
            <span className="text-[11px] font-mono text-slate-500">NIST SP 800-53 AC-5 / CM-3 / AU-10</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div>
              <label htmlFor="warrant-class-input" className="block font-semibold text-slate-700 mb-1">Warrant Class</label>
              <input
                id="warrant-class-input"
                type="text"
                value={warrantClass}
                onChange={(e) => setWarrantClass(e.target.value)}
                className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono"
              />
            </div>
            <div>
              <label htmlFor="warrant-max-cvss" className="block font-semibold text-slate-700 mb-1">Max CVSS Ceiling</label>
              <input
                id="warrant-max-cvss"
                type="number"
                step="0.1"
                min="1"
                max="10"
                value={maxCvss}
                onChange={(e) => setMaxCvss(Number(e.target.value))}
                className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono"
              />
            </div>
            <div>
              <label htmlFor="warrant-max-replicas" className="block font-semibold text-slate-700 mb-1">Blast-Radius Max Replicas</label>
              <input
                id="warrant-max-replicas"
                type="number"
                min="1"
                max="100"
                value={maxReplicas}
                onChange={(e) => setMaxReplicas(Number(e.target.value))}
                className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono"
              />
            </div>
            <div>
              <label htmlFor="warrant-sla-minutes" className="block font-semibold text-slate-700 mb-1">Containment Bridge SLA (min)</label>
              <input
                id="warrant-sla-minutes"
                type="number"
                min="5"
                max="1440"
                value={slaMinutes}
                onChange={(e) => setSlaMinutes(Number(e.target.value))}
                className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono"
              />
            </div>
            <div>
              <label htmlFor="warrant-max-p99" className="block font-semibold text-slate-700 mb-1">Canary Max p99 Latency (ms)</label>
              <input
                id="warrant-max-p99"
                type="number"
                min="10"
                max="2000"
                value={maxP99Ms}
                onChange={(e) => setMaxP99Ms(Number(e.target.value))}
                className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono"
              />
            </div>
            <div>
              <label htmlFor="warrant-ttl-days" className="block font-semibold text-slate-700 mb-1">Hard Expiration (Days)</label>
              <input
                id="warrant-ttl-days"
                type="number"
                min="1"
                max="365"
                value={ttlDays}
                onChange={(e) => setTtlDays(Number(e.target.value))}
                className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1.5">Scoped Workloads</label>
            <div className="flex flex-wrap gap-2">
              {estate.map((svc) => {
                const checked = selectedServices.includes(svc.service_id);
                return (
                  <button
                    key={svc.service_id}
                    type="button"
                    onClick={() => toggleService(svc.service_id)}
                    className={`px-2.5 py-1 rounded border text-xs font-mono ${
                      checked
                        ? 'bg-slate-900 text-white border-slate-900'
                        : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
                    }`}
                  >
                    {checked ? '✓ ' : '+ '}
                    {svc.service_id}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="border border-slate-200 rounded p-3 bg-slate-50 space-y-3 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <span className="font-bold uppercase tracking-wider text-slate-900">
                  Estate Loader &amp; Server-to-Twin Selection (v1.4.1)
                </span>
                <p className="text-[11px] text-slate-600">
                  Connect to any of the 18 vendor systems (or Demo Estate Mock), browse live servers in memory (zero DB replication), and select which server(s) to clone as your QA Twin.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {onOpenVendorConnectors && (
                  <button
                    type="button"
                    onClick={onOpenVendorConnectors}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-slate-300 bg-white hover:bg-slate-100 text-slate-800 font-semibold"
                  >
                    <PlugZap className="w-3.5 h-3.5" />
                    <span>Configure 18 Vendors</span>
                  </button>
                )}
                {selectedConnector && !selectedConnector.read_configured && selectedConnector.demo_mock_available && (
                  <button
                    type="button"
                    onClick={handleConnectDemoAndBrowse}
                    disabled={proposalLoading || selectedServices.length === 0}
                    className="px-3 py-1.5 rounded bg-emerald-700 text-white font-semibold hover:bg-emerald-800 disabled:opacity-50"
                  >
                    {proposalLoading ? 'Connecting...' : `Connect ${proposeSource} Demo & Browse Servers`}
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => handleFetchEstateProposal()}
                  disabled={proposalLoading || selectedServices.length === 0}
                  className="px-3 py-1.5 rounded bg-slate-900 text-white font-semibold hover:bg-slate-800 disabled:opacity-50"
                >
                  {proposalLoading ? 'Reading Estate...' : 'Connect & Load Estate Servers'}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-4 gap-2.5">
              <div>
                <label htmlFor="estate-propose-source" className="block font-semibold text-slate-700 mb-1">
                  Primary Source (Tier A / B)
                </label>
                <select
                  id="estate-propose-source"
                  value={proposeSource}
                  onChange={(e) => setProposeSource(e.target.value)}
                  className="w-full border border-slate-300 rounded px-2 py-1.5 font-mono bg-white text-slate-900"
                >
                  {(estateSources.filter((s) => s.can_propose_clone_sources).length > 0
                    ? estateSources.filter((s) => s.can_propose_clone_sources)
                    : [
                        { source_system: 'k8s-cilium-native', source_tier: 'TIER_B_WORKLOAD' },
                        { source_system: 'ms-mecm', source_tier: 'TIER_A_MACHINE' },
                        { source_system: 'ms-intune', source_tier: 'TIER_A_MACHINE' },
                        { source_system: 'aws-ssm', source_tier: 'TIER_A_MACHINE' },
                      ]
                  ).map((s) => {
                    const conn = vendorConnectors.find((vc) => vc.source_system === s.source_system);
                    const tag = conn ? conn.connection_mode : s.source_tier;
                    return (
                      <option key={s.source_system} value={s.source_system}>
                        {s.source_system} [{tag}]
                      </option>
                    );
                  })}
                </select>
              </div>
              <div>
                <label htmlFor="estate-census-scanner" className="block font-semibold text-slate-700 mb-1">
                  Tier C Census Cross-Check
                </label>
                <select
                  id="estate-census-scanner"
                  value={corroborateScanner}
                  onChange={(e) => setCorroborateScanner(e.target.value)}
                  className="w-full border border-slate-300 rounded px-2 py-1.5 font-mono bg-white text-slate-900"
                >
                  <option value="">None</option>
                  <option value="tenable">tenable (TIER_C_CENSUS)</option>
                  <option value="qualys_vmdr">qualys_vmdr (TIER_C_CENSUS)</option>
                  <option value="rapid7_insightvm">rapid7_insightvm (TIER_C_CENSUS)</option>
                </select>
              </div>
              <div>
                <label htmlFor="estate-drift-policy" className="block font-semibold text-slate-700 mb-1">
                  Proving Drift Policy
                </label>
                <select
                  id="estate-drift-policy"
                  value={driftPolicy}
                  onChange={(e) => setDriftPolicy(e.target.value as 'RECORD_ONLY' | 'FAIL_CLOSED')}
                  className="w-full border border-slate-300 rounded px-2 py-1.5 font-mono bg-white text-slate-900"
                >
                  <option value="RECORD_ONLY">RECORD_ONLY</option>
                  <option value="FAIL_CLOSED">FAIL_CLOSED</option>
                </select>
              </div>
              <div>
                <label htmlFor="estate-drift-tol" className="block font-semibold text-slate-700 mb-1">
                  Drift Tolerance (%)
                </label>
                <input
                  id="estate-drift-tol"
                  type="number"
                  step="0.5"
                  min="0.5"
                  max="100"
                  value={driftTolerancePct}
                  onChange={(e) => setDriftTolerancePct(Number(e.target.value))}
                  className="w-full border border-slate-300 rounded px-2 py-1.5 font-mono bg-white text-slate-900"
                />
              </div>
            </div>

            <div>
              <label htmlFor="estate-read-token-input" className="block font-semibold text-slate-700 mb-1">
                Optional Read-Only Token (X-Warrant-Estate-Read-Token — distinct from WN-8 dispatch tokens)
              </label>
              <input
                id="estate-read-token-input"
                type="password"
                value={estateReadTokenInput}
                onChange={(e) => setEstateReadTokenInput(e.target.value)}
                placeholder="Leave blank in local simulator mode when WARRANT_ESTATE_READ_TOKEN is unset"
                className="w-full border border-slate-300 rounded px-2.5 py-1 font-mono bg-white text-slate-900"
              />
            </div>

            {proposalError && (
              <div role="alert" className="p-2.5 rounded border border-amber-300 bg-amber-50 text-amber-900 space-y-2">
                <div className="font-mono text-[11px]">{proposalError}</div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 items-end pt-1">
                  <div>
                    <label htmlFor="manual-clone-sys" className="block text-[11px] font-semibold">Manual System Override</label>
                    <input
                      id="manual-clone-sys"
                      type="text"
                      value={manualCloneSystem}
                      onChange={(e) => setManualCloneSystem(e.target.value)}
                      placeholder="e.g. ms-mecm"
                      className="w-full border border-amber-400 rounded px-2 py-1 font-mono bg-white text-slate-900"
                    />
                  </div>
                  <div>
                    <label htmlFor="manual-clone-img" className="block text-[11px] font-semibold">Manual Image Identity</label>
                    <input
                      id="manual-clone-img"
                      type="text"
                      value={manualCloneImage}
                      onChange={(e) => setManualCloneImage(e.target.value)}
                      placeholder="e.g. wim://qa-win2022"
                      className="w-full border border-amber-400 rounded px-2 py-1 font-mono bg-white text-slate-900"
                    />
                  </div>
                  <button
                    type="button"
                    onClick={handleApplyManualCloneOverride}
                    className="px-2.5 py-1 rounded bg-amber-900 text-white font-semibold"
                  >
                    Declare MANUAL Source
                  </button>
                </div>
              </div>
            )}

            {estateProposal && (
              <div className="border border-emerald-300 bg-white rounded p-2.5 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[11px]">
                  <span className="font-bold text-emerald-900">
                    Snapshot {shortHash(estateProposal.proposed_estate_snapshot_sha256)} ({estateProposal.primary_snapshot.source_system})
                  </span>
                  <span className="text-slate-700">
                    Members: {estateProposal.primary_snapshot.class_membership_count} · Freshness Age: {estateProposal.primary_snapshot.source_freshness_age_seconds}s
                  </span>
                </div>
                {estateProposal.census_advisory && (
                  <div className="text-[11px] font-mono text-slate-700 bg-slate-100 px-2 py-1 rounded">
                    Tier C Census: {estateProposal.census_advisory}
                  </div>
                )}

                {estateProposal.selectable_servers && estateProposal.selectable_servers.length > 0 ? (
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-[11px] font-bold text-slate-900 inline-flex items-center gap-1">
                        <Server className="w-3.5 h-3.5 text-emerald-700" />
                        <span>
                          Select Server(s) from {estateProposal.primary_snapshot.source_system} to Clone as QA Twin ({selectedServerIds.length} of {estateProposal.selectable_servers.length} selected):
                        </span>
                      </span>
                      <div className="flex items-center gap-1.5 text-[11px]">
                        <button
                          type="button"
                          onClick={() => selectAllOrFirstServers(false)}
                          className="px-2 py-0.5 rounded border border-slate-300 bg-slate-50 hover:bg-slate-100 text-slate-800 font-semibold"
                        >
                          1st Server Only
                        </button>
                        <button
                          type="button"
                          onClick={() => selectAllOrFirstServers(true)}
                          className="px-2 py-0.5 rounded border border-slate-300 bg-slate-50 hover:bg-slate-100 text-slate-800 font-semibold"
                        >
                          Select All ({estateProposal.selectable_servers.length})
                        </button>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 gap-1.5 max-h-56 overflow-y-auto pr-1">
                      {estateProposal.selectable_servers.map((sv) => {
                        const checked = selectedServerIds.includes(sv.server_id);
                        const inputId = `twin-srv-${sv.server_id}`;
                        return (
                          <label
                            key={sv.server_id}
                            htmlFor={inputId}
                            className={`flex flex-wrap items-center justify-between gap-2 p-2 rounded border font-mono text-[11px] cursor-pointer ${
                              checked
                                ? 'border-emerald-500 bg-emerald-50/70 text-slate-900'
                                : 'border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100'
                            }`}
                          >
                            <div className="flex items-center gap-2">
                              <input
                                id={inputId}
                                type="checkbox"
                                checked={checked}
                                onChange={() => toggleSelectedServer(sv.server_id)}
                              />
                              <div>
                                <div className="font-bold text-slate-900">
                                  {sv.hostname}{' '}
                                  <span className="font-normal text-slate-600">
                                    ({sv.server_id}{sv.service_id ? ` · ${sv.service_id}` : ''})
                                  </span>
                                </div>
                                <div className="text-slate-600">
                                  {sv.os_family} {sv.os_version_or_build}
                                  {sv.kernel_release ? ` · kernel ${sv.kernel_release}` : ''}
                                  {sv.primary_package ? ` · ${sv.primary_package}` : ''}
                                </div>
                              </div>
                            </div>
                            <span className="px-2 py-0.5 rounded bg-white border border-slate-300 text-slate-800 font-semibold">
                              Twin: {sv.twin_image_identity}
                            </span>
                          </label>
                        );
                      })}
                    </div>
                  </div>
                ) : (
                  <div className="space-y-1">
                    <div className="text-[11px] font-semibold text-slate-700">
                      Confirm Candidate Clone Sources to Bind into 2-of-2 Warrant ({confirmedCloneSources.length} selected):
                    </div>
                    {estateProposal.proposed_clone_sources.map((cand) => {
                      const isChecked = confirmedCloneSources.some((c) => c.image_identity === cand.image_identity);
                      return (
                        <label key={cand.image_identity} className="flex items-center gap-2 font-mono text-[11px] text-slate-800">
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={() => toggleConfirmedCloneSource(cand.image_identity)}
                          />
                          <span>{cand.image_identity}</span>
                          <span className="text-slate-500">
                            ({cand.platform_family || 'workload'} · age={cand.image_age_seconds_at_sign ?? 0}s)
                          </span>
                        </label>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {confirmedCloneSources.length > 0 && (
              <div className="text-[11px] font-mono text-slate-800 bg-white border border-slate-300 rounded px-2.5 py-1.5">
                Bound Twin Clone Sources ({confirmedCloneSources[0].source_mode}):{' '}
                {confirmedCloneSources
                  .map((c) =>
                    c.selected_server_hostname
                      ? `${c.selected_server_hostname} -> ${c.image_identity}`
                      : `${c.source_system}=${c.image_identity}`
                  )
                  .join(' · ')}
              </div>
            )}
          </div>

          <DualKeyCeremonyPanel
            title="Mint Append-Only Standing Warrant DSSE Envelope"
            payloadType="application/vnd.g1163rt.warrant.v1+json"
            buildPayload={() => {
              const now = new Date();
              const exp = new Date(now.getTime() + ttlDays * 86400 * 1000);
              const payload: Record<string, unknown> = {
                warrant_id: `wrt-${Math.random().toString(36).slice(2, 9)}`,
                warrant_class: warrantClass,
                scope_services: selectedServices,
                max_cvss: maxCvss,
                kev_eligible: true,
                max_blast_radius_replicas: maxReplicas,
                allow_stateful_patches: false,
                sla_bridge_minutes: slaMinutes,
                max_p99_latency_ms: maxP99Ms,
                issued_at: now.toISOString(),
                expires_at: exp.toISOString(),
              };
              if (confirmedCloneSources.length > 0) {
                payload.clone_sources = confirmedCloneSources;
                payload.estate_drift_policy = driftPolicy;
                payload.estate_drift_tolerance_pct = driftTolerancePct;
                if (estateProposal?.proposed_estate_snapshot_sha256) {
                  payload.estate_snapshot_sha256 = estateProposal.proposed_estate_snapshot_sha256;
                }
              }
              return payload;
            }}
            testPersonas={testPersonas}
            principals={principals}
            rpId={rpId}
            smartcardBarEnabled={smartcardBarEnabled}
            isMobileViewport={isMobileViewport}
            submitLabel="MINT DUAL-SIGNED STANDING WARRANT"
            onSubmitEnvelope={onCreateWarrant}
          />
        </section>

        {/* Native W3C WebAuthn Hardware Key Enrollment */}
        <section className="bg-white border border-slate-200 rounded p-4 space-y-3">
          <div className="flex items-center gap-2 border-b border-slate-200 pb-2">
            <Usb className="w-4 h-4 text-indigo-700" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900">
              W3C WebAuthn Hardware Key Enrollment
            </h2>
          </div>
          <p className="text-xs text-slate-600">
            Enroll a physical YubiKey, FIDO2 PIV token, or platform authenticator on{' '}
            <code className="font-mono">RPID={rpId}</code> via <code className="font-mono">navigator.credentials.create</code>.
          </p>
          <form onSubmit={handleHardwareEnroll} className="space-y-2.5 text-xs">
            <div>
              <label htmlFor="webauthn-principal-name" className="block font-semibold text-slate-700 mb-1">Principal Display Name</label>
              <input
                id="webauthn-principal-name"
                type="text"
                value={hwName}
                onChange={(e) => setHwName(e.target.value)}
                required
                className="w-full border border-slate-300 rounded px-2.5 py-1.5"
              />
            </div>
            <div>
              <label htmlFor="webauthn-principal-email" className="block font-semibold text-slate-700 mb-1">Institutional Email</label>
              <input
                id="webauthn-principal-email"
                type="email"
                value={hwEmail}
                onChange={(e) => setHwEmail(e.target.value)}
                required
                className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono"
              />
            </div>
            <div>
              <label htmlFor="webauthn-principal-role" className="block font-semibold text-slate-700 mb-1">AC-5 Signing Role</label>
              <select
                id="webauthn-principal-role"
                value={hwRole}
                onChange={(e) => setHwRole(e.target.value as 'SERVICE_OWNER' | 'AUTHORIZING_OFFICIAL')}
                className="w-full border border-slate-300 rounded px-2.5 py-1.5 bg-white font-mono"
              >
                <option value="SERVICE_OWNER">SERVICE_OWNER (Slot 1)</option>
                <option value="AUTHORIZING_OFFICIAL">AUTHORIZING_OFFICIAL (Slot 2)</option>
              </select>
            </div>
            {!bootstrapState?.sealed && (
              <div>
                <label htmlFor="webauthn-bootstrap-token" className="block font-semibold text-slate-700 mb-1">
                  Genesis Bootstrap Token (Unsealed Setup)
                </label>
                <input
                  id="webauthn-bootstrap-token"
                  type="password"
                  value={hwAdminToken}
                  onChange={(e) => setHwAdminToken(e.target.value)}
                  placeholder="WARRANT_BOOTSTRAP_ADMIN_TOKEN"
                  className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono"
                />
              </div>
            )}
            <button
              type="submit"
              disabled={isMobileViewport}
              className="w-full py-2 rounded bg-indigo-700 hover:bg-indigo-800 text-white font-bold disabled:opacity-40"
            >
              {bootstrapState?.sealed ? 'Capture & Co-Sign 2-of-2 WebAuthn Key' : 'Enroll Genesis Hardware WebAuthn Key'}
            </button>
          </form>
          {pendingHwPayload && (
            <DualKeyCeremonyPanel
              title="Post-Seal 2-of-2 WebAuthn Enrollment Ceremony"
              payloadType="application/vnd.g1163rt.principal-governance.v1+json"
              buildPayload={() => {
                const now = new Date();
                const exp = new Date(now.getTime() + 15 * 60 * 1000);
                const suffix = Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
                return {
                  ...pendingHwPayload,
                  envelope_id: `gov-hw2-${suffix}`,
                  action: 'ENROLL_PRINCIPAL',
                  issued_at: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
                  expires_at: exp.toISOString().replace(/\.\d{3}Z$/, 'Z'),
                };
              }}
              testPersonas={testPersonas}
              principals={principals}
              rpId={rpId}
              smartcardBarEnabled={smartcardBarEnabled}
              isMobileViewport={isMobileViewport}
              submitLabel="CO-SIGN 2-OF-2 & ENROLL HARDWARE KEY"
              onSubmitEnvelope={async (env) => {
                await onEnrollWebAuthn(pendingHwPayload, undefined, env);
                setPendingHwPayload(null);
                setHwStatus(`Enrolled post-seal WebAuthn hardware authenticator for ${pendingHwPayload.email}`);
              }}
            />
          )}
          {hwError && (
            <div role="alert" className="text-xs font-mono p-2 rounded bg-red-50 border border-red-400 text-red-950">
              {hwError}
            </div>
          )}
          {hwStatus && (
            <div role="status" className="text-xs font-mono p-2 rounded bg-slate-100 border border-slate-300 text-slate-800">
              {hwStatus}
            </div>
          )}
        </section>
      </div>

      {/* Active Warrant Ledger Cards */}
      <section className="bg-white border border-slate-200 rounded p-4 space-y-3">
        <div className="flex items-center justify-between border-b border-slate-200 pb-2">
          <div className="flex items-center gap-2">
            <FileCheck2 className="w-4 h-4 text-slate-800" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900">
              Immutable Standing Warrant Ledger (Append-Only Hash-Chained)
            </h2>
          </div>
          <span className="text-xs font-mono text-slate-500">{warrants.length} Envelopes Recorded</span>
        </div>

        {revokeError && (
          <div role="alert" className="p-2.5 rounded border border-red-400 bg-red-50 text-red-950 text-xs font-mono">
            {revokeError}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {warrants.map((w) => (
            <div
              key={w.warrant_id}
              className={`border rounded p-3.5 space-y-2.5 ${
                w.live_status === 'ACTIVE'
                  ? 'border-emerald-300 bg-white'
                  : 'border-red-400 bg-red-50/40'
              }`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-mono font-bold text-slate-900">{w.warrant_id}</span>
                  <span className="ml-2 text-xs font-mono px-2 py-0.5 rounded bg-slate-100 border border-slate-200">
                    {w.warrant_class}
                  </span>
                </div>
                <span
                  className={`text-[11px] font-mono font-bold px-2 py-0.5 rounded border ${
                    w.live_status === 'ACTIVE'
                      ? 'bg-emerald-50 border-emerald-300 text-emerald-900'
                      : 'bg-red-600 border-red-700 text-white'
                  }`}
                >
                  {w.live_status}
                </span>
              </div>

              <div className="text-xs font-mono text-slate-700">
                Scope: {w.scope_services.join(', ')} · MaxCVSS={w.max_cvss.toFixed(1)} · MaxReplicas=
                {w.max_blast_radius_replicas} · BridgeSLA={w.sla_bridge_minutes}m · Expires{' '}
                {new Date(w.expires_at).toLocaleDateString()}
              </div>

              {w.clone_sources && w.clone_sources.length > 0 && (
                <div className="text-[11px] font-mono px-2.5 py-1.5 rounded border border-emerald-300 bg-emerald-50/60 text-slate-900">
                  <span className="font-bold text-emerald-950">
                    Bound Twin Sources ({w.clone_sources[0].source_mode} · {w.estate_drift_policy || 'RECORD_ONLY'}):
                  </span>{' '}
                  {w.clone_sources
                    .map((cs) =>
                      cs.selected_server_hostname
                        ? `${cs.selected_server_hostname} -> ${cs.image_identity}`
                        : `${cs.source_system}:${cs.image_identity}`
                    )
                    .join(' · ')}
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono">
                <div className="border border-slate-200 rounded p-2 bg-slate-50">
                  <div className="font-bold text-slate-800 flex items-center justify-between">
                    <span>SLOT 1: {w.slot1_principal_id}</span>
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-700" />
                  </div>
                  <div className="text-slate-600 truncate">{w.slot1_email}</div>
                  <div className="text-slate-500">fp: {shortHash(w.slot1_key_fp, 16)}</div>
                </div>
                <div className="border border-slate-200 rounded p-2 bg-slate-50">
                  <div className="font-bold text-slate-800 flex items-center justify-between">
                    <span>SLOT 2: {w.slot2_principal_id}</span>
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-700" />
                  </div>
                  <div className="text-slate-600 truncate">{w.slot2_email}</div>
                  <div className="text-slate-500">fp: {shortHash(w.slot2_key_fp, 16)}</div>
                </div>
              </div>

              {verifyMsg[w.warrant_id] && (
                <div className="text-[11px] font-mono p-2 rounded border border-slate-300 bg-slate-100 text-slate-900">
                  {verifyMsg[w.warrant_id]}
                </div>
              )}

              <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-slate-200 text-[11px] font-mono">
                <span className="text-slate-500">chain_hash: {shortHash(w.entry_hash, 18)}</span>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => handleReverify(w.warrant_id)}
                    className="px-2 py-1 rounded border border-slate-300 bg-white hover:bg-slate-50 font-semibold text-slate-800"
                  >
                    Re-Verify N1 Live
                  </button>
                  {w.live_status === 'ACTIVE' && (
                    <button
                      type="button"
                      onClick={async () => {
                        setRevokeError(null);
                        try {
                          await onRevokeSigner(w.slot2_principal_id, w.slot2_key_fp);
                        } catch (err) {
                          setRevokeError(err instanceof Error ? err.message : 'Principal revocation failed');
                        }
                      }}
                      className="inline-flex items-center gap-1 px-2 py-1 rounded border border-red-300 bg-red-50 hover:bg-red-100 font-semibold text-red-900"
                      title="Revoke AO key in principal_revocations to test instant fail-closed warrant invalidation"
                    >
                      <UserX className="w-3 h-3" /> Revoke Slot 2 Key
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      <AgentGovernancePanel
        commissioningFunctions={commissioningFunctions}
        agents={agents}
        pendingTransfers={pendingSponsorTransfers}
        principals={principals}
        nowMs={nowMs}
        onRevokeAgent={async (agentId, reasonCode) => {
          if (onRevokeAgent) await onRevokeAgent(agentId, reasonCode);
        }}
        onEmitIGAEvent={async (evType, principalId) => {
          if (onEmitIGAEvent) await onEmitIGAEvent(evType, principalId);
        }}
        onTransferSponsors={async (fn, newSO, newAO) => {
          if (onTransferSponsors) await onTransferSponsors(fn, newSO, newAO);
        }}
      />
    </div>
  );
};
