import React, { useCallback, useEffect, useState } from 'react';
import { Activity, FileSignature, GitCompare, ShieldAlert, Vault } from 'lucide-react';
import type { BootstrapSnapshot, DSSEEnvelope } from './types';
import {
  buildDualPrincipalGovernanceEnvelope,
  buildDualPrincipalGovernanceEnvelopeWebAuthn,
  buildSinglePrincipalGovernanceEnvelope,
  buildSinglePrincipalGovernanceEnvelopeWebAuthn,
  bytesToBase64,
  hasLocalPersonaKey,
  sha256HexString,
} from './lib/crypto';
import { utf8ToBytes } from '@noble/hashes/utils';
import { CommandBar } from './components/CommandBar';
import { View1RacePipeline } from './components/View1RacePipeline';
import { View2WarrantDesk } from './components/View2WarrantDesk';
import { View3ShadowEstate } from './components/View3ShadowEstate';
import { View4ContainmentLockout } from './components/View4ContainmentLockout';
import { View5AuditorLedger } from './components/View5AuditorLedger';
import { AuditorPortal } from './components/AuditorPortal';
import { LiveFeedsModal } from './components/LiveFeedsModal';

type ViewKey = 'VIEW1_RACE' | 'VIEW2_WARRANTS' | 'VIEW3_SHADOW' | 'VIEW4_CONTAINMENT' | 'VIEW5_AUDITOR';

export const App: React.FC = () => {
  const isAuditorRoute = window.location.pathname.startsWith('/auditor');

  const [snapshot, setSnapshot] = useState<BootstrapSnapshot | null>(null);
  const [activeView, setActiveView] = useState<ViewKey>('VIEW1_RACE');
  const [smartcardBarEnabled, setSmartcardBarEnabled] = useState(true);
  const [showFeedsModal, setShowFeedsModal] = useState(false);
  const [isMobileViewport, setIsMobileViewport] = useState(() => window.innerWidth < 1024);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [sseConnected, setSseConnected] = useState(false);
  const [automationToken, setAutomationToken] = useState<string>(
    () => window.sessionStorage.getItem('warrant_automation_token') || ''
  );

  const saveAutomationToken = (tok: string) => {
    const clean = tok.trim();
    setAutomationToken(clean);
    if (clean) {
      window.sessionStorage.setItem('warrant_automation_token', clean);
    } else {
      window.sessionStorage.removeItem('warrant_automation_token');
    }
  };

  const loadBootstrap = useCallback(async () => {
    const res = await fetch('/api/v1/bootstrap');
    if (!res.ok) return;
    const data: BootstrapSnapshot = await res.json();
    setSnapshot(data);
  }, []);

  useEffect(() => {
    if (isAuditorRoute) return;
    loadBootstrap();

    const es = new EventSource('/api/v1/events/stream');
    es.onopen = () => setSseConnected(true);
    es.onerror = () => setSseConnected(false);
    es.onmessage = () => {
      loadBootstrap();
    };
    return () => es.close();
  }, [isAuditorRoute, loadBootstrap]);

  useEffect(() => {
    const onResize = () => setIsMobileViewport(window.innerWidth < 1024);
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  if (isAuditorRoute) {
    return <AuditorPortal />;
  }

  const postRawJSON = async (url: string, rawBody: string, extraHeaders?: Record<string, string>) => {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(extraHeaders || {}) },
      body: rawBody,
    });
    const text = await res.text();
    let data: Record<string, unknown> = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { error: text };
    }
    if (!res.ok) {
      throw new Error((data.error as string) || `HTTP ${res.status}`);
    }
    await loadBootstrap();
    return data;
  };

  const postJSON = async (url: string, body: unknown, extraHeaders?: Record<string, string>) => {
    return postRawJSON(url, JSON.stringify(body), extraHeaders);
  };

  if (!snapshot) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 text-slate-700 font-mono text-xs">
        INITIALIZING G1-WARRANT DETERMINISTIC CONTROL PLANE...
      </div>
    );
  }

  const pendingExceptionsCount =
    snapshot.exceptions.filter((e) => e.status === 'PENDING_DUAL_KEY').length +
    (snapshot.pending_sponsor_transfers?.length || 0);
  const rpId = snapshot.webauthn?.rp_id || 'localhost';

  const revokedIds = new Set(
    snapshot.principals.filter((p) => p.revoked).map((p) => p.principal_id)
  );
  const activePersonas = snapshot.test_personas.filter(
    (tp) =>
      (tp.role === 'SERVICE_OWNER' || tp.role === 'AUTHORIZING_OFFICIAL') &&
      !revokedIds.has(tp.principal_id) &&
      hasLocalPersonaKey(tp)
  );
  const activeWebAuthnPrincipals = snapshot.principals.filter(
    (p) =>
      !p.revoked &&
      p.authenticator_mode === 'WEBAUTHN_HARDWARE' &&
      (p.role === 'SERVICE_OWNER' || p.role === 'AUTHORIZING_OFFICIAL')
  );

  const postActionJSON = async (
    url: string,
    body: unknown,
    action: string,
    fields: Record<string, unknown> = {},
    allowAutomationToken = false
  ) => {
    const rawBody = JSON.stringify(body);
    const canonicalPath = new URL(url, window.location.origin).pathname;
    const scopedFields: Record<string, unknown> = {
      ...fields,
      http_method: 'POST',
      canonical_path: canonicalPath,
      request_body_sha256: sha256HexString(rawBody),
    };
    const headers: Record<string, string> = {};

    if (smartcardBarEnabled && activePersonas.length > 0) {
      const env = buildSinglePrincipalGovernanceEnvelope(action, scopedFields, activePersonas[0]);
      headers['X-Warrant-Governance-DSSE'] = bytesToBase64(utf8ToBytes(JSON.stringify(env)));
    } else if (allowAutomationToken && automationToken) {
      headers['X-Warrant-Automation-Token'] = automationToken;
    } else if (activeWebAuthnPrincipals.length > 0) {
      const env = await buildSinglePrincipalGovernanceEnvelopeWebAuthn(
        action,
        scopedFields,
        activeWebAuthnPrincipals[0],
        rpId
      );
      headers['X-Warrant-Governance-DSSE'] = bytesToBase64(utf8ToBytes(JSON.stringify(env)));
    }
    return postRawJSON(url, rawBody, headers);
  };

  const navItems: Array<{ key: ViewKey; label: string; badge?: number; icon: React.ReactNode }> = [
    {
      key: 'VIEW1_RACE',
      label: '1. Race Pipeline',
      badge: snapshot.remediations.length,
      icon: <Activity className="w-4 h-4" />,
    },
    {
      key: 'VIEW2_WARRANTS',
      label: '2. Warrant Desk & Dual-Key',
      badge: pendingExceptionsCount > 0 ? pendingExceptionsCount : undefined,
      icon: <FileSignature className="w-4 h-4" />,
    },
    {
      key: 'VIEW3_SHADOW',
      label: '3. Shadow & Estate Readiness',
      icon: <GitCompare className="w-4 h-4" />,
    },
    {
      key: 'VIEW4_CONTAINMENT',
      label: '4. Bridges & Drift Lockout',
      badge: snapshot.drifts.length > 0 ? snapshot.drifts.length : undefined,
      icon: <ShieldAlert className="w-4 h-4" />,
    },
    {
      key: 'VIEW5_AUDITOR',
      label: '5. OSCAL Vault & Agent Ledger',
      badge: snapshot.attestations.length,
      icon: <Vault className="w-4 h-4" />,
    },
  ];

  return (
    <div className="min-h-screen flex flex-col bg-slate-50">
      <CommandBar
        scoreboard={snapshot.scoreboard}
        feedStatus={snapshot.feed_status}
        testPersonas={snapshot.test_personas}
        principals={snapshot.principals}
        rpId={snapshot.webauthn?.rp_id || 'localhost'}
        smartcardBarEnabled={smartcardBarEnabled}
        onToggleSmartcardBar={() => setSmartcardBarEnabled((v) => !v)}
        onOpenLiveFeeds={() => setShowFeedsModal(true)}
        isMobileViewport={isMobileViewport}
        onOpenInbox={() => setActiveView('VIEW2_WARRANTS')}
        onTriggerFreeze={async (mode, actor, reason) => {
          await postActionJSON(
            '/api/v1/freeze',
            { mode, actor, reason_code: reason },
            'EMERGENCY_FREEZE',
            { freeze_mode: mode, reason_code: reason }
          );
        }}
        onThawFreeze={async (env: DSSEEnvelope) => {
          await postJSON('/api/v1/freeze/thaw', env);
        }}
      />

      {/* Primary 5-View Institutional Clearinghouse Navigation */}
      <nav aria-label="G1-Warrant Control Plane Views" className="bg-white border-b border-slate-200 px-4">
        <div className="max-w-[1600px] mx-auto flex items-center justify-between gap-2 overflow-x-auto">
          <div className="flex items-center gap-1">
            {navItems.map((item) => {
              const active = activeView === item.key;
              return (
                <button
                  key={item.key}
                  type="button"
                  onClick={() => setActiveView(item.key)}
                  aria-current={active ? 'page' : undefined}
                  className={`inline-flex items-center gap-2 px-3.5 py-2.5 text-xs font-bold whitespace-nowrap border-b-2 transition ${
                    active
                      ? 'border-slate-900 text-slate-900 bg-slate-50'
                      : 'border-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-50/50'
                  }`}
                >
                  {item.icon}
                  <span>{item.label}</span>
                  {item.badge !== undefined && (
                    <span
                      className={`px-1.5 py-0.2 text-[10px] font-mono rounded ${
                        item.key === 'VIEW4_CONTAINMENT' && snapshot.drifts.length > 0
                          ? 'bg-red-600 text-white'
                          : item.key === 'VIEW2_WARRANTS' && pendingExceptionsCount > 0
                          ? 'bg-amber-500 text-slate-950'
                          : 'bg-slate-200 text-slate-800'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          <div className="hidden md:flex items-center gap-2 text-[11px] font-mono text-slate-500 py-2">
            <span className={`w-2 h-2 rounded-full ${sseConnected ? 'bg-emerald-600' : 'bg-amber-500'}`} />
            <span>SSE: {sseConnected ? 'LIVE STREAM' : 'RECONNECTING'}</span>
            <span>·</span>
            <span>ZERO-LLM KERNEL</span>
          </div>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 max-w-[1600px] w-full mx-auto p-4">
        {activeView === 'VIEW1_RACE' && (
          <View1RacePipeline
            remediations={snapshot.remediations}
            bridges={snapshot.bridges}
            drifts={snapshot.drifts}
            pendingExceptionsCount={pendingExceptionsCount}
            isLiveFeedMode={snapshot.feed_status?.config.mode === 'live'}
            nowMs={nowMs}
            onSimulate={async (sc) => {
              await postActionJSON(`/api/v1/simulate/${sc}`, {}, 'SIMULATION_DRILL', { scenario: sc });
            }}
            onSubmitIntake={async (vendor, rawPayload, intakeToken, targetService, distributorId) => {
              const params = new URLSearchParams();
              if (targetService) params.set('target_service', targetService);
              if (distributorId && vendor !== 'sarif') params.set('distributor_id', distributorId);
              const qs = params.toString() ? `?${params.toString()}` : '';
              const headers: Record<string, string> = {
                'Content-Type': vendor === 'qualys' && rawPayload.trim().startsWith('<') ? 'application/xml' : 'application/json',
              };
              if (intakeToken.trim()) {
                headers['X-Warrant-Intake-Token'] = intakeToken.trim();
              }
              const resp = await fetch(`/api/v1/intake/${vendor}${qs}`, {
                method: 'POST',
                headers,
                body: rawPayload,
              });
              const text = await resp.text();
              if (!resp.ok) {
                let msg = text;
                try {
                  const errJson = JSON.parse(text);
                  msg = errJson.error || errJson.reason || text;
                } catch {
                  // raw body fallback
                }
                throw new Error(msg || `HTTP ${resp.status}`);
              }
              await loadBootstrap();
              return JSON.parse(text);
            }}
            onEmergencyRollback={async (remId, reason) => {
              await postActionJSON(
                `/api/v1/pipeline/${remId}/emergency-rollback`,
                { reason },
                'EMERGENCY_ROLLBACK',
                { remediation_id: remId, reason_code: reason }
              );
            }}
            onJumpToExceptions={() => setActiveView('VIEW2_WARRANTS')}
          />
        )}

        {activeView === 'VIEW2_WARRANTS' && (
          <View2WarrantDesk
            warrants={snapshot.warrants}
            exceptions={snapshot.exceptions}
            pressure={snapshot.pressure}
            estate={snapshot.estate}
            principals={snapshot.principals}
            bootstrapState={snapshot.bootstrap_state}
            commissioningFunctions={snapshot.commissioning_functions}
            agents={snapshot.agents}
            pendingSponsorTransfers={snapshot.pending_sponsor_transfers}
            nowMs={nowMs}
            testPersonas={snapshot.test_personas}
            rpId={rpId}
            smartcardBarEnabled={smartcardBarEnabled}
            isMobileViewport={isMobileViewport}
            onCreateWarrant={async (env) => {
              await postJSON('/api/v1/warrants', env);
            }}
            onRevokeAgent={async (agentId, reasonCode) => {
              if (smartcardBarEnabled && activePersonas.length > 0) {
                const env = buildSinglePrincipalGovernanceEnvelope(
                  'REVOKE_AGENT_IDENTITY',
                  { agent_id: agentId, reason_code: reasonCode },
                  activePersonas[0]
                );
                await postJSON('/api/v1/agents/revoke', env);
                return;
              }
              if (activeWebAuthnPrincipals.length > 0) {
                const env = await buildSinglePrincipalGovernanceEnvelopeWebAuthn(
                  'REVOKE_AGENT_IDENTITY',
                  { agent_id: agentId, reason_code: reasonCode },
                  activeWebAuthnPrincipals[0],
                  rpId
                );
                await postJSON('/api/v1/agents/revoke', env);
                return;
              }
              throw new Error('Active SERVICE_OWNER or AUTHORIZING_OFFICIAL key required for 1-of-2 agent kill-switch');
            }}
            onEmitIGAEvent={async (eventType, principalId) => {
              await postActionJSON(
                '/api/v1/iga/events',
                { event_type: eventType, principal_id: principalId, reason_code: `CONSOLE_${eventType}` },
                'EMIT_IGA_EVENT',
                { target_principal_id: principalId, iga_event_type: eventType, reason_code: `CONSOLE_${eventType}` }
              );
            }}
            onTransferSponsors={async (fn, newSO, newAO) => {
              const fields: Record<string, unknown> = {
                function_id: fn.function_id,
                display_name: fn.display_name,
                owning_org_unit: fn.owning_org_unit,
                cost_center: fn.cost_center,
                primary_so_principal_id: newSO,
                secondary_so_principal_id: '',
                primary_ao_principal_id: newAO,
                secondary_ao_principal_id: '',
                escalation_contact: fn.escalation_contact,
                orphan_grace_hours: fn.orphan_grace_hours,
                reason_code: 'CONSOLE_2OF2_SPONSOR_SUCCESSION',
              };
              if (smartcardBarEnabled) {
                const so = activePersonas.find((p) => p.role === 'SERVICE_OWNER');
                const ao = activePersonas.find((p) => p.role === 'AUTHORIZING_OFFICIAL');
                if (so && ao) {
                  const env = buildDualPrincipalGovernanceEnvelope('TRANSFER_COMMISSIONING_SPONSOR', fields, so, ao);
                  await postJSON(`/api/v1/commissioning-functions/${encodeURIComponent(fn.function_id)}/transfer`, env);
                  return;
                }
              }
              const soHw = activeWebAuthnPrincipals.find((p) => p.role === 'SERVICE_OWNER');
              const aoHw = activeWebAuthnPrincipals.find((p) => p.role === 'AUTHORIZING_OFFICIAL');
              if (soHw && aoHw) {
                const env = await buildDualPrincipalGovernanceEnvelopeWebAuthn(
                  'TRANSFER_COMMISSIONING_SPONSOR',
                  fields,
                  soHw,
                  aoHw,
                  rpId
                );
                await postJSON(`/api/v1/commissioning-functions/${encodeURIComponent(fn.function_id)}/transfer`, env);
                return;
              }
              throw new Error('2-of-2 active SERVICE_OWNER + AUTHORIZING_OFFICIAL keys required for sponsor transfer');
            }}
            onRevokeSigner={async (principalId, keyFp) => {
              const target = snapshot.principals.find(
                (p) => p.principal_id === principalId || p.key_fingerprint === keyFp
              );
              const targetRole = target?.role;
              const revFields: Record<string, unknown> = {
                http_method: 'POST',
                canonical_path: '/api/v1/principals/revoke',
                target_principal_id: principalId,
                target_key_fingerprint: keyFp,
                reason_code: 'OPERATOR_KEY_REVOCATION_DRILL',
              };
              // v1.0.3: 1-of-2 REVOKE_PRINCIPAL is strictly self-revocation (signer.principal_id === target.principal_id);
              // revoking any peer principal requires a 2-of-2 DSSE ceremony (SERVICE_OWNER + AUTHORIZING_OFFICIAL).
              const survivingSameRole = snapshot.principals.filter(
                (p) => !p.revoked && p.role === targetRole && p.principal_id !== principalId
              );
              if (smartcardBarEnabled) {
                const selfPersona = activePersonas.find((p) => p.principal_id === principalId);
                if (selfPersona && survivingSameRole.length >= 1) {
                  const env = buildSinglePrincipalGovernanceEnvelope('REVOKE_PRINCIPAL', revFields, selfPersona);
                  await postJSON('/api/v1/principals/revoke', env);
                  return;
                }
                const soPersona = activePersonas.find((p) => p.role === 'SERVICE_OWNER');
                const aoPersona = activePersonas.find((p) => p.role === 'AUTHORIZING_OFFICIAL');
                if (soPersona && aoPersona) {
                  const env = buildDualPrincipalGovernanceEnvelope('REVOKE_PRINCIPAL', revFields, soPersona, aoPersona);
                  await postJSON('/api/v1/principals/revoke', env);
                  return;
                }
              }
              const selfHw = activeWebAuthnPrincipals.find((p) => p.principal_id === principalId);
              if (selfHw && survivingSameRole.length >= 1) {
                const env = await buildSinglePrincipalGovernanceEnvelopeWebAuthn(
                  'REVOKE_PRINCIPAL',
                  revFields,
                  selfHw,
                  rpId
                );
                await postJSON('/api/v1/principals/revoke', env);
                return;
              }
              const soHw = activeWebAuthnPrincipals.find((p) => p.role === 'SERVICE_OWNER');
              const aoHw = activeWebAuthnPrincipals.find((p) => p.role === 'AUTHORIZING_OFFICIAL');
              if (soHw && aoHw) {
                const env = await buildDualPrincipalGovernanceEnvelopeWebAuthn(
                  'REVOKE_PRINCIPAL',
                  revFields,
                  soHw,
                  aoHw,
                  rpId
                );
                await postJSON('/api/v1/principals/revoke', env);
                return;
              }
              throw new Error(
                `1-of-2 revocation is restricted strictly to self-revocation with >=1 ${targetRole || 'same-role'} backup; peer revocation requires 2-of-2 SO+AO co-signatures (or atomic rotate-and-revoke)`
              );
            }}
            onResolveException={async (exceptionId, decision, env) => {
              await postJSON(`/api/v1/exceptions/${exceptionId}/resolve`, {
                decision,
                dsse_envelope: env,
              });
            }}
            onEnrollWebAuthn={async (payload, adminToken, dualEnv) => {
              if (dualEnv) {
                await postJSON('/api/v1/principals/webauthn/register', dualEnv);
                return;
              }
              if (snapshot.bootstrap_state?.sealed) {
                const so = activePersonas.find((p) => p.role === 'SERVICE_OWNER');
                const ao = activePersonas.find((p) => p.role === 'AUTHORIZING_OFFICIAL');
                if (so && ao) {
                  const env = buildDualPrincipalGovernanceEnvelope('ENROLL_PRINCIPAL', payload, so, ao);
                  await postJSON('/api/v1/principals/webauthn/register', env);
                  return;
                }
              }
              const headers: Record<string, string> = {};
              if (adminToken && adminToken.trim()) {
                headers['X-Warrant-Admin-Token'] = adminToken.trim();
              }
              await postJSON('/api/v1/principals/webauthn/register', payload, headers);
            }}
          />
        )}

        {activeView === 'VIEW3_SHADOW' && (
          <View3ShadowEstate
            shadowRuns={snapshot.shadow_runs}
            estate={snapshot.estate}
            remediations={snapshot.remediations}
          />
        )}

        {activeView === 'VIEW4_CONTAINMENT' && (
          <View4ContainmentLockout
            bridges={snapshot.bridges}
            lockouts={snapshot.lockouts}
            drifts={snapshot.drifts}
            distributors={snapshot.distributors}
            deploymentOrders={snapshot.deployment_orders}
            deploymentResults={snapshot.deployment_results}
            nowMs={nowMs}
            onRollbackOrder={async (orderId, reason) => {
              await postActionJSON(
                `/api/v1/distributors/orders/${encodeURIComponent(orderId)}/rollback`,
                { reason_code: reason },
                'EMERGENCY_ROLLBACK',
                { reason_code: reason }
              );
            }}
          />
        )}

        {activeView === 'VIEW5_AUDITOR' && (
          <View5AuditorLedger
            attestations={snapshot.attestations}
            agentActions={snapshot.agent_actions}
            witnessMode={snapshot.witness_mode || snapshot.scoreboard.witness_mode}
            kernelPublicKey={snapshot.kernel_public_key}
            onMintAuditorLink={async (label, scopedIds, ttlHours) => {
              return (await postActionJSON(
                '/api/v1/auditor-tokens',
                { label, scoped_attestation_ids: scopedIds, ttl_hours: ttlHours },
                'MINT_AUDITOR_TOKEN',
                {
                  auditor_label: label,
                  scoped_attestation_ids: scopedIds,
                  ttl_hours: ttlHours,
                }
              )) as { auditor_url?: string };
            }}
          />
        )}
      </main>

      {showFeedsModal && snapshot.feed_status && (
        <LiveFeedsModal
          feedStatus={snapshot.feed_status}
          automationToken={automationToken}
          onChangeAutomationToken={saveAutomationToken}
          onClose={() => setShowFeedsModal(false)}
          onSaveConfig={async (cfg) => {
            await postActionJSON('/api/v1/feeds/config', cfg, 'FEED_MUTATION', {}, true);
          }}
          onSyncKEV={async () => {
            await postActionJSON('/api/v1/feeds/sync/kev', {}, 'FEED_MUTATION', {}, true);
          }}
          onSyncOSV={async () => {
            await postActionJSON('/api/v1/feeds/sync/osv', {}, 'FEED_MUTATION', {}, true);
          }}
          onIngestOSV={async (osvId, serviceId) => {
            await postActionJSON(
              '/api/v1/feeds/osv/ingest',
              { osv_id: osvId, service_id: serviceId },
              'FEED_MUTATION',
              {},
              true
            );
            setShowFeedsModal(false);
            setActiveView('VIEW1_RACE');
          }}
        />
      )}
    </div>
  );
};
