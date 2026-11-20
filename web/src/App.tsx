import React, { useCallback, useEffect, useState } from 'react';
import { Activity, FileSignature, GitCompare, ShieldAlert, Vault } from 'lucide-react';
import type { BootstrapSnapshot, DSSEEnvelope } from './types';
import {
  buildDualPrincipalGovernanceEnvelope,
  buildSinglePrincipalGovernanceEnvelope,
  bytesToBase64,
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

  const postJSON = async (url: string, body: unknown, extraHeaders?: Record<string, string>) => {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(extraHeaders || {}) },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    await loadBootstrap();
    return data;
  };

  if (!snapshot) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 text-slate-700 font-mono text-xs">
        INITIALIZING G1-WARRANT DETERMINISTIC CONTROL PLANE...
      </div>
    );
  }

  const pendingExceptionsCount = snapshot.exceptions.filter((e) => e.status === 'PENDING_DUAL_KEY').length;

  const revokedIds = new Set(
    snapshot.principals.filter((p) => p.revoked).map((p) => p.principal_id)
  );
  const activePersonas = snapshot.test_personas.filter(
    (tp) =>
      (tp.role === 'SERVICE_OWNER' || tp.role === 'AUTHORIZING_OFFICIAL') &&
      !revokedIds.has(tp.principal_id)
  );
  const buildGovHeaders = (action: string, fields: Record<string, unknown> = {}): Record<string, string> => {
    if (activePersonas.length === 0) return {};
    const env = buildSinglePrincipalGovernanceEnvelope(action, fields, activePersonas[0]);
    const b64 = bytesToBase64(utf8ToBytes(JSON.stringify(env)));
    return { 'X-Warrant-Governance-DSSE': b64 };
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
          await postJSON(
            '/api/v1/freeze',
            { mode, actor, reason_code: reason },
            buildGovHeaders('EMERGENCY_FREEZE', { freeze_mode: mode, reason_code: reason })
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
            nowMs={nowMs}
            onSimulate={async (sc) => {
              await postJSON(`/api/v1/simulate/${sc}`, {}, buildGovHeaders('SIMULATION_DRILL', { scenario: sc }));
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
            testPersonas={snapshot.test_personas}
            rpId={snapshot.webauthn?.rp_id || 'localhost'}
            smartcardBarEnabled={smartcardBarEnabled}
            isMobileViewport={isMobileViewport}
            onCreateWarrant={async (env) => {
              await postJSON('/api/v1/warrants', env);
            }}
            onRevokeSigner={async (principalId, keyFp) => {
              const signer =
                activePersonas.find((p) => p.principal_id !== principalId) || activePersonas[0];
              if (!signer) {
                throw new Error('Revoking a principal requires a 1-of-2 DSSE active principal signature (use warrant principals revoke --key <active.priv.json>)');
              }
              const env = buildSinglePrincipalGovernanceEnvelope(
                'REVOKE_PRINCIPAL',
                {
                  target_principal_id: principalId,
                  target_key_fingerprint: keyFp,
                  reason_code: 'OPERATOR_KEY_REVOCATION_DRILL',
                },
                signer
              );
              await postJSON('/api/v1/principals/revoke', env);
            }}
            onResolveException={async (exceptionId, decision, env) => {
              await postJSON(`/api/v1/exceptions/${exceptionId}/resolve`, {
                decision,
                dsse_envelope: env,
              });
            }}
            onEnrollWebAuthn={async (payload) => {
              const so = activePersonas.find((p) => p.role === 'SERVICE_OWNER');
              const ao = activePersonas.find((p) => p.role === 'AUTHORIZING_OFFICIAL');
              if (so && ao) {
                const env = buildDualPrincipalGovernanceEnvelope('ENROLL_PRINCIPAL', payload, so, ao);
                await postJSON('/api/v1/principals/webauthn/register', env);
              } else {
                await postJSON('/api/v1/principals/webauthn/register', payload);
              }
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
            nowMs={nowMs}
          />
        )}

        {activeView === 'VIEW5_AUDITOR' && (
          <View5AuditorLedger
            attestations={snapshot.attestations}
            agentActions={snapshot.agent_actions}
            kernelPublicKey={snapshot.kernel_public_key}
            onMintAuditorLink={async (label, scopedIds, ttlHours) => {
              return postJSON(
                '/api/v1/auditor-tokens',
                { label, scoped_attestation_ids: scopedIds, ttl_hours: ttlHours },
                buildGovHeaders('MINT_AUDITOR_TOKEN', {
                  auditor_label: label,
                  scoped_attestation_ids: scopedIds,
                  ttl_hours: ttlHours,
                })
              );
            }}
          />
        )}
      </main>

      {showFeedsModal && snapshot.feed_status && (
        <LiveFeedsModal
          feedStatus={snapshot.feed_status}
          onClose={() => setShowFeedsModal(false)}
          onSaveConfig={async (cfg) => {
            await postJSON('/api/v1/feeds/config', cfg, buildGovHeaders('FEED_MUTATION'));
          }}
          onSyncKEV={async () => {
            await postJSON('/api/v1/feeds/sync/kev', {}, buildGovHeaders('FEED_MUTATION'));
          }}
          onSyncOSV={async () => {
            await postJSON('/api/v1/feeds/sync/osv', {}, buildGovHeaders('FEED_MUTATION'));
          }}
          onIngestOSV={async (osvId, serviceId) => {
            await postJSON(
              '/api/v1/feeds/osv/ingest',
              { osv_id: osvId, service_id: serviceId },
              buildGovHeaders('FEED_MUTATION')
            );
            setShowFeedsModal(false);
            setActiveView('VIEW1_RACE');
          }}
        />
      )}
    </div>
  );
};
