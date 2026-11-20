import React, { useRef, useState } from 'react';
import { Shield, AlertOctagon, Inbox, CreditCard, Lock, Unlock, X, Radio } from 'lucide-react';
import type { DSSEEnvelope, GlobalScoreboard, LiveFeedStatus, Principal, TestSmartcardPersona } from '../types';
import { formatDurationSeconds } from '../lib/templates';
import { DualKeyCeremonyPanel } from './DualKeyCeremonyPanel';

interface CommandBarProps {
  scoreboard: GlobalScoreboard;
  feedStatus?: LiveFeedStatus;
  testPersonas: TestSmartcardPersona[];
  principals: Principal[];
  rpId: string;
  smartcardBarEnabled: boolean;
  onToggleSmartcardBar: () => void;
  onOpenLiveFeeds: () => void;
  isMobileViewport: boolean;
  onOpenInbox: () => void;
  onTriggerFreeze: (mode: 'FREEZE_HOLD' | 'FREEZE_ROLLBACK', actor: string, reason: string) => Promise<void>;
  onThawFreeze: (env: DSSEEnvelope) => Promise<void>;
}

export const CommandBar: React.FC<CommandBarProps> = ({
  scoreboard,
  feedStatus,
  testPersonas,
  principals,
  rpId,
  smartcardBarEnabled,
  onToggleSmartcardBar,
  onOpenLiveFeeds,
  isMobileViewport,
  onOpenInbox,
  onTriggerFreeze,
  onThawFreeze,
}) => {
  const [holdProgress, setHoldProgress] = useState(0);
  const holdInterval = useRef<number | null>(null);
  const [showFreezeModal, setShowFreezeModal] = useState(false);
  const [showThawModal, setShowThawModal] = useState(false);
  const [freezeMode, setFreezeMode] = useState<'FREEZE_HOLD' | 'FREEZE_ROLLBACK'>('FREEZE_HOLD');
  const [freezeActor, setFreezeActor] = useState('ops-duty-officer@g1163rt.sec');
  const [freezeReason, setFreezeReason] = useState('ANOMALOUS_UPSTREAM_TELEMETRY');
  const [submittingFreeze, setSubmittingFreeze] = useState(false);
  const [freezeError, setFreezeError] = useState<string | null>(null);

  const fs = scoreboard.freeze_state;
  const isFrozen = fs.mode !== 'OPERATIONAL';

  const startHold = () => {
    if (holdInterval.current !== null) return;
    const start = Date.now();
    holdInterval.current = window.setInterval(() => {
      const elapsed = Date.now() - start;
      const pct = Math.min(100, (elapsed / 950) * 100);
      setHoldProgress(pct);
      if (pct >= 100) {
        stopHold();
        setShowFreezeModal(true);
      }
    }, 30);
  };

  const stopHold = () => {
    if (holdInterval.current !== null) {
      window.clearInterval(holdInterval.current);
      holdInterval.current = null;
    }
    setHoldProgress(0);
  };

  const submitFreeze = async () => {
    setSubmittingFreeze(true);
    setFreezeError(null);
    try {
      await onTriggerFreeze(freezeMode, freezeActor, freezeReason);
      setShowFreezeModal(false);
    } catch (err) {
      setFreezeError(err instanceof Error ? err.message : 'Emergency freeze failed');
    } finally {
      setSubmittingFreeze(false);
    }
  };

  return (
    <header className="sticky top-0 z-30 bg-white border-b border-slate-300 shadow-sm">
      {isMobileViewport && (
        <div
          role="status"
          className="bg-amber-950 text-amber-100 px-4 py-1.5 text-xs font-medium flex items-center justify-between"
        >
          <span>
            MOBILE POSTURE (&lt; 1024px): Read + Pager + Hold-to-Freeze Active. Dual-Key Warrant Signing Disabled by Policy.
          </span>
          <span className="font-mono text-[11px] uppercase">NIST AC-5 / Section 508</span>
        </div>
      )}

      <div className="max-w-[1600px] mx-auto px-4 py-2.5 flex flex-wrap items-center justify-between gap-3">
        {/* Left: Brand & System Posture Pill */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2.5">
            <img
              src="/g1-logo.jpg"
              alt="G1-Warrant Logo"
              className="w-9 h-9 rounded object-contain bg-white border border-slate-200 p-0.5 shadow-sm"
            />
            <div>
              <div className="text-sm font-bold tracking-tight text-slate-900 leading-none">G1-WARRANT</div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
                G1163RT Security Labs · Control Plane
              </div>
            </div>
          </div>

          {!isFrozen ? (
            <div
              role="status"
              className="inline-flex items-center gap-2 px-3 py-1 rounded border border-emerald-300 bg-emerald-50 text-emerald-950 text-xs font-semibold"
            >
              <span className="w-2 h-2 rounded-full bg-emerald-600 animate-pulse" />
              <span>OPERATIONAL [{scoreboard.active_warrants_count} Active Warrants]</span>
            </div>
          ) : (
            <div
              role="alert"
              className="inline-flex items-center gap-2 px-3 py-1 rounded border border-red-500 bg-red-600 text-white text-xs font-bold"
            >
              <AlertOctagon className="w-4 h-4" />
              <span>
                {fs.mode === 'FREEZE_HOLD' ? 'FREEZE: HOLD' : 'FREEZE: ROLLBACK'} · {fs.actor} ·{' '}
                {new Date(fs.updated_at).toLocaleTimeString()}
              </span>
            </div>
          )}
        </div>

        {/* Center: Rolling 30d Central Scoreboard */}
        <div className="flex items-center divide-x divide-slate-200 border border-slate-200 rounded bg-slate-50 px-2 py-1">
          <div className="px-3">
            <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">30d Fleet Median TTVR</div>
            <div className="text-sm font-mono font-bold text-slate-900 tabular-nums">
              {formatDurationSeconds(scoreboard.fleet_median_ttvr_seconds)}
              <span className="text-[11px] font-normal text-emerald-700 ml-1.5">(vs 43d manual)</span>
            </div>
          </div>
          <div className="px-3">
            <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Active Bridges Armed</div>
            <div className="text-sm font-mono font-bold text-slate-900 tabular-nums">
              {scoreboard.active_bridges_armed}{' '}
              <span className="text-[11px] font-normal text-amber-800">
                (med {formatDurationSeconds(scoreboard.median_bridge_age_seconds)})
              </span>
            </div>
          </div>
          <div className="px-3">
            <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
              Autonomous Estate Eligibility
            </div>
            <div className="text-sm font-mono font-bold text-slate-900 tabular-nums">
              {scoreboard.autonomous_eligibility_pct.toFixed(1)}%{' '}
              <span className="text-[11px] font-normal text-slate-600">
                ({scoreboard.eligible_services_count}/{scoreboard.total_services_count})
              </span>
            </div>
          </div>
        </div>

        {/* Right Tray: Witness Mode + Live Feeds + Smartcard Toggle + Action Inbox Badge + Hold-to-Freeze / Dual-Key Thaw */}
        <div className="flex items-center gap-2">
          <span
            role="status"
            title={
              scoreboard.witness_mode === 'EXTERNAL_NOTARY'
                ? 'Ledger Merkle checkpoints are anchored to an external transparency notary (WARRANT_EXTERNAL_ANCHOR_URL).'
                : 'Ledger Merkle checkpoints are anchored in-process/locally only (configure WARRANT_EXTERNAL_ANCHOR_URL for external notary anchoring).'
            }
            className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded border text-[11px] font-mono font-semibold ${
              scoreboard.witness_mode === 'EXTERNAL_NOTARY'
                ? 'bg-emerald-50 border-emerald-400 text-emerald-950'
                : 'bg-amber-50 border-amber-400 text-amber-950'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Witness: {scoreboard.witness_mode || 'IN_PROCESS_LOCAL'}</span>
          </span>

          <button
            type="button"
            onClick={onOpenLiveFeeds}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded border text-xs font-mono font-semibold transition ${
              feedStatus?.config.mode === 'live'
                ? 'bg-emerald-50 border-emerald-400 text-emerald-950 hover:bg-emerald-100'
                : 'bg-slate-100 border-slate-300 text-slate-700 hover:bg-slate-200'
            }`}
            title="Configure Optional Live Threat & Scanner Feeds (CISA KEV, Google OSV.dev, Aquasec Trivy)"
          >
            <Radio className={`w-3.5 h-3.5 ${feedStatus?.config.mode === 'live' ? 'text-emerald-600' : 'text-slate-500'}`} />
            <span>
              Feeds: {feedStatus?.config.mode === 'live' ? `LIVE (KEV:${feedStatus.cisa_kev_catalog_count})` : 'OFFLINE'}
            </span>
          </button>

          <button
            type="button"
            onClick={onToggleSmartcardBar}
            aria-pressed={smartcardBarEnabled}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded border text-xs font-medium transition ${
              smartcardBarEnabled
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
            }`}
            title="Toggle Deterministic FIPS/Ed25519 Test Smartcard Bar"
          >
            <CreditCard className="w-3.5 h-3.5" />
            <span>FIPS Smartcard Bar: {smartcardBarEnabled ? 'ON' : 'OFF'}</span>
          </button>

          <button
            type="button"
            onClick={onOpenInbox}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded border text-xs font-semibold transition ${
              scoreboard.awaiting_dual_key_inbox_count > 0
                ? 'bg-amber-50 border-amber-400 text-amber-950 hover:bg-amber-100'
                : 'bg-white border-slate-300 text-slate-700 hover:bg-slate-50'
            }`}
          >
            <Inbox className="w-3.5 h-3.5" />
            <span>{scoreboard.awaiting_dual_key_inbox_count} Awaiting Dual-Key</span>
          </button>

          {!isFrozen ? (
            <button
              type="button"
              onMouseDown={startHold}
              onMouseUp={stopHold}
              onMouseLeave={stopHold}
              onTouchStart={startHold}
              onTouchEnd={stopHold}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') startHold();
              }}
              onKeyUp={stopHold}
              aria-label="Hold to activate emergency fleet freeze"
              className="relative overflow-hidden inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded border border-red-700 bg-red-600 hover:bg-red-700 text-white text-xs font-bold tracking-wide select-none"
            >
              <span
                className="absolute inset-y-0 left-0 bg-red-950/50 transition-all duration-75"
                style={{ width: `${holdProgress}%` }}
              />
              <Lock className="w-3.5 h-3.5 relative z-10" />
              <span className="relative z-10">
                {holdProgress > 0 ? `HOLDING ${Math.round(holdProgress)}%` : '[ HOLD TO FREEZE FLEET ]'}
              </span>
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setShowThawModal(true)}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded border border-emerald-700 bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-bold"
            >
              <Unlock className="w-3.5 h-3.5" />
              <span>[ THAW FLEET (2-OF-2 REQUIRED) ]</span>
            </button>
          )}
        </div>
      </div>

      {/* Deterministic FIPS/Ed25519 Test Smartcard Bar */}
      {smartcardBarEnabled && (
        <div className="bg-slate-900 text-slate-200 border-t border-slate-800 px-4 py-1.5">
          <div className="max-w-[1600px] mx-auto flex flex-wrap items-center justify-between gap-2 text-[11px]">
            <div className="flex items-center gap-2 font-mono">
              <Shield className="w-3.5 h-3.5 text-emerald-400" />
              <span className="font-semibold text-white">DETERMINISTIC FIPS/ED25519 TEST SMARTCARD BAR:</span>
              <span className="text-slate-400">Real client-side RFC 8032 Ed25519 PAE signing + W3C WebAuthn active</span>
            </div>
            <div className="flex flex-wrap items-center gap-2 font-mono">
              {testPersonas
                .filter((p) => ['usr-alice-so', 'usr-bob-ao', 'usr-mallory-so', 'usr-carol-sysadmin'].includes(p.principal_id))
                .map((p) => (
                  <span
                    key={p.key_id}
                    className={`px-2 py-0.5 rounded border ${
                      p.principal_id.includes('mallory') || p.principal_id.includes('carol')
                        ? 'border-rose-700 bg-rose-950/60 text-rose-200'
                        : 'border-slate-700 bg-slate-800 text-slate-200'
                    }`}
                  >
                    {p.badge_label} · fp:{p.key_fingerprint.slice(0, 8)}
                  </span>
                ))}
            </div>
          </div>
        </div>
      )}

      {/* Freeze Modal */}
      {showFreezeModal && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="freeze-modal-title"
          className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4"
        >
          <div className="bg-white border border-slate-300 rounded-md shadow-xl max-w-lg w-full p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <h2 id="freeze-modal-title" className="text-sm font-bold uppercase tracking-wider text-red-900 flex items-center gap-2">
                <AlertOctagon className="w-4 h-4 text-red-600" />
                Asymmetric Fleet-Wide Emergency Freeze
              </h2>
              <button
                type="button"
                aria-label="Close emergency freeze modal"
                onClick={() => setShowFreezeModal(false)}
                className="text-slate-500 hover:text-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="bg-emerald-50 border border-emerald-300 rounded p-3 text-xs text-emerald-950">
              <strong>SAFETY INVARIANT CONFIRMED:</strong> Emergency Freeze halts only <code className="font-mono">N2</code> rollout mutations. Active <code className="font-mono">CiliumNetworkPolicy</code> containment bridges and <code className="font-mono">N3</code> sub-second runtime drift re-arming remain <strong>100% ARMED</strong>.
            </div>

            <div className="space-y-2">
              <div className="block text-xs font-bold text-slate-700">Select Freeze Posture</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setFreezeMode('FREEZE_HOLD')}
                  className={`p-3 text-left rounded border text-xs ${
                    freezeMode === 'FREEZE_HOLD'
                      ? 'border-red-600 bg-red-50 text-red-950 font-semibold'
                      : 'border-slate-200 bg-white text-slate-700'
                  }`}
                >
                  <div className="font-bold">FREEZE: HOLD CANARIES</div>
                  <div className="text-[11px] mt-1 opacity-90">Block new rollouts; hold in-flight canaries at current weight.</div>
                </button>
                <button
                  type="button"
                  onClick={() => setFreezeMode('FREEZE_ROLLBACK')}
                  className={`p-3 text-left rounded border text-xs ${
                    freezeMode === 'FREEZE_ROLLBACK'
                      ? 'border-red-600 bg-red-50 text-red-950 font-semibold'
                      : 'border-slate-200 bg-white text-slate-700'
                  }`}
                >
                  <div className="font-bold">FREEZE: ROLLBACK CANARIES</div>
                  <div className="text-[11px] mt-1 opacity-90">Block new rollouts; trigger immediate rollback of all active canaries.</div>
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label htmlFor="freeze-actor-input" className="block text-xs font-semibold text-slate-700 mb-1">
                  Authenticated Actor
                </label>
                <input
                  id="freeze-actor-input"
                  type="text"
                  value={freezeActor}
                  onChange={(e) => setFreezeActor(e.target.value)}
                  className="w-full border border-slate-300 rounded px-2.5 py-1.5 text-xs font-mono"
                />
              </div>
              <div>
                <label htmlFor="freeze-reason-select" className="block text-xs font-semibold text-slate-700 mb-1">
                  Reason Code
                </label>
                <select
                  id="freeze-reason-select"
                  value={freezeReason}
                  onChange={(e) => setFreezeReason(e.target.value)}
                  className="w-full border border-slate-300 rounded px-2.5 py-1.5 text-xs font-mono bg-white"
                >
                  <option value="ANOMALOUS_UPSTREAM_TELEMETRY">ANOMALOUS_UPSTREAM_TELEMETRY</option>
                  <option value="FEDERAL_INCIDENT_DIRECTIVE">FEDERAL_INCIDENT_DIRECTIVE</option>
                  <option value="CHANGE_FREEZE_WINDOW">CHANGE_FREEZE_WINDOW</option>
                </select>
              </div>
            </div>

            {freezeError && (
              <div role="alert" className="p-2.5 rounded border border-red-400 bg-red-50 text-red-950 text-xs font-mono">
                {freezeError}
              </div>
            )}

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-200">
              <button
                type="button"
                onClick={() => setShowFreezeModal(false)}
                className="px-3 py-1.5 text-xs font-semibold border border-slate-300 rounded text-slate-700"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={submittingFreeze}
                onClick={submitFreeze}
                className="px-4 py-1.5 text-xs font-bold rounded bg-red-600 hover:bg-red-700 text-white"
              >
                {submittingFreeze ? 'ACTIVATING...' : `ACTIVATE ${freezeMode}`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Dual-Key Thaw Modal */}
      {showThawModal && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="thaw-modal-title"
          className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4"
        >
          <div className="bg-white border border-slate-300 rounded-md shadow-xl max-w-2xl w-full p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <h2 id="thaw-modal-title" className="text-sm font-bold uppercase tracking-wider text-slate-900">
                Thaw Emergency Freeze — Live 2-of-2 Dual-Key Ceremony Required
              </h2>
              <button
                type="button"
                aria-label="Close thaw modal"
                onClick={() => setShowThawModal(false)}
                className="text-slate-500 hover:text-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <p className="text-xs text-slate-700">
              Asymmetric Thaw Policy: Triggering Freeze is single-operator hold-to-activate; restoring{' '}
              <code className="font-mono font-semibold">OPERATIONAL</code> rollout authority requires distinct{' '}
              <code className="font-mono">SERVICE_OWNER</code> (Slot 1) and{' '}
              <code className="font-mono">AUTHORIZING_OFFICIAL</code> (Slot 2) cryptographic signatures.
            </p>
            <DualKeyCeremonyPanel
              title="DSSE Freeze-Thaw Authorization Envelope"
              payloadType="application/vnd.g1163rt.freeze-thaw.v1+json"
              buildPayload={() => {
                const now = new Date();
                const exp = new Date(now.getTime() + 15 * 60 * 1000);
                const suffix = Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
                return {
                  envelope_id: `thaw-ui-${suffix}`,
                  action: 'THAW',
                  freeze_epoch: fs.freeze_epoch || 2,
                  issued_at: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
                  expires_at: exp.toISOString().replace(/\.\d{3}Z$/, 'Z'),
                };
              }}
              testPersonas={testPersonas}
              principals={principals}
              rpId={rpId}
              smartcardBarEnabled={smartcardBarEnabled}
              isMobileViewport={isMobileViewport}
              submitLabel="VERIFY 2-OF-2 & THAW FLEET"
              onSubmitEnvelope={async (env) => {
                await onThawFreeze(env);
                setShowThawModal(false);
              }}
            />
          </div>
        </div>
      )}
    </header>
  );
};
