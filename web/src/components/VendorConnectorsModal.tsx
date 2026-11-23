import React, { useState } from 'react';
import { Server, X, CheckCircle2, PlugZap, Sparkles, ArrowRight } from 'lucide-react';
import type { VendorConnectorConfigStatus, VendorConnectorTestResult } from '../types';
import { shortHash } from '../lib/templates';

interface VendorConnectorsModalProps {
  connectors: VendorConnectorConfigStatus[];
  onClose: () => void;
  onRefresh: () => Promise<void>;
  onSelectForTwinInWarrantDesk: (sourceSystem: string) => void;
}

type TierFilter = 'ALL' | 'TIER_A_MACHINE' | 'TIER_B_WORKLOAD' | 'TIER_C_CENSUS';

export const VendorConnectorsModal: React.FC<VendorConnectorsModalProps> = ({
  connectors,
  onClose,
  onRefresh,
  onSelectForTwinInWarrantDesk,
}) => {
  const [tierFilter, setTierFilter] = useState<TierFilter>('ALL');
  const [expandedSystem, setExpandedSystem] = useState<string | null>(null);
  const [editReadUrl, setEditReadUrl] = useState('');
  const [editReadToken, setEditReadToken] = useState('');
  const [editDispatchUrl, setEditDispatchUrl] = useState('');
  const [editDispatchToken, setEditDispatchToken] = useState('');
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [bannerMsg, setBannerMsg] = useState<string | null>(null);
  const [bannerErr, setBannerErr] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, VendorConnectorTestResult>>({});

  const demoAvailable = connectors.some((c) => c.demo_mock_available);
  const readyCount = connectors.filter((c) => c.read_configured).length;

  const filtered = connectors.filter((c) => (tierFilter === 'ALL' ? true : c.source_tier === tierFilter));

  const openEditor = (c: VendorConnectorConfigStatus) => {
    if (expandedSystem === c.source_system) {
      setExpandedSystem(null);
      return;
    }
    setExpandedSystem(c.source_system);
    setEditReadUrl(c.read_url || '');
    setEditReadToken('');
    setEditDispatchUrl(c.dispatch_url || '');
    setEditDispatchToken('');
    setBannerErr(null);
  };

  const handleSaveConnector = async (c: VendorConnectorConfigStatus) => {
    if (
      editReadToken.trim() !== '' &&
      editDispatchToken.trim() !== '' &&
      editReadToken.trim() === editDispatchToken.trim()
    ) {
      setBannerErr(
        `CREDENTIAL_SEPARATION_VIOLATION (${c.source_system}): Read-Only Token and WN-8 Dispatch Token must be strictly distinct.`
      );
      return;
    }
    setBusyKey(`save:${c.source_system}`);
    setBannerErr(null);
    setBannerMsg(null);
    try {
      const res = await fetch(`/api/v1/estate-loader/connectors/${encodeURIComponent(c.source_system)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          read_url: editReadUrl.trim(),
          read_token: editReadToken.trim() || undefined,
          dispatch_url: c.supports_wn8_dispatch ? editDispatchUrl.trim() : undefined,
          dispatch_token: c.supports_wn8_dispatch && editDispatchToken.trim() ? editDispatchToken.trim() : undefined,
        }),
      });
      const body = await res.json();
      if (!res.ok) {
        throw new Error(body.error || body.reason || `HTTP ${res.status}`);
      }
      await onRefresh();
      setEditReadToken('');
      setEditDispatchToken('');
      setBannerMsg(`Saved connector configuration for ${c.source_system}.`);
    } catch (err) {
      setBannerErr(err instanceof Error ? err.message : 'Failed to save connector');
    } finally {
      setBusyKey(null);
    }
  };

  const handleConnectDemoMock = async (systemId: string) => {
    setBusyKey(`demo:${systemId}`);
    setBannerErr(null);
    setBannerMsg(null);
    try {
      const res = await fetch('/api/v1/estate-loader/connectors/demo-mock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ system_id: systemId }),
      });
      const body = await res.json();
      if (!res.ok) {
        throw new Error(body.error || body.reason || `HTTP ${res.status}`);
      }
      await onRefresh();
      setBannerMsg(
        systemId === '*'
          ? 'Connected all 18 systems to fleet-sim Demo Estate Mock (distinct Read & Dispatch tokens wired).'
          : `Connected ${systemId} to fleet-sim Demo Estate Mock.`
      );
    } catch (err) {
      setBannerErr(err instanceof Error ? err.message : 'Failed to attach Demo Estate Mock');
    } finally {
      setBusyKey(null);
    }
  };

  const handleTestRead = async (systemId: string) => {
    setBusyKey(`test:${systemId}`);
    setBannerErr(null);
    try {
      const res = await fetch(`/api/v1/estate-loader/connectors/${encodeURIComponent(systemId)}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          warrant_class: 'KEV-TIER1-STATELESS',
          scope_services: ['payments-ledger-api', 'identity-sso-gateway'],
        }),
      });
      const body = await res.json();
      if (!res.ok) {
        throw new Error(body.error || body.reason || `HTTP ${res.status}`);
      }
      const tr = body as VendorConnectorTestResult;
      setTestResults((prev) => ({ ...prev, [systemId]: tr }));
    } catch (err) {
      setBannerErr(err instanceof Error ? err.message : 'Connector read test failed');
    } finally {
      setBusyKey(null);
    }
  };

  const modeBadgeClass = (mode: VendorConnectorConfigStatus['connection_mode']) => {
    switch (mode) {
      case 'DEMO_MOCK':
        return 'bg-emerald-50 border-emerald-400 text-emerald-950';
      case 'LIVE_CUSTOM':
        return 'bg-indigo-50 border-indigo-400 text-indigo-950';
      case 'LOCAL_CLUSTER':
        return 'bg-slate-100 border-slate-400 text-slate-900';
      default:
        return 'bg-amber-50 border-amber-400 text-amber-950';
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="vendor-connectors-modal-title"
      className="fixed inset-0 z-50 bg-slate-950/60 flex items-center justify-center p-4"
    >
      <div className="bg-white border border-slate-300 rounded-lg shadow-2xl max-w-5xl w-full max-h-[90vh] flex flex-col">
        <div className="px-4 py-3 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <PlugZap className="w-4 h-4 text-slate-900" />
            <div>
              <h2 id="vendor-connectors-modal-title" className="text-sm font-bold text-slate-900">
                18-Vendor Estate Loader &amp; WN-8 Distributor Connections ({readyCount}/{connectors.length} Ready)
              </h2>
              <p className="text-xs text-slate-600">
                Configure bounded decision-time Read URLs/Tokens (separate from WN-8 Dispatch credentials) or attach the wire-accurate Demo Estate Mock.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {demoAvailable && (
              <button
                type="button"
                onClick={() => handleConnectDemoMock('*')}
                disabled={busyKey !== null}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-bold disabled:opacity-50"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>{busyKey === 'demo:*' ? 'Connecting 18 Vendors...' : 'Connect All 18 to Demo Estate'}</span>
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              aria-label="Close Vendor Connections Modal"
              className="p-1.5 rounded border border-slate-300 bg-white hover:bg-slate-100 text-slate-700"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="px-4 py-2.5 border-b border-slate-200 bg-slate-50 flex flex-wrap items-center justify-between gap-2 text-xs">
          <div className="flex flex-wrap gap-1.5">
            {(
              [
                ['ALL', `All (${connectors.length})`],
                ['TIER_A_MACHINE', 'Tier A: Machine Truth (12)'],
                ['TIER_B_WORKLOAD', 'Tier B: Kubernetes (3)'],
                ['TIER_C_CENSUS', 'Tier C: Scanners Census Only (3)'],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                onClick={() => setTierFilter(key)}
                className={`px-2.5 py-1 rounded border font-mono font-semibold ${
                  tierFilter === key
                    ? 'bg-slate-900 text-white border-slate-900'
                    : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-100'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
          <span className="font-mono text-[11px] text-slate-600">
            Zero Asset Replication · Tokens Write-Only (Masked) · Read != Dispatch Enforced
          </span>
        </div>

        <div className="p-4 overflow-y-auto space-y-2.5 flex-1">
          {bannerErr && (
            <div role="alert" className="p-2.5 rounded border border-red-400 bg-red-50 text-red-950 text-xs font-mono">
              {bannerErr}
            </div>
          )}
          {bannerMsg && (
            <div role="status" className="p-2.5 rounded border border-emerald-400 bg-emerald-50 text-emerald-950 text-xs font-mono">
              {bannerMsg}
            </div>
          )}

          {filtered.map((c) => {
            const isExpanded = expandedSystem === c.source_system;
            const tr = testResults[c.source_system];
            return (
              <div key={c.source_system} className="border border-slate-200 rounded bg-white p-3 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="space-y-0.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <Server className="w-3.5 h-3.5 text-slate-700" />
                      <span className="text-xs font-mono font-bold text-slate-900">{c.source_system}</span>
                      <span className="text-xs text-slate-700 font-medium">{c.display_name}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 border border-slate-300 text-slate-800">
                        {c.source_tier}
                      </span>
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${modeBadgeClass(c.connection_mode)}`}>
                        {c.connection_mode}
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-slate-600">
                      Read: {c.read_url || (c.connection_mode === 'LOCAL_CLUSTER' ? 'in-cluster / local workload state' : 'unconfigured')}{' '}
                      {c.read_token_configured ? `(token ${c.read_token_masked})` : ''}
                      {c.supports_wn8_dispatch && (
                        <>
                          {' · '}WN-8 Dispatch: {c.dispatch_url || 'simulated'}{' '}
                          {c.dispatch_token_configured ? `(token ${c.dispatch_token_masked})` : ''}
                        </>
                      )}
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5 text-xs">
                    {c.demo_mock_available && c.connection_mode !== 'DEMO_MOCK' && (
                      <button
                        type="button"
                        onClick={() => handleConnectDemoMock(c.source_system)}
                        disabled={busyKey !== null}
                        className="px-2.5 py-1 rounded border border-emerald-400 bg-emerald-50 hover:bg-emerald-100 text-emerald-950 font-semibold"
                      >
                        Attach Demo Mock
                      </button>
                    )}
                    {c.read_configured && (
                      <button
                        type="button"
                        onClick={() => handleTestRead(c.source_system)}
                        disabled={busyKey !== null}
                        className="px-2.5 py-1 rounded border border-slate-300 bg-slate-50 hover:bg-slate-100 text-slate-800 font-semibold"
                      >
                        {busyKey === `test:${c.source_system}` ? 'Testing...' : 'Test Read'}
                      </button>
                    )}
                    {c.can_propose_clone_sources && c.read_configured && (
                      <button
                        type="button"
                        onClick={() => onSelectForTwinInWarrantDesk(c.source_system)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-white font-semibold"
                      >
                        <span>Select Servers to Twin</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => openEditor(c)}
                      className="px-2.5 py-1 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-800 font-semibold"
                    >
                      {isExpanded ? 'Hide Config' : 'Configure'}
                    </button>
                  </div>
                </div>

                {tr && (
                  <div className="p-2 rounded border border-emerald-300 bg-emerald-50/60 text-[11px] font-mono text-slate-900 space-y-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="inline-flex items-center gap-1 font-bold text-emerald-950">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-700" />
                        <span>
                          LIVE READ OK · Members={tr.class_membership_count} · Clone Templates={tr.candidate_source_count} · Snapshot={shortHash(tr.snapshot_sha256 || '')}
                        </span>
                      </span>
                      <span className="text-slate-600">Freshness Age: {tr.freshness_age_seconds}s</span>
                    </div>
                    {tr.selectable_servers && tr.selectable_servers.length > 0 && (
                      <div className="text-slate-700">
                        Discoverable Servers ({tr.selectable_servers.length}):{' '}
                        {tr.selectable_servers.map((sv) => `${sv.hostname} [${sv.twin_image_identity}]`).join(' · ')}
                      </div>
                    )}
                  </div>
                )}

                {isExpanded && (
                  <div className="border-t border-slate-200 pt-2.5 grid grid-cols-1 md:grid-cols-2 gap-2.5 text-xs">
                    <div>
                      <label htmlFor={`read-url-${c.source_system}`} className="block font-semibold text-slate-700 mb-1">
                        Read-Only Inventory URL ({c.read_env_prefix}_READ_URL)
                      </label>
                      <input
                        id={`read-url-${c.source_system}`}
                        type="url"
                        value={editReadUrl}
                        onChange={(e) => setEditReadUrl(e.target.value)}
                        placeholder={`https://${c.source_system}.corp.example`}
                        className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono bg-white text-slate-900"
                      />
                    </div>
                    <div>
                      <label htmlFor={`read-tok-${c.source_system}`} className="block font-semibold text-slate-700 mb-1">
                        Read-Only Bearer Token ({c.read_env_prefix}_READ_TOKEN)
                      </label>
                      <input
                        id={`read-tok-${c.source_system}`}
                        type="password"
                        value={editReadToken}
                        onChange={(e) => setEditReadToken(e.target.value)}
                        placeholder={c.read_token_configured ? `Configured (${c.read_token_masked}) — enter new to replace` : 'Read-only API token'}
                        className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono bg-white text-slate-900"
                      />
                    </div>

                    {c.supports_wn8_dispatch && (
                      <>
                        <div>
                          <label htmlFor={`disp-url-${c.source_system}`} className="block font-semibold text-slate-700 mb-1">
                            WN-8 Patch Dispatch URL ({c.dispatch_env_prefix}_URL)
                          </label>
                          <input
                            id={`disp-url-${c.source_system}`}
                            type="url"
                            value={editDispatchUrl}
                            onChange={(e) => setEditDispatchUrl(e.target.value)}
                            placeholder={`https://${c.source_system}.corp.example`}
                            className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono bg-white text-slate-900"
                          />
                        </div>
                        <div>
                          <label htmlFor={`disp-tok-${c.source_system}`} className="block font-semibold text-slate-700 mb-1">
                            WN-8 Dispatch Token ({c.dispatch_env_prefix}_TOKEN — MUST differ from Read Token)
                          </label>
                          <input
                            id={`disp-tok-${c.source_system}`}
                            type="password"
                            value={editDispatchToken}
                            onChange={(e) => setEditDispatchToken(e.target.value)}
                            placeholder={c.dispatch_token_configured ? `Configured (${c.dispatch_token_masked}) — enter new to replace` : 'Privileged patch dispatch token'}
                            className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono bg-white text-slate-900"
                          />
                        </div>
                      </>
                    )}

                    <div className="md:col-span-2 flex justify-end gap-2 pt-1">
                      <button
                        type="button"
                        onClick={() => setExpandedSystem(null)}
                        className="px-3 py-1.5 rounded border border-slate-300 bg-white text-slate-700 font-semibold"
                      >
                        Cancel
                      </button>
                      <button
                        type="button"
                        onClick={() => handleSaveConnector(c)}
                        disabled={busyKey !== null}
                        className="px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-800 text-white font-bold disabled:opacity-50"
                      >
                        {busyKey === `save:${c.source_system}` ? 'Saving...' : `Save ${c.source_system} Config`}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
