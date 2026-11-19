import React, { useState } from 'react';
import { Radio, RefreshCw, X, ShieldCheck, ArrowRight, Terminal } from 'lucide-react';
import type { FeedRuntimeConfig, LiveFeedStatus } from '../types';
import { shortHash } from '../lib/templates';

interface LiveFeedsModalProps {
  feedStatus: LiveFeedStatus;
  onClose: () => void;
  onSaveConfig: (cfg: FeedRuntimeConfig) => Promise<void>;
  onSyncKEV: () => Promise<void>;
  onSyncOSV: () => Promise<void>;
  onIngestOSV: (osvId: string, serviceId: string) => Promise<void>;
}

export const LiveFeedsModal: React.FC<LiveFeedsModalProps> = ({
  feedStatus,
  onClose,
  onSaveConfig,
  onSyncKEV,
  onSyncOSV,
  onIngestOSV,
}) => {
  const [mode, setMode] = useState<'offline' | 'live'>(feedStatus.config.mode);
  const [cisaUrl, setCisaUrl] = useState(feedStatus.config.cisa_kev_url);
  const [pollInterval, setPollInterval] = useState(feedStatus.config.kev_poll_interval);
  const [osvUrl, setOsvUrl] = useState(feedStatus.config.osv_api_url);
  const [trivyEnabled, setTrivyEnabled] = useState(feedStatus.config.trivy_enabled);

  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const runAction = async (name: string, fn: () => Promise<void>, okMsg?: string) => {
    setBusyAction(name);
    setErrorMsg(null);
    setNotice(null);
    try {
      await fn();
      if (okMsg) setNotice(okMsg);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Feed operation failed');
    } finally {
      setBusyAction(null);
    }
  };

  const isLive = feedStatus.config.mode === 'live';

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="live-feeds-title"
      className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="bg-white border border-slate-300 rounded-md shadow-2xl max-w-5xl w-full max-h-[90vh] overflow-y-auto p-5 space-y-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-slate-200 pb-3">
          <div className="flex items-center gap-2.5">
            <Radio className={`w-5 h-5 ${isLive ? 'text-emerald-600' : 'text-slate-500'}`} />
            <div>
              <h2 id="live-feeds-title" className="text-sm font-bold uppercase tracking-wider text-slate-900">
                Live Threat &amp; Scanner Feed Configuration ($0 Real Public Feeds)
              </h2>
              <div className="text-xs font-mono text-slate-500">
                CISA KEV (cisa.gov) · Google OSV.dev SBOM Lookup · Aquasec Trivy SARIF Sidecar · Sanitized via Zero-Egress warrant-extractor
              </div>
            </div>
          </div>
          <button
            type="button"
            aria-label="Close live feeds configuration modal"
            onClick={onClose}
            className="p-1 text-slate-500 hover:text-slate-800"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Configuration Form */}
        <section className="bg-slate-50 border border-slate-200 rounded p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-800">
              Runtime Feed Toggles (<code className="font-mono">WARRANT_FEED_MODE</code>)
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setMode('offline')}
                className={`px-3 py-1 rounded text-xs font-mono font-bold border ${
                  mode === 'offline'
                    ? 'bg-slate-900 text-white border-slate-900'
                    : 'bg-white text-slate-700 border-slate-300'
                }`}
              >
                offline (Air-Gapped Enclave Default)
              </button>
              <button
                type="button"
                onClick={() => setMode('live')}
                className={`px-3 py-1 rounded text-xs font-mono font-bold border ${
                  mode === 'live'
                    ? 'bg-emerald-700 text-white border-emerald-800'
                    : 'bg-white text-slate-700 border-slate-300'
                }`}
              >
                live (Real CISA KEV + OSV.dev + Trivy)
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            <div className="md:col-span-2">
              <label htmlFor="feed-cisa-url" className="block font-semibold text-slate-700 mb-1">WARRANT_CISA_KEV_URL</label>
              <input
                id="feed-cisa-url"
                type="url"
                value={cisaUrl}
                onChange={(e) => setCisaUrl(e.target.value)}
                className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono bg-white"
              />
            </div>
            <div>
              <label htmlFor="feed-poll-interval" className="block font-semibold text-slate-700 mb-1">WARRANT_KEV_POLL_INTERVAL</label>
              <input
                id="feed-poll-interval"
                type="text"
                value={pollInterval}
                onChange={(e) => setPollInterval(e.target.value)}
                className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono bg-white"
              />
            </div>
            <div className="md:col-span-2">
              <label htmlFor="feed-osv-url" className="block font-semibold text-slate-700 mb-1">WARRANT_OSV_API_URL</label>
              <input
                id="feed-osv-url"
                type="url"
                value={osvUrl}
                onChange={(e) => setOsvUrl(e.target.value)}
                className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono bg-white"
              />
            </div>
            <div className="flex items-end">
              <label htmlFor="feed-trivy-enabled" className="inline-flex items-center gap-2 font-semibold text-slate-700 pb-1.5 cursor-pointer">
                <input
                  id="feed-trivy-enabled"
                  type="checkbox"
                  checked={trivyEnabled}
                  onChange={(e) => setTrivyEnabled(e.target.checked)}
                  className="rounded border-slate-300"
                />
                WARRANT_TRIVY_ENABLED (--profile live-feeds)
              </label>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-200">
            <div className="text-[11px] font-mono text-slate-600 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5" />
              <span>CLI Sidecar Launch: docker compose --profile live-feeds up --build -d</span>
            </div>
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() =>
                runAction(
                  'save',
                  () =>
                    onSaveConfig({
                      mode,
                      cisa_kev_url: cisaUrl,
                      kev_poll_interval: pollInterval,
                      osv_api_url: osvUrl,
                      trivy_enabled: trivyEnabled,
                      updated_at: new Date().toISOString(),
                    }),
                  `Saved runtime feed configuration (mode=${mode}).`
                )
              }
              className="px-4 py-1.5 rounded bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold disabled:opacity-50"
            >
              {busyAction === 'save' ? 'Saving...' : 'Save Feed Configuration'}
            </button>
          </div>
        </section>

        {errorMsg && (
          <div role="alert" className="p-2.5 rounded border border-red-400 bg-red-50 text-red-950 text-xs font-mono">
            {errorMsg}
          </div>
        )}
        {notice && (
          <div role="status" className="p-2.5 rounded border border-emerald-400 bg-emerald-50 text-emerald-950 text-xs font-mono">
            {notice}
          </div>
        )}

        {/* Live Sync Actions & Catalog Counters */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="border border-slate-200 rounded p-4 space-y-2.5 bg-white">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-900">
                1. Live US Gov CISA KEV Feed
              </span>
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-900">
                {feedStatus.cisa_kev_catalog_count} KEV CVEs Synced
              </span>
            </div>
            <p className="text-xs text-slate-600">
              Downloads the daily CISA Known Exploited Vulnerabilities JSON, strips all prose inside{' '}
              <code className="font-mono">warrant-extractor</code>, and flags matching Race Pipeline CVEs.
            </p>
            <div className="text-[11px] font-mono text-slate-500">
              Catalog Version: {feedStatus.latest_catalog_version || 'NOT_SYNCED'} · Last Sync:{' '}
              {feedStatus.last_kev_sync_at ? new Date(feedStatus.last_kev_sync_at).toLocaleTimeString() : '—'}
            </div>
            <button
              type="button"
              disabled={!isLive || busyAction !== null}
              onClick={() =>
                runAction('kev', onSyncKEV, 'Pulled & sanitized live CISA KEV catalog via warrant-extractor.')
              }
              className="w-full inline-flex items-center justify-center gap-1.5 py-2 rounded bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-bold disabled:opacity-40"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${busyAction === 'kev' ? 'animate-spin' : ''}`} />
              {busyAction === 'kev'
                ? 'Pulling & Sanitizing cisa.gov KEV Catalog...'
                : isLive
                ? 'Pull Live CISA KEV Catalog Now'
                : 'Enable Live Mode Above to Pull CISA KEV'}
            </button>
          </div>

          <div className="border border-slate-200 rounded p-4 space-y-2.5 bg-white">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-900">
                2. Google OSV.dev Fleet SBOM Lookup
              </span>
              <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-100 border border-slate-300 text-slate-800">
                {feedStatus.osv_advisories.length} Advisories
              </span>
            </div>
            <p className="text-xs text-slate-600">
              Queries <code className="font-mono">api.osv.dev/v1/querybatch</code> against registered estate SBOM PURLs, sanitizes results via <code className="font-mono">warrant-extractor</code>, and cross-checks CISA KEV.
            </p>
            <div className="text-[11px] font-mono text-slate-500">
              KEV-Cross-Matched SBOM Hits: {feedStatus.osv_advisories.filter((a) => a.is_kev).length}
            </div>
            <button
              type="button"
              disabled={!isLive || busyAction !== null}
              onClick={() =>
                runAction('osv', onSyncOSV, 'Queried live Google OSV.dev API & sanitized advisories via warrant-extractor.')
              }
              className="w-full inline-flex items-center justify-center gap-1.5 py-2 rounded bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold disabled:opacity-40"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${busyAction === 'osv' ? 'animate-spin' : ''}`} />
              {busyAction === 'osv'
                ? 'Querying api.osv.dev Against Fleet SBOM...'
                : isLive
                ? 'Query Live Google OSV.dev SBOM Now'
                : 'Enable Live Mode Above to Query OSV.dev'}
            </button>
          </div>
        </div>

        {/* Discovered Live OSV Advisories Table */}
        {feedStatus.osv_advisories.length > 0 && (
          <section className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900">
              Sanitized Live OSV.dev Fleet SBOM Findings ({feedStatus.osv_advisories.length})
            </h3>
            <div className="overflow-x-auto border border-slate-200 rounded max-h-56">
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead>
                  <tr className="bg-slate-100 border-b border-slate-300 text-[11px] uppercase text-slate-700">
                    <th className="p-2">OSV / CVE</th>
                    <th className="p-2">Target Service</th>
                    <th className="p-2">SBOM PURL</th>
                    <th className="p-2">CVSS / KEV</th>
                    <th className="p-2">Fixed Ver</th>
                    <th className="p-2">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {feedStatus.osv_advisories.slice(0, 15).map((adv) => (
                    <tr key={`${adv.osv_id}-${adv.service_id}-${adv.package_purl}`} className="hover:bg-slate-50">
                      <td className="p-2">
                        <div className="font-bold text-slate-900">{adv.cve_id}</div>
                        <div className="text-[10px] text-slate-500">{adv.osv_id}</div>
                      </td>
                      <td className="p-2 font-semibold">{adv.service_id}</td>
                      <td className="p-2 text-[11px] text-slate-600">{adv.package_purl}</td>
                      <td className="p-2">
                        <span className="font-bold">{adv.cvss_score.toFixed(1)}</span>
                        {adv.is_kev && (
                          <span className="ml-1.5 px-1.5 py-0.2 rounded bg-red-600 text-white text-[10px] font-bold">
                            CISA KEV
                          </span>
                        )}
                      </td>
                      <td className="p-2 text-emerald-800 font-semibold">{adv.fixed_version}</td>
                      <td className="p-2">
                        <button
                          type="button"
                          disabled={busyAction !== null}
                          onClick={() =>
                            runAction(
                              `ingest-${adv.osv_id}`,
                              () => onIngestOSV(adv.osv_id, adv.service_id),
                              `Routed ${adv.cve_id} (${adv.service_id}) into the 5-stage Race Pipeline.`
                            )
                          }
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-700 hover:bg-emerald-800 text-white text-[11px] font-bold"
                        >
                          Remediate <ArrowRight className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* Recent Sync Runs (CISA_KEV, GOOGLE_OSV, TRIVY_SARIF) */}
        <section className="space-y-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-1.5">
            <ShieldCheck className="w-4 h-4 text-emerald-700" />
            Sanitized Feed &amp; Trivy Intake Lineage ({feedStatus.recent_sync_runs.length})
          </h3>
          {feedStatus.recent_sync_runs.length === 0 ? (
            <div className="text-xs font-mono text-slate-500 p-3 border border-slate-200 rounded bg-slate-50">
              No external feed runs executed yet (Default mode is offline for air-gapped enclave determinism).
            </div>
          ) : (
            <div className="overflow-x-auto border border-slate-200 rounded max-h-48">
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead>
                  <tr className="bg-slate-100 border-b border-slate-300 text-[11px] uppercase text-slate-700">
                    <th className="p-2">Timestamp</th>
                    <th className="p-2">Source</th>
                    <th className="p-2">Status</th>
                    <th className="p-2">Ingested / KEV Hits</th>
                    <th className="p-2">Raw Input SHA-256 -&gt; Typed Schema SHA-256</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {feedStatus.recent_sync_runs.map((r) => (
                    <tr key={r.sync_id}>
                      <td className="p-2 text-[11px] text-slate-600">{new Date(r.synced_at).toLocaleTimeString()}</td>
                      <td className="p-2 font-bold">{r.feed_source}</td>
                      <td className="p-2">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                            r.status === 'SUCCESS'
                              ? 'bg-emerald-50 border-emerald-300 text-emerald-900'
                              : 'bg-red-50 border-red-300 text-red-900'
                          }`}
                        >
                          {r.status}
                        </span>
                      </td>
                      <td className="p-2">
                        {r.items_ingested} items ({r.kev_matches} KEV)
                      </td>
                      <td className="p-2 text-[11px]">
                        {r.error_message
                          ? r.error_message
                          : `${shortHash(r.raw_input_sha256, 12)} -> ${shortHash(r.typed_output_sha256, 12)}`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
