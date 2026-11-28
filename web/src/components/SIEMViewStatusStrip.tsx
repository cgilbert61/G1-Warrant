import React from 'react';
import { Radio, AlertTriangle, CheckCircle2, RefreshCw, Settings } from 'lucide-react';
import type { SIEMDestination } from '../types';

interface SIEMViewStatusStripProps {
  activeView: string;
  destinations: SIEMDestination[];
  flushingId: string | null;
  onFlushDestination: (destinationId: string) => Promise<void>;
  onOpenConfigureModal: () => void;
}

const VIEW_LABELS: Record<string, string> = {
  VIEW1_RACE: 'View 1 · Race Pipeline',
  VIEW2_WARRANTS: 'View 2 · Warrant Desk',
  VIEW3_SHADOW: 'View 3 · Shadow & Estate',
  VIEW4_CONTAINMENT: 'View 4 · Containment & Drift',
  VIEW5_AUDITOR: 'View 5 · OSCAL Vault & Ledger',
};

export const SIEMViewStatusStrip: React.FC<SIEMViewStatusStripProps> = ({
  activeView,
  destinations,
  flushingId,
  onFlushDestination,
  onOpenConfigureModal,
}) => {
  const visible = destinations.filter((d) => (d.console_views || []).includes(activeView));
  if (visible.length === 0) {
    return null;
  }

  const anyFailed = visible.some((d) => Boolean(d.last_error) || d.failed_count > 0);

  return (
    <section
      aria-label={`SIEM Shipping Telemetry for ${VIEW_LABELS[activeView] || activeView}`}
      className={`mb-4 rounded-md border p-3 ${
        anyFailed
          ? 'bg-red-50/70 border-red-300 text-slate-900'
          : 'bg-white border-slate-200 text-slate-900'
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 mb-2 border-b border-slate-200/80">
        <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-800">
          <Radio className={`w-4 h-4 ${anyFailed ? 'text-red-700' : 'text-emerald-700'}`} />
          <span>SIEM Ordered Shipping Status — {VIEW_LABELS[activeView] || activeView}</span>
          <span className="font-mono text-[11px] font-normal text-slate-600">
            ({visible.length} destination{visible.length === 1 ? '' : 's'} routed to this view)
          </span>
        </div>
        <button
          type="button"
          onClick={onOpenConfigureModal}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-800 text-xs font-mono font-semibold transition"
        >
          <Settings className="w-3.5 h-3.5 text-slate-600" />
          <span>Configure SIEMs</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
        {visible.map((dest) => {
          const hasErr = Boolean(dest.last_error);
          const isFlushing = flushingId === dest.destination_id;
          return (
            <div
              key={dest.destination_id}
              className={`rounded border px-3 py-2 flex flex-col gap-1.5 text-xs ${
                !dest.enabled
                  ? 'border-slate-200 bg-slate-50 text-slate-700'
                  : hasErr
                  ? 'border-red-300 bg-white text-slate-900'
                  : 'border-slate-200 bg-slate-50/60 text-slate-900'
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  {hasErr ? (
                    <AlertTriangle className="w-3.5 h-3.5 text-red-700 shrink-0" />
                  ) : (
                    <CheckCircle2
                      className={`w-3.5 h-3.5 shrink-0 ${dest.enabled ? 'text-emerald-700' : 'text-slate-500'}`}
                    />
                  )}
                  <span className="font-bold text-slate-900 truncate">{dest.display_name}</span>
                  <span className="px-1.5 py-0.5 rounded border border-slate-300 bg-white font-mono text-[10px] text-slate-700">
                    {dest.siem_vendor} · {dest.format}
                  </span>
                  <span
                    className={`px-1.5 py-0.5 rounded font-mono text-[10px] font-bold ${
                      dest.enabled
                        ? 'bg-emerald-100 text-emerald-900 border border-emerald-300'
                        : 'bg-slate-200 text-slate-800 border border-slate-300'
                    }`}
                  >
                    {dest.enabled ? 'ON' : 'OFF'}
                  </span>
                </div>

                <div className="flex items-center gap-2 font-mono text-[11px]">
                  <span className="text-emerald-800 font-semibold">Sent: {dest.sent_count}</span>
                  <span className="text-slate-700">Queued: {dest.queued_count}</span>
                  <span className={dest.failed_count > 0 ? 'text-red-800 font-bold' : 'text-slate-700'}>
                    Failed: {dest.failed_count}
                  </span>
                  <button
                    type="button"
                    disabled={isFlushing}
                    onClick={() => onFlushDestination(dest.destination_id)}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-slate-300 bg-white hover:bg-slate-100 text-slate-800 text-[11px] font-mono font-semibold disabled:opacity-60"
                    title="Flush ordered SIEM cursor batch immediately (no dual-key required)"
                  >
                    <RefreshCw className={`w-3 h-3 ${isFlushing ? 'animate-spin' : ''}`} />
                    <span>{isFlushing ? 'Flushing...' : 'Flush Now'}</span>
                  </button>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-600">
                <span className="truncate" title={dest.endpoint}>
                  Endpoint: {dest.endpoint} · CredRef: {dest.credential_ref}
                </span>
                <span>
                  Batch {dest.batch_size} / {dest.schedule_seconds}s
                  {dest.last_transport_status ? ` · ${dest.last_transport_status}` : ''}
                </span>
              </div>

              {dest.last_error && (
                <div
                  role="alert"
                  className="rounded border border-red-200 bg-red-50 px-2 py-1 text-[11px] font-mono text-red-900 break-words"
                >
                  DELIVERY FAILURE (queued without record loss; retry #{dest.retry_count}): {dest.last_error}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
};
