import React, { useMemo, useState } from 'react';
import {
  Radio,
  X,
  Plus,
  RefreshCw,
  Trash2,
  Edit3,
  Power,
  ShieldCheck,
  AlertTriangle,
  Lock,
} from 'lucide-react';
import type { SIEMConfigAuditRecord, SIEMDestination, SIEMVendorDescriptor } from '../types';
import { shortHash } from '../lib/templates';

interface SIEMDestinationsModalProps {
  vendors: SIEMVendorDescriptor[];
  destinations: SIEMDestination[];
  auditRecords: SIEMConfigAuditRecord[];
  onClose: () => void;
  onRefresh: () => Promise<void>;
}

const ALL_RECORD_TYPES: Array<{ id: string; label: string; detail: string }> = [
  { id: 'SIGNED_CLOSURE', label: 'Signed Closure Records', detail: 'OSCAL POA&M & Ed25519 DSSE closure attestations' },
  { id: 'WORM_LEDGER', label: 'WORM Ledger Entries', detail: 'warrants, remediation_traces, freeze, agent & estate ledgers' },
  { id: 'AUTH_CLASS_SIGNING', label: 'Authorization Class Signings', detail: '2-of-2 dual-key warrants, exceptions, principal enrollments' },
  { id: 'DISPATCH_RESULT', label: 'Dispatch & Deployment Results', detail: 'WN-8 distributor orders & per-asset deployment results' },
  { id: 'SHIELD_EVENT', label: 'Shield Arm / Disarm Events', detail: '6-substrate containment bridges, lockouts & N3 drift' },
  { id: 'TWIN_PROOF_VERDICT', label: 'Twin Proof Verdicts', detail: 'Differential canary / shadow comparison verdicts' },
  { id: 'INGEST_EVENT', label: 'Ingest Events', detail: 'SARIF/Finder typed intakes & CISA KEV / OSV feed syncs' },
  { id: 'SIEM_CONFIG_AUDIT', label: 'SIEM Config Audit', detail: 'WORM hash-chained SIEM destination config mutations' },
];

const ALL_CONSOLE_VIEWS: Array<{ id: string; label: string }> = [
  { id: 'VIEW1_RACE', label: '1. Race Pipeline' },
  { id: 'VIEW2_WARRANTS', label: '2. Warrant Desk & Dual-Key' },
  { id: 'VIEW3_SHADOW', label: '3. Shadow & Estate Readiness' },
  { id: 'VIEW4_CONTAINMENT', label: '4. Bridges & Drift Lockout' },
  { id: 'VIEW5_AUDITOR', label: '5. OSCAL Vault & Agent Ledger' },
];

const ALLOWED_CREDENTIAL_REF_PREFIXES = [
  'env://',
  'file://',
  'k8s-secret://',
  'aws-sm://',
  'azure-kv://',
  'gcp-sm://',
  'none://',
];

function validateCredentialRefClientSide(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) {
    return 'Credential reference URI is required (use none:// only for unauthenticated local/mTLS collectors).';
  }
  const lower = trimmed.toLowerCase();
  if (
    lower.startsWith('bearer ') ||
    lower.startsWith('splunk ') ||
    lower.startsWith('basic ') ||
    trimmed.includes('-----BEGIN') ||
    /\s/.test(trimmed)
  ) {
    return 'RAW SECRET REJECTED: The Warrant UI never accepts, stores, or displays raw tokens, keys, or PEM secrets. Provide a secret reference URI (e.g., env://SPLUNK_HEC_TOKEN or file:///run/secrets/siem_token).';
  }
  const matched = ALLOWED_CREDENTIAL_REF_PREFIXES.find((p) => trimmed.startsWith(p));
  if (!matched) {
    return `Credential reference must start with one of: ${ALLOWED_CREDENTIAL_REF_PREFIXES.join(', ')}`;
  }
  if (matched !== 'none://' && trimmed.slice(matched.length).trim().length === 0) {
    return `Credential reference ${matched} requires a secret identifier after the scheme.`;
  }
  return null;
}

export const SIEMDestinationsModal: React.FC<SIEMDestinationsModalProps> = ({
  vendors,
  destinations,
  auditRecords,
  onClose,
  onRefresh,
}) => {
  const [activeTab, setActiveTab] = useState<'DESTINATIONS' | 'FORM' | 'AUDIT'>(
    destinations.length === 0 ? 'FORM' : 'DESTINATIONS'
  );
  const [editingId, setEditingId] = useState<string | null>(null);

  const defaultVendor = vendors[0]?.vendor_id || 'splunk_es';
  const [siemVendor, setSiemVendor] = useState<string>(defaultVendor);
  const [displayName, setDisplayName] = useState<string>('Splunk Enterprise Security HEC');
  const [endpoint, setEndpoint] = useState<string>(
    vendors[0]?.endpoint_hint || 'https://splunk.corp.example:8088/services/collector/event'
  );
  const [credentialRef, setCredentialRef] = useState<string>('env://SPLUNK_HEC_TOKEN');
  const [format, setFormat] = useState<string>(vendors[0]?.default_format || 'SPLUNK_HEC_JSON');
  const [vendorOptions, setVendorOptions] = useState<Record<string, string>>({});
  const [recordTypes, setRecordTypes] = useState<string[]>(ALL_RECORD_TYPES.map((r) => r.id));
  const [batchSize, setBatchSize] = useState<number>(100);
  const [scheduleSeconds, setScheduleSeconds] = useState<number>(10);
  const [enabled, setEnabled] = useState<boolean>(true);
  const [consoleViews, setConsoleViews] = useState<string[]>(['VIEW1_RACE', 'VIEW4_CONTAINMENT', 'VIEW5_AUDITOR']);

  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [bannerMsg, setBannerMsg] = useState<string | null>(null);
  const [bannerErr, setBannerErr] = useState<string | null>(null);

  const selectedVendorMeta = useMemo(
    () => vendors.find((v) => v.vendor_id === siemVendor) || vendors[0],
    [vendors, siemVendor]
  );

  const resetFormForVendor = (vendorId: string) => {
    const meta = vendors.find((v) => v.vendor_id === vendorId);
    setEditingId(null);
    setSiemVendor(vendorId);
    setDisplayName(meta ? meta.display_name : vendorId);
    setEndpoint(meta?.endpoint_hint || '');
    setFormat(meta?.default_format || '');
    const envName = `${vendorId.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_TOKEN`;
    setCredentialRef(
      vendorId === 'ibm_qradar' ||
        vendorId === 'exabeam' ||
        vendorId === 'logrhythm' ||
        vendorId === 'fortisiem' ||
        vendorId === 'arcsight' ||
        vendorId === 'generic_fallback'
        ? 'none://'
        : `env://${envName}`
    );
    setVendorOptions({});
    setRecordTypes(ALL_RECORD_TYPES.map((r) => r.id));
    setBatchSize(100);
    setScheduleSeconds(10);
    setEnabled(true);
    setConsoleViews(['VIEW1_RACE', 'VIEW4_CONTAINMENT', 'VIEW5_AUDITOR']);
  };

  const startCreateNew = () => {
    resetFormForVendor(vendors[0]?.vendor_id || 'splunk_es');
    setBannerErr(null);
    setBannerMsg(null);
    setActiveTab('FORM');
  };

  const startEdit = (d: SIEMDestination) => {
    setEditingId(d.destination_id);
    setSiemVendor(d.siem_vendor);
    setDisplayName(d.display_name);
    setEndpoint(d.endpoint);
    setCredentialRef(d.credential_ref);
    setFormat(d.format);
    setVendorOptions({ ...(d.vendor_options || {}) });
    setRecordTypes(d.record_types && d.record_types.length > 0 ? [...d.record_types] : ALL_RECORD_TYPES.map((r) => r.id));
    setBatchSize(d.batch_size || 100);
    setScheduleSeconds(d.schedule_seconds || 10);
    setEnabled(d.enabled);
    setConsoleViews(d.console_views && d.console_views.length > 0 ? [...d.console_views] : ['VIEW1_RACE', 'VIEW5_AUDITOR']);
    setBannerErr(null);
    setBannerMsg(null);
    setActiveTab('FORM');
  };

  const toggleArrayItem = (arr: string[], item: string, setter: (next: string[]) => void) => {
    if (arr.includes(item)) {
      setter(arr.filter((x) => x !== item));
    } else {
      setter([...arr, item]);
    }
  };

  const handleSaveForm = async (e: React.FormEvent) => {
    e.preventDefault();
    setBannerErr(null);
    setBannerMsg(null);

    const credErr = validateCredentialRefClientSide(credentialRef);
    if (credErr) {
      setBannerErr(credErr);
      return;
    }
    if (!endpoint.trim()) {
      setBannerErr('Ingestion endpoint URL or host:port is required.');
      return;
    }
    if (recordTypes.length === 0) {
      setBannerErr('Select at least one Warrant record family to ship.');
      return;
    }
    if (consoleViews.length === 0) {
      setBannerErr('Select at least one Warrant Console view where delivery results should appear.');
      return;
    }

    const cleanedOpts: Record<string, string> = {};
    Object.entries(vendorOptions).forEach(([k, v]) => {
      if (v && v.trim() !== '') {
        cleanedOpts[k] = v.trim();
      }
    });

    const payload = {
      destination_id: editingId || undefined,
      display_name: displayName.trim() || selectedVendorMeta?.display_name || siemVendor,
      siem_vendor: siemVendor,
      endpoint: endpoint.trim(),
      credential_ref: credentialRef.trim(),
      format,
      vendor_options: cleanedOpts,
      record_types: recordTypes,
      batch_size: Number(batchSize) || 100,
      schedule_seconds: Number(scheduleSeconds) || 10,
      enabled,
      console_views: consoleViews,
    };

    setBusyKey('save-form');
    try {
      const url = editingId
        ? `/api/v1/siem/destinations/${encodeURIComponent(editingId)}`
        : '/api/v1/siem/destinations';
      const method = editingId ? 'PUT' : 'POST';
      const res = await fetch(url, {
        method,
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body.error || `HTTP ${res.status}`);
      }
      await onRefresh();
      setBannerMsg(
        editingId
          ? `Updated SIEM destination "${payload.display_name}" and recorded WORM audit entry.`
          : `Created SIEM destination "${payload.display_name}" and recorded WORM audit entry.`
      );
      setEditingId(null);
      setActiveTab('DESTINATIONS');
    } catch (err) {
      setBannerErr(err instanceof Error ? err.message : 'Failed to save SIEM destination');
    } finally {
      setBusyKey(null);
    }
  };

  const handleToggleEnabled = async (d: SIEMDestination) => {
    setBusyKey(`toggle:${d.destination_id}`);
    setBannerErr(null);
    setBannerMsg(null);
    try {
      const res = await fetch(`/api/v1/siem/destinations/${encodeURIComponent(d.destination_id)}`, {
        method: 'PUT',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          destination_id: d.destination_id,
          display_name: d.display_name,
          siem_vendor: d.siem_vendor,
          endpoint: d.endpoint,
          credential_ref: d.credential_ref,
          format: d.format,
          vendor_options: d.vendor_options || {},
          record_types: d.record_types,
          batch_size: d.batch_size,
          schedule_seconds: d.schedule_seconds,
          enabled: !d.enabled,
          console_views: d.console_views,
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body.error || `HTTP ${res.status}`);
      }
      await onRefresh();
      setBannerMsg(`Set ${d.display_name} to ${!d.enabled ? 'ENABLED' : 'DISABLED'} (WORM config audit appended).`);
    } catch (err) {
      setBannerErr(err instanceof Error ? err.message : 'Failed to toggle destination');
    } finally {
      setBusyKey(null);
    }
  };

  const handleFlushNow = async (d: SIEMDestination) => {
    setBusyKey(`flush:${d.destination_id}`);
    setBannerErr(null);
    setBannerMsg(null);
    try {
      const res = await fetch(`/api/v1/siem/destinations/${encodeURIComponent(d.destination_id)}/flush`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body.error || `HTTP ${res.status}`);
      }
      await onRefresh();
      const updated = body.destination as SIEMDestination | undefined;
      if (updated?.last_error) {
        setBannerErr(`Flush attempted for ${d.display_name}: ${updated.last_error} (queued=${updated.queued_count})`);
      } else {
        setBannerMsg(
          `Flushed ${d.display_name} in strict ledger order — total sent: ${updated?.sent_count ?? d.sent_count}, queued: ${updated?.queued_count ?? 0}.`
        );
      }
    } catch (err) {
      setBannerErr(err instanceof Error ? err.message : 'Failed to flush destination');
    } finally {
      setBusyKey(null);
    }
  };

  const handleDelete = async (d: SIEMDestination) => {
    setBusyKey(`delete:${d.destination_id}`);
    setBannerErr(null);
    setBannerMsg(null);
    try {
      const res = await fetch(`/api/v1/siem/destinations/${encodeURIComponent(d.destination_id)}`, {
        method: 'DELETE',
        credentials: 'same-origin',
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body.error || `HTTP ${res.status}`);
      }
      await onRefresh();
      setBannerMsg(`Deleted SIEM destination "${d.display_name}" (deletion sealed in WORM siem_config_audit).`);
    } catch (err) {
      setBannerErr(err instanceof Error ? err.message : 'Failed to delete destination');
    } finally {
      setBusyKey(null);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="siem-destinations-modal-title"
      className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4 overflow-y-auto"
    >
      <div className="bg-white border border-slate-300 rounded-md shadow-2xl max-w-6xl w-full max-h-[92vh] flex flex-col overflow-hidden">
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between gap-3 bg-slate-50">
          <div>
            <h2
              id="siem-destinations-modal-title"
              className="text-sm font-bold uppercase tracking-wider text-slate-900 flex items-center gap-2"
            >
              <Radio className="w-4 h-4 text-emerald-700" />
              <span>SIEM Shipping Destinations & Ordered Ledger Egress (13 Native Senders)</span>
            </h2>
            <p className="text-xs text-slate-600 mt-0.5">
              UI-configured per destination · Credential reference URIs only (never raw secrets) · Strict ledger ordering · Zero dual-key or extra device step
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close SIEM destinations modal"
            className="p-1.5 rounded border border-slate-200 bg-white hover:bg-slate-100 text-slate-700"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Sub-Navigation Tabs */}
        <div className="px-5 pt-2.5 border-b border-slate-200 flex flex-wrap items-center justify-between gap-2 bg-white">
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => setActiveTab('DESTINATIONS')}
              className={`px-3 py-2 text-xs font-bold border-b-2 transition ${
                activeTab === 'DESTINATIONS'
                  ? 'border-slate-900 text-slate-900'
                  : 'border-transparent text-slate-600 hover:text-slate-900'
              }`}
            >
              Configured Destinations ({destinations.length})
            </button>
            <button
              type="button"
              onClick={() => {
                if (activeTab !== 'FORM' && !editingId) {
                  resetFormForVendor(siemVendor);
                }
                setActiveTab('FORM');
              }}
              className={`px-3 py-2 text-xs font-bold border-b-2 transition ${
                activeTab === 'FORM'
                  ? 'border-slate-900 text-slate-900'
                  : 'border-transparent text-slate-600 hover:text-slate-900'
              }`}
            >
              {editingId ? `Edit Destination (${editingId})` : '+ Add SIEM Destination'}
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('AUDIT')}
              className={`px-3 py-2 text-xs font-bold border-b-2 transition ${
                activeTab === 'AUDIT'
                  ? 'border-slate-900 text-slate-900'
                  : 'border-transparent text-slate-600 hover:text-slate-900'
              }`}
            >
              WORM Config Audit Trail ({auditRecords.length})
            </button>
          </div>

          <div className="pb-2 flex items-center gap-2 text-[11px] font-mono text-slate-700">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-700" />
            <span>Session-Authorized Operator Config · No Dual-Key Ceremony Required</span>
          </div>
        </div>

        {/* Body */}
        <div className="p-5 overflow-y-auto space-y-4 flex-1">
          {bannerMsg && (
            <div
              role="status"
              className="rounded border border-emerald-300 bg-emerald-50 px-3 py-2 text-xs font-mono text-emerald-900"
            >
              {bannerMsg}
            </div>
          )}
          {bannerErr && (
            <div
              role="alert"
              className="rounded border border-red-300 bg-red-50 px-3 py-2 text-xs font-mono text-red-900 flex items-start gap-2"
            >
              <AlertTriangle className="w-4 h-4 text-red-700 shrink-0 mt-0.5" />
              <span>{bannerErr}</span>
            </div>
          )}

          {activeTab === 'DESTINATIONS' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-xs text-slate-700">
                  Each destination maintains an independent monotonic PostgreSQL stream cursor (`siem_stream_cursors`) so failed deliveries queue and retry in exact ledger sequence without blocking other SIEMs.
                </p>
                <button
                  type="button"
                  onClick={startCreateNew}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold shrink-0"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Add SIEM Destination</span>
                </button>
              </div>

              {destinations.length === 0 ? (
                <div className="rounded border border-slate-200 bg-slate-50 p-6 text-center space-y-2">
                  <div className="text-xs font-bold text-slate-800">No SIEM Destinations Configured Yet</div>
                  <p className="text-xs text-slate-600 max-w-xl mx-auto">
                    Configure Splunk ES, Microsoft Sentinel, IBM QRadar, Google SecOps, CrowdStrike Falcon LogScale, Elastic Security, Palo Alto Cortex XSIAM, Exabeam, LogRhythm, Sumo Logic, FortiSIEM, OpenText ArcSight, or Generic Syslog/CEF/HTTPS directly from this UI.
                  </p>
                  <button
                    type="button"
                    onClick={startCreateNew}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Configure First SIEM Destination</span>
                  </button>
                </div>
              ) : (
                <div className="space-y-2.5">
                  {destinations.map((d) => (
                    <div
                      key={d.destination_id}
                      className="rounded border border-slate-200 bg-white p-3.5 space-y-2 shadow-sm"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-sm font-bold text-slate-900">{d.display_name}</span>
                          <span className="px-2 py-0.5 rounded border border-slate-300 bg-slate-50 font-mono text-[11px] text-slate-800">
                            {d.siem_vendor}
                          </span>
                          <span className="px-2 py-0.5 rounded border border-slate-300 bg-slate-50 font-mono text-[11px] text-slate-800">
                            {d.format}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold ${
                              d.enabled
                                ? 'bg-emerald-100 text-emerald-900 border border-emerald-300'
                                : 'bg-slate-200 text-slate-800 border border-slate-300'
                            }`}
                          >
                            {d.enabled ? 'ENABLED' : 'DISABLED'}
                          </span>
                        </div>

                        <div className="flex flex-wrap items-center gap-1.5">
                          <button
                            type="button"
                            disabled={busyKey !== null}
                            onClick={() => handleFlushNow(d)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-800 text-xs font-mono font-semibold"
                          >
                            <RefreshCw
                              className={`w-3.5 h-3.5 ${busyKey === `flush:${d.destination_id}` ? 'animate-spin' : ''}`}
                            />
                            <span>Flush Now</span>
                          </button>
                          <button
                            type="button"
                            disabled={busyKey !== null}
                            onClick={() => handleToggleEnabled(d)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-800 text-xs font-mono font-semibold"
                          >
                            <Power className="w-3.5 h-3.5" />
                            <span>{d.enabled ? 'Turn Off' : 'Turn On'}</span>
                          </button>
                          <button
                            type="button"
                            disabled={busyKey !== null}
                            onClick={() => startEdit(d)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-800 text-xs font-mono font-semibold"
                          >
                            <Edit3 className="w-3.5 h-3.5" />
                            <span>Edit</span>
                          </button>
                          <button
                            type="button"
                            disabled={busyKey !== null}
                            onClick={() => handleDelete(d)}
                            aria-label={`Delete SIEM destination ${d.display_name}`}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-red-300 bg-white hover:bg-red-50 text-red-800 text-xs font-mono font-semibold"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                            <span>Delete</span>
                          </button>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs font-mono text-slate-700 bg-slate-50 p-2.5 rounded border border-slate-200">
                        <div className="truncate" title={d.endpoint}>
                          <span className="font-semibold text-slate-900">Endpoint:</span> {d.endpoint}
                        </div>
                        <div className="truncate" title={d.credential_ref}>
                          <span className="font-semibold text-slate-900">Credential Ref:</span> {d.credential_ref}
                        </div>
                        <div>
                          <span className="font-semibold text-slate-900">Schedule:</span> batch={d.batch_size} every{' '}
                          {d.schedule_seconds}s
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
                        <div className="flex flex-wrap items-center gap-3">
                          <span className="text-emerald-800 font-bold">Sent: {d.sent_count}</span>
                          <span className="text-slate-800">Queued: {d.queued_count}</span>
                          <span className={d.failed_count > 0 ? 'text-red-800 font-bold' : 'text-slate-800'}>
                            Failures: {d.failed_count}
                          </span>
                          <span className="text-slate-700">Retries: {d.retry_count}</span>
                          {d.last_transport_status && (
                            <span className="text-slate-600">Last Status: {d.last_transport_status}</span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-600">
                          Views: {(d.console_views || []).join(', ')}
                        </div>
                      </div>

                      {d.last_error && (
                        <div className="rounded border border-red-300 bg-red-50 px-2.5 py-1.5 text-xs font-mono text-red-900">
                          LAST ERROR: {d.last_error}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'FORM' && (
            <form onSubmit={handleSaveForm} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="siem-vendor-select" className="block text-xs font-bold text-slate-800 mb-1">
                    1. Named SIEM Target (13 Supported Senders)
                  </label>
                  <select
                    id="siem-vendor-select"
                    value={siemVendor}
                    onChange={(e) => {
                      const nextVendor = e.target.value;
                      if (!editingId) {
                        resetFormForVendor(nextVendor);
                      } else {
                        const meta = vendors.find((v) => v.vendor_id === nextVendor);
                        setSiemVendor(nextVendor);
                        if (meta) {
                          setFormat(meta.default_format);
                        }
                      }
                    }}
                    className="w-full rounded border border-slate-300 bg-white px-3 py-2 text-xs font-mono text-slate-900"
                  >
                    {vendors.map((v) => (
                      <option key={v.vendor_id} value={v.vendor_id}>
                        {v.display_name} ({v.vendor_id}) — [{v.proof_status}]
                      </option>
                    ))}
                  </select>
                  {selectedVendorMeta && (
                    <p className="text-[11px] text-slate-600 mt-1">{selectedVendorMeta.auth_description}</p>
                  )}
                </div>

                <div>
                  <label htmlFor="siem-display-name" className="block text-xs font-bold text-slate-800 mb-1">
                    Destination Label
                  </label>
                  <input
                    id="siem-display-name"
                    type="text"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    placeholder="Production SOC Splunk ES"
                    className="w-full rounded border border-slate-300 bg-white px-3 py-2 text-xs font-mono text-slate-900"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="siem-endpoint-input" className="block text-xs font-bold text-slate-800 mb-1">
                    2. Ingestion Endpoint (URL or Syslog tcp:// / tls:// / udp:// host:port)
                  </label>
                  <input
                    id="siem-endpoint-input"
                    type="text"
                    value={endpoint}
                    onChange={(e) => setEndpoint(e.target.value)}
                    placeholder={selectedVendorMeta?.endpoint_hint || 'https://siem.example.com/ingest'}
                    className="w-full rounded border border-slate-300 bg-white px-3 py-2 text-xs font-mono text-slate-900"
                  />
                  {selectedVendorMeta?.endpoint_hint && (
                    <p className="text-[11px] font-mono text-slate-600 mt-1">
                      Vendor pattern: {selectedVendorMeta.endpoint_hint}
                    </p>
                  )}
                </div>

                <div>
                  <label htmlFor="siem-credref-input" className="block text-xs font-bold text-slate-800 mb-1">
                    3. Credential Reference URI ONLY (Raw Secrets Rejected)
                  </label>
                  <div className="relative">
                    <input
                      id="siem-credref-input"
                      type="text"
                      autoComplete="off"
                      spellCheck={false}
                      value={credentialRef}
                      onChange={(e) => setCredentialRef(e.target.value)}
                      placeholder="env://SPLUNK_HEC_TOKEN or file:///run/secrets/siem_token"
                      className="w-full rounded border border-slate-300 bg-white px-3 py-2 text-xs font-mono text-slate-900"
                    />
                  </div>
                  <p className="text-[11px] text-slate-600 mt-1 flex items-center gap-1">
                    <Lock className="w-3 h-3 text-slate-600 shrink-0" />
                    <span>
                      Allowed schemes: <code>env://</code>, <code>file://</code>, <code>k8s-secret://</code>,{' '}
                      <code>aws-sm://</code>, <code>azure-kv://</code>, <code>gcp-sm://</code>, <code>none://</code>. Raw tokens are never stored or echoed.
                    </span>
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label htmlFor="siem-format-select" className="block text-xs font-bold text-slate-800 mb-1">
                    4. Wire Format
                  </label>
                  <select
                    id="siem-format-select"
                    value={format}
                    onChange={(e) => setFormat(e.target.value)}
                    className="w-full rounded border border-slate-300 bg-white px-3 py-2 text-xs font-mono text-slate-900"
                  >
                    {(selectedVendorMeta?.supported_formats || [format]).map((fmt) => (
                      <option key={fmt} value={fmt}>
                        {fmt}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="siem-batch-size" className="block text-xs font-bold text-slate-800 mb-1">
                    5a. Max Batch Size (1–500, strict seq order)
                  </label>
                  <input
                    id="siem-batch-size"
                    type="number"
                    min={1}
                    max={500}
                    value={batchSize}
                    onChange={(e) => setBatchSize(Number(e.target.value))}
                    className="w-full rounded border border-slate-300 bg-white px-3 py-2 text-xs font-mono text-slate-900"
                  />
                </div>

                <div>
                  <label htmlFor="siem-schedule-seconds" className="block text-xs font-bold text-slate-800 mb-1">
                    5b. Flush Schedule Interval (seconds)
                  </label>
                  <input
                    id="siem-schedule-seconds"
                    type="number"
                    min={1}
                    max={3600}
                    value={scheduleSeconds}
                    onChange={(e) => setScheduleSeconds(Number(e.target.value))}
                    className="w-full rounded border border-slate-300 bg-white px-3 py-2 text-xs font-mono text-slate-900"
                  />
                </div>
              </div>

              {/* Optional Non-Secret Vendor Parameters */}
              {selectedVendorMeta?.option_keys && selectedVendorMeta.option_keys.length > 0 && (
                <div className="rounded border border-slate-200 bg-slate-50 p-3 space-y-2">
                  <div className="text-xs font-bold text-slate-800">
                    Vendor Routing Metadata (Non-Secret Transport Parameters)
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    {selectedVendorMeta.option_keys.map((optKey) => {
                      const inputId = `siem-opt-${optKey}`;
                      return (
                        <div key={optKey}>
                          <label htmlFor={inputId} className="block text-[11px] font-mono font-semibold text-slate-700 mb-1">
                            {optKey}
                          </label>
                          <input
                            id={inputId}
                            type="text"
                            value={vendorOptions[optKey] || ''}
                            onChange={(e) =>
                              setVendorOptions((prev) => ({
                                ...prev,
                                [optKey]: e.target.value,
                              }))
                            }
                            placeholder={`Optional ${optKey}`}
                            className="w-full rounded border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-mono text-slate-900"
                          />
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Record Types Filter */}
              <fieldset className="rounded border border-slate-200 p-3 space-y-2">
                <legend className="px-1 text-xs font-bold text-slate-800">
                  6. Warrant Record Types Shipped to This SIEM
                </legend>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {ALL_RECORD_TYPES.map((rt) => {
                    const checked = recordTypes.includes(rt.id);
                    return (
                      <label
                        key={rt.id}
                        className="flex items-start gap-2 rounded border border-slate-200 bg-slate-50/70 px-2.5 py-2 text-xs cursor-pointer hover:bg-slate-100"
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleArrayItem(recordTypes, rt.id, setRecordTypes)}
                          className="mt-0.5"
                        />
                        <div>
                          <div className="font-semibold text-slate-900">
                            {rt.label} <span className="font-mono text-[10px] text-slate-600">({rt.id})</span>
                          </div>
                          <div className="text-[11px] text-slate-600">{rt.detail}</div>
                        </div>
                      </label>
                    );
                  })}
                </div>
              </fieldset>

              {/* Console Views Placement + On/Off */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <fieldset className="md:col-span-2 rounded border border-slate-200 p-3 space-y-2">
                  <legend className="px-1 text-xs font-bold text-slate-800">
                    7. Where Delivery Results, Failures & Counts Show Up in Warrant Console
                  </legend>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {ALL_CONSOLE_VIEWS.map((vw) => {
                      const checked = consoleViews.includes(vw.id);
                      return (
                        <label
                          key={vw.id}
                          className="flex items-center gap-2 rounded border border-slate-200 bg-slate-50/70 px-2.5 py-1.5 text-xs font-medium text-slate-900 cursor-pointer hover:bg-slate-100"
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => toggleArrayItem(consoleViews, vw.id, setConsoleViews)}
                          />
                          <span>{vw.label}</span>
                        </label>
                      );
                    })}
                  </div>
                </fieldset>

                <div className="rounded border border-slate-200 p-3 flex flex-col justify-between bg-slate-50">
                  <div>
                    <div className="text-xs font-bold text-slate-800 mb-1">8. Destination On / Off</div>
                    <p className="text-[11px] text-slate-600">
                      When OFF, background schedule pauses while preserving the destination’s acknowledged cursor position.
                    </p>
                  </div>
                  <label className="mt-3 inline-flex items-center gap-2 text-xs font-bold text-slate-900 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={enabled}
                      onChange={(e) => setEnabled(e.target.checked)}
                    />
                    <span>{enabled ? 'Destination ENABLED (Shipping Active)' : 'Destination DISABLED (Paused)'}</span>
                  </label>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-200">
                <button
                  type="button"
                  onClick={() => {
                    setEditingId(null);
                    setActiveTab('DESTINATIONS');
                  }}
                  className="px-3 py-1.5 rounded border border-slate-300 bg-white hover:bg-slate-50 text-slate-800 text-xs font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={busyKey === 'save-form'}
                  className="px-4 py-1.5 rounded bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold disabled:opacity-60"
                >
                  {busyKey === 'save-form'
                    ? 'Saving & Sealing WORM Audit...'
                    : editingId
                    ? 'Save Destination Changes'
                    : 'Create SIEM Destination'}
                </button>
              </div>
            </form>
          )}

          {activeTab === 'AUDIT' && (
            <div className="space-y-2.5">
              <p className="text-xs text-slate-700">
                Every SIEM destination creation, edit, toggle, or deletion is recorded in PostgreSQL WORM table{' '}
                <code className="font-mono">siem_config_audit</code> (`trg_worm_siem_config_audit`) and verified by{' '}
                <code className="font-mono">VerifyAllLedgerChains</code>.
              </p>
              {auditRecords.length === 0 ? (
                <div className="rounded border border-slate-200 bg-slate-50 p-4 text-xs font-mono text-slate-600">
                  No SIEM configuration mutations recorded yet.
                </div>
              ) : (
                <div className="overflow-x-auto rounded border border-slate-200">
                  <table className="w-full text-left border-collapse text-xs font-mono">
                    <thead className="bg-slate-100 text-slate-800 border-b border-slate-200">
                      <tr>
                        <th className="px-3 py-2">Seq</th>
                        <th className="px-3 py-2">Action</th>
                        <th className="px-3 py-2">Vendor / Dest</th>
                        <th className="px-3 py-2">Actor</th>
                        <th className="px-3 py-2">Cred Ref</th>
                        <th className="px-3 py-2">Prev → Entry Hash</th>
                        <th className="px-3 py-2">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 bg-white text-slate-800">
                      {auditRecords.map((rec) => (
                        <tr key={rec.audit_id}>
                          <td className="px-3 py-2 font-bold">#{rec.seq_no}</td>
                          <td className="px-3 py-2">{rec.action}</td>
                          <td className="px-3 py-2">
                            {rec.siem_vendor} ({rec.destination_id})
                          </td>
                          <td className="px-3 py-2">{rec.actor}</td>
                          <td className="px-3 py-2">{rec.config_snapshot?.credential_ref || '—'}</td>
                          <td className="px-3 py-2">
                            {shortHash(rec.prev_hash)} → {shortHash(rec.entry_hash)}
                          </td>
                          <td className="px-3 py-2">{new Date(rec.occurred_at).toISOString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
