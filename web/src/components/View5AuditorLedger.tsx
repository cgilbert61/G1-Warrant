import React, { useState } from 'react';
import {
  FileKey2,
  ListChecks,
  Download,
  CheckCircle2,
  Link2,
  ShieldCheck,
  Search,
  ExternalLink,
} from 'lucide-react';
import type { AgentLedgerEntry, AttestationRecord, LedgerVerificationReport } from '../types';
import { verifyDSSEEnvelopeInBrowser, type BrowserDSSEVerificationResult } from '../lib/crypto';
import { shortHash } from '../lib/templates';

interface View5AuditorLedgerProps {
  attestations: AttestationRecord[];
  agentActions: AgentLedgerEntry[];
  witnessMode?: 'EXTERNAL_NOTARY' | 'IN_PROCESS_LOCAL';
  kernelPublicKey: {
    key_id: string;
    alg: string;
    public_key_b64: string;
    key_fingerprint: string;
  };
  onMintAuditorLink: (
    label: string,
    scopedIds: string[],
    ttlHours: number
  ) => Promise<{ auditor_url?: string }>;
}

export const View5AuditorLedger: React.FC<View5AuditorLedgerProps> = ({
  attestations,
  agentActions,
  witnessMode,
  kernelPublicKey,
  onMintAuditorLink,
}) => {
  const [activeTab, setActiveTab] = useState<'VAULT' | 'LEDGER'>('VAULT');
  const [filterText, setFilterText] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  const [verifyResults, setVerifyResults] = useState<Record<string, BrowserDSSEVerificationResult>>({});
  const [shareLabel, setShareLabel] = useState('FedRAMP 3PAO Quarterly Evidence Review');
  const [shareTTLHours, setShareTTLHours] = useState(24);
  const [generatedLink, setGeneratedLink] = useState<string | null>(null);
  const [mintError, setMintError] = useState<string | null>(null);
  const [chainReport, setChainReport] = useState<LedgerVerificationReport | null>(null);
  const [chainError, setChainError] = useState<string | null>(null);
  const [verifyingChain, setVerifyingChain] = useState(false);

  const filteredAttestations = attestations.filter((a) => {
    if (kevOnly && !a.is_kev) return false;
    if (!filterText) return true;
    const q = filterText.toLowerCase();
    return (
      a.cve_id.toLowerCase().includes(q) ||
      a.service_id.toLowerCase().includes(q) ||
      a.attestation_id.toLowerCase().includes(q) ||
      a.warrant_id.toLowerCase().includes(q)
    );
  });

  const handleBrowserVerify = (att: AttestationRecord) => {
    const res = verifyDSSEEnvelopeInBrowser(att.dsse_envelope, {
      [kernelPublicKey.key_id]: kernelPublicKey.public_key_b64,
    });
    setVerifyResults((prev) => ({ ...prev, [att.attestation_id]: res }));
  };

  const handleMintAuditorLink = async (e: React.FormEvent) => {
    e.preventDefault();
    setMintError(null);
    try {
      const data = await onMintAuditorLink(
        shareLabel,
        filteredAttestations.map((a) => a.attestation_id),
        shareTTLHours
      );
      if (data.auditor_url) {
        setGeneratedLink(`${window.location.origin}${data.auditor_url}`);
      }
    } catch (err) {
      setMintError(err instanceof Error ? err.message : 'Failed to mint auditor token');
    }
  };

  const handleVerifyHashChains = async () => {
    setVerifyingChain(true);
    setChainError(null);
    try {
      const res = await fetch('/api/v1/ledger/verify', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      setChainReport(data);
    } catch (err) {
      setChainError(err instanceof Error ? err.message : 'Ledger chain verification failed');
    } finally {
      setVerifyingChain(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-300 pb-2">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setActiveTab('VAULT')}
            className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-t text-xs font-bold uppercase tracking-wider border-b-2 ${
              activeTab === 'VAULT'
                ? 'border-slate-900 text-slate-900 bg-white'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            <FileKey2 className="w-4 h-4" /> Tab A — NIST OSCAL 1.1.2 POA&amp;M Vault ({attestations.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('LEDGER')}
            className={`inline-flex items-center gap-1.5 px-3.5 py-2 rounded-t text-xs font-bold uppercase tracking-wider border-b-2 ${
              activeTab === 'LEDGER'
                ? 'border-slate-900 text-slate-900 bg-white'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            <ListChecks className="w-4 h-4" /> Tab B — Governed Agent Ledger ({agentActions.length})
          </button>
        </div>

        <span
          role="status"
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-[11px] font-mono font-semibold ${
            (chainReport?.witness_mode || witnessMode) === 'EXTERNAL_NOTARY'
              ? 'bg-emerald-50 border-emerald-400 text-emerald-950'
              : 'bg-amber-50 border-amber-400 text-amber-950'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Ledger Witness: {chainReport?.witness_mode || witnessMode || 'IN_PROCESS_LOCAL'}</span>
        </span>
      </div>

      {activeTab === 'VAULT' ? (
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="xl:col-span-2 space-y-3">
            {/* Filters */}
            <div className="bg-white border border-slate-200 rounded p-3 flex flex-wrap items-center justify-between gap-2">
              <div className="relative flex-1 min-w-[220px]">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
                <input
                  id="oscal-vault-filter"
                  aria-label="Filter OSCAL attestations by CVE, Service ID, Warrant ID, or Attestation ID"
                  type="search"
                  placeholder="Filter by CVE, Service ID, Warrant ID, or Attestation ID..."
                  value={filterText}
                  onChange={(e) => setFilterText(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 border border-slate-300 rounded text-xs font-mono"
                />
              </div>
              <label htmlFor="kev-closures-only" className="inline-flex items-center gap-2 text-xs font-semibold text-slate-700 cursor-pointer">
                <input
                  id="kev-closures-only"
                  type="checkbox"
                  checked={kevOnly}
                  onChange={(e) => setKevOnly(e.target.checked)}
                  className="rounded border-slate-300"
                />
                CISA KEV Closures Only
              </label>
            </div>

            {/* Attestation Cards */}
            {filteredAttestations.map((att) => {
              const vr = verifyResults[att.attestation_id];
              return (
                <div key={att.attestation_id} className="bg-white border border-emerald-300 rounded p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-slate-900">{att.attestation_id}</span>
                      <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-emerald-50 border border-emerald-300 text-emerald-900">
                        {att.cve_id} · {att.service_id}
                      </span>
                      {att.is_kev && (
                        <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-red-600 text-white">
                          KEV CLOSED
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => handleBrowserVerify(att)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-800 bg-slate-900 hover:bg-slate-800 text-white text-xs font-mono font-semibold"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" /> Verify DSSE + JCS In-Browser
                      </button>
                      <a
                        href={`/api/v1/attestations/${att.attestation_id}/oscal`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-mono font-bold"
                      >
                        <Download className="w-3.5 h-3.5" /> OSCAL 1.1.2 JSON
                      </a>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] font-mono text-slate-700">
                    <div>
                      <span className="text-slate-500">Warrant:</span> {att.warrant_id} ({att.slot1_principal_id} +{' '}
                      {att.slot2_principal_id})
                    </div>
                    <div>
                      <span className="text-slate-500">Lockout Policy:</span> {att.lockout_policy_id}
                    </div>
                    <div>
                      <span className="text-slate-500">Twin Transcript:</span> {shortHash(att.twin_transcript_sha256, 16)}
                    </div>
                    <div>
                      <span className="text-slate-500">Pods Attested:</span> {att.fleet_digest_manifest.length}/
                      {att.fleet_digest_manifest.length} Running Patched Digest
                    </div>
                    <div>
                      <span className="text-slate-500">TTVR:</span> {att.ttvr_seconds}s
                    </div>
                    <div>
                      <span className="text-slate-500">Re-Verify By:</span>{' '}
                      {new Date(att.reverify_expires_at).toLocaleDateString()}
                    </div>
                  </div>

                  {vr && (
                    <div
                      className={`p-3 rounded border text-xs font-mono space-y-1 ${
                        vr.valid
                          ? 'bg-emerald-50 border-emerald-400 text-emerald-950'
                          : 'bg-red-50 border-red-400 text-red-950'
                      }`}
                    >
                      <div className="font-bold flex items-center gap-1.5">
                        <CheckCircle2 className="w-4 h-4" />
                        CLIENT-SIDE CRYPTOGRAPHIC VERIFICATION: {vr.valid ? 'AUTHENTIC & CANONICAL' : 'FAILED'}
                      </div>
                      <div>RFC 8785 JCS Byte-Exact Match: {String(vr.jcsCanonicalMatch)}</div>
                      <div>Payload SHA-256: {vr.payloadSHA256}</div>
                      <div>
                        DSSEv1 PAE ({vr.paeByteLength} bytes) SHA-256: {vr.paeSHA256}
                      </div>
                      {vr.signatureChecks.map((sc) => (
                        <div key={sc.keyid}>
                          [{sc.alg}] key={sc.keyid}: {sc.detail}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Right Column: Scoped External Auditor Share Link Generator */}
          <div className="space-y-4">
            <section className="bg-white border border-slate-200 rounded p-4 space-y-3">
              <div className="flex items-center gap-2 border-b border-slate-200 pb-2">
                <Link2 className="w-4 h-4 text-slate-800" />
                <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900">
                  Scoped External Auditor Share Link (N5)
                </h2>
              </div>
              <p className="text-xs text-slate-600">
                Mints a time-bounded, read-only cryptographic bearer token serving exclusively the{' '}
                <code className="font-mono">/auditor</code> Vault surface. Any attempt to call operational endpoints returns HTTP 403.
              </p>

              <form onSubmit={handleMintAuditorLink} className="space-y-2.5 text-xs">
                <div>
                  <label htmlFor="auditor-share-label" className="block font-semibold text-slate-700 mb-1">Assessment Engagement Label</label>
                  <input
                    id="auditor-share-label"
                    type="text"
                    value={shareLabel}
                    onChange={(e) => setShareLabel(e.target.value)}
                    required
                    className="w-full border border-slate-300 rounded px-2.5 py-1.5"
                  />
                </div>
                <div>
                  <label htmlFor="auditor-share-ttl" className="block font-semibold text-slate-700 mb-1">Token TTL (Hours)</label>
                  <input
                    id="auditor-share-ttl"
                    type="number"
                    min="1"
                    max="720"
                    value={shareTTLHours}
                    onChange={(e) => setShareTTLHours(Number(e.target.value))}
                    className="w-full border border-slate-300 rounded px-2.5 py-1.5 font-mono"
                  />
                </div>
                <button
                  type="submit"
                  className="w-full py-2 rounded bg-slate-900 hover:bg-slate-800 text-white font-bold"
                >
                  Mint Scoped Read-Only Auditor Link ({filteredAttestations.length} POA&amp;Ms)
                </button>
              </form>

              {mintError && (
                <div role="alert" className="p-2.5 rounded border border-red-400 bg-red-50 text-red-950 text-xs font-mono">
                  {mintError}
                </div>
              )}

              {generatedLink && (
                <div className="p-3 rounded border border-emerald-300 bg-emerald-50 space-y-2 text-xs font-mono">
                  <div className="font-bold text-emerald-950">SCOPED BEARER URL READY:</div>
                  <div className="p-2 bg-white border border-emerald-200 rounded break-all text-[11px]">
                    {generatedLink}
                  </div>
                  <a
                    href={generatedLink}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-emerald-900 font-bold underline"
                  >
                    Open Dedicated /auditor Verification Portal <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>
              )}
            </section>

            <section className="bg-white border border-slate-200 rounded p-4 space-y-2 text-xs font-mono">
              <div className="font-sans font-bold uppercase tracking-wider text-slate-900 border-b border-slate-200 pb-1.5">
                Kernel Attestation Seal Trust Root
              </div>
              <div>Key ID: {kernelPublicKey.key_id}</div>
              <div>Algorithm: {kernelPublicKey.alg}</div>
              <div className="break-all text-[11px] text-slate-600">
                SHA-256 FP: {kernelPublicKey.key_fingerprint}
              </div>
            </section>
          </div>
        </div>
      ) : (
        /* TAB B: Governed Agent Ledger */
        <section className="bg-white border border-slate-200 rounded p-4 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-3">
            <div>
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900">
                N4 Hash-Chained Governed Agent &amp; Extractor Action Ledger
              </h2>
              <p className="text-xs text-slate-600">
                Append-only PostgreSQL trigger-protected ledger proving minute-scoped Task Warrants (TTL &lt;= 300s), zero-egress isolation, and raw-input -&gt; typed-schema SHA-256 lineage.
              </p>
            </div>
            <button
              type="button"
              disabled={verifyingChain}
              onClick={handleVerifyHashChains}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded bg-slate-900 hover:bg-slate-800 text-white text-xs font-mono font-bold"
            >
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              {verifyingChain ? 'Verifying 6 Ledger & Authority Chains...' : 'Verify Cryptographic Hash Chains'}
            </button>
          </div>

          {chainError && (
            <div role="alert" className="p-2.5 rounded border border-red-400 bg-red-50 text-red-950 text-xs font-mono">
              {chainError}
            </div>
          )}

          {chainReport && (
            <div
              className={`p-3 rounded border text-xs font-mono space-y-1.5 ${
                chainReport.all_valid
                  ? 'bg-emerald-50 border-emerald-400 text-emerald-950'
                  : 'bg-red-50 border-red-400 text-red-950'
              }`}
            >
              <div className="font-bold">
                IMMUTABLE LEDGER HASH-CHAIN AUDIT: {chainReport.all_valid ? 'ALL 6 CHAINS & LINEAGE INTACT' : 'TAMPER / UNATTESTED INSERT DETECTED'} (Verified{' '}
                {new Date(chainReport.verified_at).toISOString()})
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                {chainReport.tables.map((t) => (
                  <div key={t.table_name} className="bg-white border border-emerald-200 rounded p-2">
                    <div className="font-bold">{t.table_name}</div>
                    <div>
                      Rows: {t.row_count} · Valid: {String(t.valid)}
                    </div>
                    <div className="text-[10px] text-slate-500 truncate">head: {t.terminal_hash}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs font-mono">
              <thead>
                <tr className="bg-slate-100 border-y border-slate-300 text-[11px] uppercase text-slate-700">
                  <th className="p-2">Action / Token (TTL)</th>
                  <th className="p-2">Worker &amp; Egress Profile</th>
                  <th className="p-2">Asset &amp; Action Type</th>
                  <th className="p-2">Warrant &amp; Principals</th>
                  <th className="p-2">Raw Input SHA-256 -&gt; Typed Output SHA-256</th>
                  <th className="p-2">Chain Link (prev -&gt; entry)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {agentActions.map((act) => (
                  <tr
                    key={act.action_id}
                    className={act.status === 'SECURITY_VIOLATION' ? 'bg-red-50' : 'hover:bg-slate-50'}
                  >
                    <td className="p-2">
                      <div className="font-bold text-slate-900">{act.action_id}</div>
                      <div className="text-[11px] text-slate-600">
                        {act.task_token_id} ({act.token_ttl_sec}s)
                      </div>
                    </td>
                    <td className="p-2">
                      <div className="font-semibold text-slate-900">{act.worker_name}</div>
                      <span
                        className={`inline-block text-[10px] px-1.5 py-0.5 rounded border ${
                          act.egress_profile === 'ZERO_EGRESS_ISOLATED'
                            ? 'bg-emerald-50 border-emerald-300 text-emerald-900'
                            : 'bg-slate-100 border-slate-300 text-slate-700'
                        }`}
                      >
                        {act.egress_profile}
                      </span>
                    </td>
                    <td className="p-2">
                      <div className="font-bold text-slate-900">{act.action_type}</div>
                      <div className="text-[11px] text-slate-600">{act.target_asset}</div>
                    </td>
                    <td className="p-2 text-[11px]">
                      <div className="font-semibold">{act.warrant_id}</div>
                      <div className="text-slate-500">
                        {act.slot1_principal_id} + {act.slot2_principal_id}
                      </div>
                    </td>
                    <td className="p-2 text-[11px]">
                      <div>in: {shortHash(act.raw_input_sha256, 14)}</div>
                      <div className="text-emerald-800 font-semibold">out: {shortHash(act.typed_output_sha256, 14)}</div>
                    </td>
                    <td className="p-2 text-[11px]">
                      <div className="text-slate-500">prev: {shortHash(act.prev_hash, 12)}</div>
                      <div className="font-bold text-slate-900">curr: {shortHash(act.entry_hash, 12)}</div>
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
