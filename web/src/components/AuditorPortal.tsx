import React, { useEffect, useState } from 'react';
import { ShieldCheck, Lock, CheckCircle2, AlertOctagon, Sun, Moon } from 'lucide-react';
import type { AttestationRecord, LedgerVerificationReport } from '../types';
import { verifyDSSEEnvelopeInBrowser, type BrowserDSSEVerificationResult } from '../lib/crypto';
import { useTheme } from '../lib/theme';

export const AuditorPortal: React.FC = () => {
  const { theme, toggleTheme } = useTheme();
  const params = new URLSearchParams(window.location.search);
  const token = params.get('token') || '';

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [label, setLabel] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [attestations, setAttestations] = useState<AttestationRecord[]>([]);
  const [ledgerProof, setLedgerProof] = useState<LedgerVerificationReport | null>(null);
  const [kernelPK, setKernelPK] = useState<{ key_id: string; public_key_b64: string; key_fingerprint: string } | null>(
    null
  );
  const [verifiedMap, setVerifiedMap] = useState<Record<string, BrowserDSSEVerificationResult>>({});

  useEffect(() => {
    if (!token) {
      setError('Missing ?token=g1aud_... scoped bearer token in URL.');
      setLoading(false);
      return;
    }
    fetch('/api/v1/auditor/vault', {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(async (r) => {
        const body = await r.json();
        if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
        return body;
      })
      .then((data) => {
        setLabel(data.token_metadata?.label || 'Scoped External Audit');
        setExpiresAt(data.token_metadata?.expires_at || '');
        setAttestations(data.attestations || []);
        setLedgerProof(data.ledger_proof || null);
        setKernelPK(data.kernel_public_key || null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Auditor authentication failed'))
      .finally(() => setLoading(false));
  }, [token]);

  const verifyCard = (att: AttestationRecord) => {
    if (!kernelPK) return;
    const res = verifyDSSEEnvelopeInBrowser(att.dsse_envelope, {
      [kernelPK.key_id]: kernelPK.public_key_b64,
    });
    setVerifiedMap((prev) => ({ ...prev, [att.attestation_id]: res }));
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="bg-slate-900 text-white border-b border-slate-800 px-6 py-4">
        <div className="max-w-5xl mx-auto flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <img
              src="/g1-logo.jpg"
              alt="G1-Warrant Logo"
              className="w-9 h-9 rounded object-contain bg-white p-0.5 shadow"
            />
            <Lock className="w-5 h-5 text-emerald-400" />
            <div>
              <h1 className="text-sm font-bold uppercase tracking-wider">
                G1-Warrant Scoped External Auditor Vault (Read-Only)
              </h1>
              <div className="text-xs font-mono text-slate-400">
                G1163RT Security Labs · NIST OSCAL 1.1.2 &amp; DSSE Cryptographic Evidence Surface
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {expiresAt && (
              <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-emerald-300">
                Scope: {label} · Expires {new Date(expiresAt).toLocaleString()}
              </span>
            )}
            <button
              type="button"
              onClick={toggleTheme}
              aria-pressed={theme === 'dark'}
              aria-label={theme === 'dark' ? 'Switch Auditor Vault to Light Mode' : 'Switch Auditor Vault to Dark Mode'}
              title={theme === 'dark' ? 'Switch Auditor Vault to Light Mode' : 'Switch Auditor Vault to Dark Mode'}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-semibold transition"
            >
              {theme === 'dark' ? (
                <>
                  <Sun className="w-3.5 h-3.5 text-amber-400" />
                  <span>Light</span>
                </>
              ) : (
                <>
                  <Moon className="w-3.5 h-3.5 text-slate-300" />
                  <span>Dark</span>
                </>
              )}
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto p-6 space-y-4">
        {loading && <div className="text-xs font-mono text-slate-600">Validating scoped bearer token...</div>}

        {error && (
          <div className="bg-red-50 border border-red-400 text-red-950 p-4 rounded flex items-center gap-3 text-xs font-mono">
            <AlertOctagon className="w-5 h-5 text-red-600 shrink-0" />
            <span>AUDITOR_ACCESS_DENIED: {error}</span>
          </div>
        )}

        {!loading && !error && (
          <>
            {ledgerProof && (
              <div className="bg-emerald-50 border border-emerald-300 text-emerald-950 p-3.5 rounded text-xs font-mono">
                <strong>APPEND-ONLY LEDGER INTEGRITY:</strong> all_valid={String(ledgerProof.all_valid)} across{' '}
                {ledgerProof.tables.map((t) => `${t.table_name}(${t.row_count})`).join(', ')}
              </div>
            )}

            {attestations.map((att) => {
              const vr = verifiedMap[att.attestation_id];
              return (
                <div key={att.attestation_id} className="bg-white border border-slate-300 rounded p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-2">
                    <div className="text-xs font-mono font-bold">
                      {att.attestation_id} · {att.cve_id} · {att.service_id} · Lockout: {att.lockout_policy_id}
                    </div>
                    <button
                      type="button"
                      onClick={() => verifyCard(att)}
                      className="inline-flex items-center gap-1 px-3 py-1 rounded bg-slate-900 text-white text-xs font-mono font-bold"
                    >
                      <ShieldCheck className="w-3.5 h-3.5" /> Verify DSSE + RFC 8785 JCS In-Browser
                    </button>
                  </div>

                  {vr && (
                    <div className="p-3 rounded border border-emerald-400 bg-emerald-50 text-emerald-950 text-xs font-mono space-y-1">
                      <div className="font-bold flex items-center gap-1">
                        <CheckCircle2 className="w-4 h-4" /> MATHEMATICAL PROOF VERIFIED: {String(vr.valid)}
                      </div>
                      <div>JCS Byte-Exact Match: {String(vr.jcsCanonicalMatch)}</div>
                      <div>PAE SHA-256: {vr.paeSHA256}</div>
                      {vr.signatureChecks.map((c) => (
                        <div key={c.keyid}>
                          {c.keyid}: {c.detail}
                        </div>
                      ))}
                    </div>
                  )}

                  <details className="text-xs font-mono">
                    <summary className="cursor-pointer font-semibold text-slate-700">
                      Inspect Embedded NIST OSCAL 1.1.2 POA&amp;M JSON Package
                    </summary>
                    <pre className="mt-2 p-3 rounded bg-slate-900 text-slate-100 overflow-x-auto text-[11px] max-h-96">
                      {JSON.stringify(att.oscal_poam_json, null, 2)}
                    </pre>
                  </details>
                </div>
              );
            })}
          </>
        )}
      </main>
    </div>
  );
};
