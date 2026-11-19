import React, { useState } from 'react';
import { KeyRound, ShieldAlert, CheckCircle2, Fingerprint, Usb } from 'lucide-react';
import type { DSSEEnvelope, DSSESignature, Principal, TestSmartcardPersona } from '../types';
import { createUnsignedDSSE, signPAEWithSmartcardPersona, signPAEWithWebAuthn } from '../lib/crypto';

interface DualKeyCeremonyPanelProps {
  title: string;
  payloadType: string;
  buildPayload: () => unknown;
  testPersonas: TestSmartcardPersona[];
  principals: Principal[];
  rpId: string;
  smartcardBarEnabled: boolean;
  isMobileViewport: boolean;
  submitLabel: string;
  onSubmitEnvelope: (env: DSSEEnvelope) => Promise<void>;
  secondaryLabel?: string;
  onSecondaryEnvelope?: (env: DSSEEnvelope) => Promise<void>;
}

export const DualKeyCeremonyPanel: React.FC<DualKeyCeremonyPanelProps> = ({
  title,
  payloadType,
  buildPayload,
  testPersonas,
  principals,
  rpId,
  smartcardBarEnabled,
  isMobileViewport,
  submitLabel,
  onSubmitEnvelope,
  secondaryLabel,
  onSecondaryEnvelope,
}) => {
  const [slot1Sig, setSlot1Sig] = useState<DSSESignature | null>(null);
  const [slot2Sig, setSlot2Sig] = useState<DSSESignature | null>(null);
  const [lockedEnvelope, setLockedEnvelope] = useState<{
    envelope: DSSEEnvelope;
    paeBytes: Uint8Array;
  } | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const ensureUnsigned = () => {
    if (lockedEnvelope) return lockedEnvelope;
    const built = createUnsignedDSSE(payloadType, buildPayload());
    const state = { envelope: built.envelope, paeBytes: built.paeBytes };
    setLockedEnvelope(state);
    return state;
  };

  const resetCeremony = () => {
    setSlot1Sig(null);
    setSlot2Sig(null);
    setLockedEnvelope(null);
    setErrorMsg(null);
  };

  const handleSmartcardSign = (slot: 1 | 2, persona: TestSmartcardPersona) => {
    if (isMobileViewport) return;
    setErrorMsg(null);
    try {
      const state = ensureUnsigned();
      const sig = signPAEWithSmartcardPersona(slot, persona, state.paeBytes);
      if (slot === 1) setSlot1Sig(sig);
      else setSlot2Sig(sig);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Smartcard signing error');
    }
  };

  const handleWebAuthnSign = async (slot: 1 | 2, principal: Principal) => {
    if (isMobileViewport) return;
    setErrorMsg(null);
    setBusy(true);
    try {
      const state = ensureUnsigned();
      const sig = await signPAEWithWebAuthn(slot, principal, state.paeBytes, rpId);
      if (slot === 1) setSlot1Sig(sig);
      else setSlot2Sig(sig);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'WebAuthn signing error');
    } finally {
      setBusy(false);
    }
  };

  const executeSubmit = async (handler: (env: DSSEEnvelope) => Promise<void>) => {
    if (!lockedEnvelope || !slot1Sig || !slot2Sig) return;
    setErrorMsg(null);
    setBusy(true);
    try {
      const finalEnv: DSSEEnvelope = {
        ...lockedEnvelope.envelope,
        signatures: [slot1Sig, slot2Sig],
      };
      await handler(finalEnv);
      resetCeremony();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Ceremony submission rejected');
    } finally {
      setBusy(false);
    }
  };

  const hardwarePrincipals = principals.filter((p) => p.authenticator_mode === 'WEBAUTHN_HARDWARE' && !p.revoked);

  return (
    <div className="border border-slate-300 bg-slate-50 rounded p-4 space-y-3">
      <div className="flex items-center justify-between border-b border-slate-200 pb-2">
        <div className="flex items-center gap-2">
          <KeyRound className="w-4 h-4 text-slate-700" />
          <span className="text-xs font-bold uppercase tracking-wider text-slate-800">{title}</span>
        </div>
        {(slot1Sig || slot2Sig) && (
          <button
            type="button"
            onClick={resetCeremony}
            className="text-xs text-slate-600 hover:text-slate-900 underline"
          >
            Reset Slots
          </button>
        )}
      </div>

      {isMobileViewport && (
        <div
          role="alert"
          className="bg-amber-100 border border-amber-400 text-amber-950 text-xs p-2.5 rounded flex items-center gap-2"
        >
          <ShieldAlert className="w-4 h-4 shrink-0" />
          <span>
            <strong>VIEWPORT POLICY (&lt; 1024px):</strong> Cryptographic dual-key signing is disabled on mobile viewports. Use desktop (&gt;= 1024px) for hardware ceremonies.
          </span>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {/* SLOT 1 */}
        <div className="bg-white border border-slate-200 rounded p-3 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-700">SLOT 1 — SERVICE OWNER (AC-5)</span>
            {slot1Sig ? (
              <span className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-800 bg-emerald-50 border border-emerald-300 px-2 py-0.5 rounded">
                <CheckCircle2 className="w-3.5 h-3.5" /> Signed ({slot1Sig.principal_id})
              </span>
            ) : (
              <span className="text-xs text-slate-500">Awaiting Signature</span>
            )}
          </div>
          {slot1Sig && (
            <div className="text-[11px] font-mono bg-slate-50 p-1.5 rounded border border-slate-200 truncate">
              key={slot1Sig.keyid} · sig={slot1Sig.sig.slice(0, 20)}...
            </div>
          )}
          {smartcardBarEnabled && (
            <div className="flex flex-wrap gap-1.5 pt-1">
              {testPersonas.map((p) => (
                <button
                  key={`s1-${p.key_id}`}
                  type="button"
                  disabled={isMobileViewport || busy}
                  onClick={() => handleSmartcardSign(1, p)}
                  className={`text-[11px] px-2 py-1 rounded border font-medium transition ${
                    p.role === 'SERVICE_OWNER' && !p.principal_id.includes('mallory')
                      ? 'bg-slate-900 text-white border-slate-900 hover:bg-slate-800'
                      : 'bg-rose-50 text-rose-900 border-rose-300 hover:bg-rose-100'
                  } disabled:opacity-40`}
                  title={p.badge_label}
                >
                  <Fingerprint className="w-3 h-3 inline mr-1" />
                  {p.display_name.split(' ')[0]} ({p.role === 'SERVICE_OWNER' ? 'SO' : p.role === 'AUTHORIZING_OFFICIAL' ? 'AO' : 'SYSADMIN'})
                </button>
              ))}
            </div>
          )}
          {hardwarePrincipals.length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-1 border-t border-slate-100">
              {hardwarePrincipals.map((hp) => (
                <button
                  key={`hw1-${hp.key_id}`}
                  type="button"
                  disabled={isMobileViewport || busy}
                  onClick={() => handleWebAuthnSign(1, hp)}
                  className="text-[11px] px-2 py-1 rounded border border-indigo-300 bg-indigo-50 text-indigo-950 hover:bg-indigo-100 font-medium disabled:opacity-40"
                >
                  <Usb className="w-3 h-3 inline mr-1" />
                  WebAuthn: {hp.display_name} ({hp.role})
                </button>
              ))}
            </div>
          )}
        </div>

        {/* SLOT 2 */}
        <div className="bg-white border border-slate-200 rounded p-3 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-700">SLOT 2 — AUTHORIZING OFFICIAL (AC-5)</span>
            {slot2Sig ? (
              <span className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-800 bg-emerald-50 border border-emerald-300 px-2 py-0.5 rounded">
                <CheckCircle2 className="w-3.5 h-3.5" /> Signed ({slot2Sig.principal_id})
              </span>
            ) : (
              <span className="text-xs text-slate-500">Awaiting Signature</span>
            )}
          </div>
          {slot2Sig && (
            <div className="text-[11px] font-mono bg-slate-50 p-1.5 rounded border border-slate-200 truncate">
              key={slot2Sig.keyid} · sig={slot2Sig.sig.slice(0, 20)}...
            </div>
          )}
          {smartcardBarEnabled && (
            <div className="flex flex-wrap gap-1.5 pt-1">
              {testPersonas.map((p) => (
                <button
                  key={`s2-${p.key_id}`}
                  type="button"
                  disabled={isMobileViewport || busy}
                  onClick={() => handleSmartcardSign(2, p)}
                  className={`text-[11px] px-2 py-1 rounded border font-medium transition ${
                    p.role === 'AUTHORIZING_OFFICIAL'
                      ? 'bg-slate-900 text-white border-slate-900 hover:bg-slate-800'
                      : 'bg-rose-50 text-rose-900 border-rose-300 hover:bg-rose-100'
                  } disabled:opacity-40`}
                  title={p.badge_label}
                >
                  <Fingerprint className="w-3 h-3 inline mr-1" />
                  {p.display_name.split(' ')[0]} ({p.role === 'SERVICE_OWNER' ? 'SO' : p.role === 'AUTHORIZING_OFFICIAL' ? 'AO' : 'SYSADMIN'})
                </button>
              ))}
            </div>
          )}
          {hardwarePrincipals.length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-1 border-t border-slate-100">
              {hardwarePrincipals.map((hp) => (
                <button
                  key={`hw2-${hp.key_id}`}
                  type="button"
                  disabled={isMobileViewport || busy}
                  onClick={() => handleWebAuthnSign(2, hp)}
                  className="text-[11px] px-2 py-1 rounded border border-indigo-300 bg-indigo-50 text-indigo-950 hover:bg-indigo-100 font-medium disabled:opacity-40"
                >
                  <Usb className="w-3 h-3 inline mr-1" />
                  WebAuthn: {hp.display_name} ({hp.role})
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {errorMsg && (
        <div role="alert" className="bg-red-50 border border-red-400 text-red-950 text-xs font-mono p-2.5 rounded">
          KERNEL_CEREMONY_REJECTED: {errorMsg}
        </div>
      )}

      <div className="flex items-center justify-end gap-2 pt-1">
        {secondaryLabel && onSecondaryEnvelope && (
          <button
            type="button"
            disabled={isMobileViewport || !slot1Sig || !slot2Sig || busy}
            onClick={() => executeSubmit(onSecondaryEnvelope)}
            className="px-3 py-1.5 text-xs font-bold rounded border border-red-300 bg-red-50 text-red-900 hover:bg-red-100 disabled:opacity-40"
          >
            {secondaryLabel}
          </button>
        )}
        <button
          type="button"
          disabled={isMobileViewport || !slot1Sig || !slot2Sig || busy}
          onClick={() => executeSubmit(onSubmitEnvelope)}
          className="px-4 py-1.5 text-xs font-bold rounded bg-emerald-700 text-white hover:bg-emerald-800 disabled:opacity-40"
        >
          {busy ? 'VERIFYING DSSE + OPA AC-5...' : submitLabel}
        </button>
      </div>
    </div>
  );
};
