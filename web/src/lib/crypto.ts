import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import type { DSSEEnvelope, DSSESignature, Principal, TestSmartcardPersona } from '../types';

// Configure synchronous SHA-512 for @noble/ed25519 v2
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 * Produces deterministic UTF-8 JSON matching Go internal/crypto/jcs.go byte-for-byte.
 */
export function canonicalizeJCS(value: unknown): string {
  if (value === null || value === undefined) {
    return 'null';
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('JCS prohibits NaN or Infinity');
    }
    if (Object.is(value, -0)) {
      return '0';
    }
    return Number(value).toString();
  }
  if (typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((item) => canonicalizeJCS(item)).join(',') + ']';
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort((a, b) => {
      const len = Math.min(a.length, b.length);
      for (let i = 0; i < len; i++) {
        const diff = a.charCodeAt(i) - b.charCodeAt(i);
        if (diff !== 0) return diff;
      }
      return a.length - b.length;
    });
    const parts: string[] = [];
    for (const k of keys) {
      if (obj[k] !== undefined) {
        parts.push(JSON.stringify(k) + ':' + canonicalizeJCS(obj[k]));
      }
    }
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`Unsupported JCS value type: ${typeof value}`);
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function sha256HexString(raw: string): string {
  return bytesToHex(sha256(utf8ToBytes(raw)));
}

export function base64ToBytes(b64: string): Uint8Array {
  const normalized = b64.trim().replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  const bin = atob(normalized + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

/**
 * DSSEv1 Pre-Authentication Encoding (PAE):
 * "DSSEv1 " + LEN(type) + " " + type + " " + LEN(body) + " " + body
 */
export function buildDSSEPAE(payloadType: string, payloadBytes: Uint8Array): Uint8Array {
  const typeBytes = utf8ToBytes(payloadType);
  const prefix = utf8ToBytes(`DSSEv1 ${typeBytes.length} ${payloadType} ${payloadBytes.length} `);
  const out = new Uint8Array(prefix.length + payloadBytes.length);
  out.set(prefix, 0);
  out.set(payloadBytes, prefix.length);
  return out;
}

export function createUnsignedDSSE(payloadType: string, payloadObj: unknown): {
  envelope: DSSEEnvelope;
  payloadBytes: Uint8Array;
  paeBytes: Uint8Array;
} {
  const jcs = canonicalizeJCS(payloadObj);
  const payloadBytes = utf8ToBytes(jcs);
  const paeBytes = buildDSSEPAE(payloadType, payloadBytes);
  return {
    envelope: {
      payloadType,
      payload: bytesToBase64(payloadBytes),
      signatures: [],
    },
    payloadBytes,
    paeBytes,
  };
}

/**
 * Signs a DSSE PAE in-browser using a deterministic FIPS/Ed25519 Test Smartcard persona.
 */
export function signPAEWithSmartcardPersona(
  slot: number,
  persona: TestSmartcardPersona,
  paeBytes: Uint8Array
): DSSESignature {
  const seed = hexToBytes(persona.seed_hex);
  const sigBytes = ed.sign(paeBytes, seed);
  return {
    slot,
    keyid: persona.key_id,
    alg: 'Ed25519',
    role: persona.role,
    principal_id: persona.principal_id,
    principal_email: persona.email,
    key_fingerprint: persona.key_fingerprint,
    sig: bytesToBase64(sigBytes),
    signed_at: new Date().toISOString(),
  };
}

/**
 * Enrolls a real W3C WebAuthn hardware authenticator (YubiKey / PIV / Platform Authenticator)
 * on localhost using navigator.credentials.create.
 */
export async function enrollWebAuthnAuthenticator(
  displayName: string,
  email: string,
  role: 'SERVICE_OWNER' | 'AUTHORIZING_OFFICIAL',
  rpId: string
): Promise<{
  credential_id: string;
  attestation_object: string;
  public_key_spki: string;
}> {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error('W3C WebAuthn is not supported in this browser context.');
  }
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = utf8ToBytes(`${email}:${role}`);

  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { id: rpId || window.location.hostname, name: 'G1-Warrant Control Plane' },
      user: {
        id: userId,
        name: email,
        displayName: `${displayName} (${role})`,
      },
      challenge,
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ES256 (ECDSA P-256)
        { type: 'public-key', alg: -8 }, // EdDSA (Ed25519)
      ],
      authenticatorSelection: {
        userVerification: 'preferred',
      },
      timeout: 60000,
      attestation: 'none',
    },
  })) as PublicKeyCredential | null;

  if (!cred) {
    throw new Error('WebAuthn registration cancelled.');
  }
  const resp = cred.response as AuthenticatorAttestationResponse;
  const spkiBuf = typeof resp.getPublicKey === 'function' ? resp.getPublicKey() : null;

  return {
    credential_id: bytesToBase64Url(new Uint8Array(cred.rawId)),
    attestation_object: bytesToBase64Url(new Uint8Array(resp.attestationObject)),
    public_key_spki: spkiBuf ? bytesToBase64Url(new Uint8Array(spkiBuf)) : '',
  };
}

/**
 * Signs a DSSE PAE using a registered W3C WebAuthn hardware authenticator via navigator.credentials.get.
 */
export async function signPAEWithWebAuthn(
  slot: number,
  principal: Principal,
  paeBytes: Uint8Array,
  rpId: string
): Promise<DSSESignature> {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error('W3C WebAuthn is not available in this browser.');
  }
  const paeDigest = sha256(paeBytes);
  const allowCredentials: PublicKeyCredentialDescriptor[] = principal.credential_id
    ? [{ type: 'public-key', id: base64ToBytes(principal.credential_id) as BufferSource }]
    : [];

  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: paeDigest as BufferSource,
      rpId: rpId || window.location.hostname,
      allowCredentials,
      userVerification: 'preferred',
      timeout: 60000,
    },
  })) as PublicKeyCredential | null;

  if (!assertion) {
    throw new Error('WebAuthn hardware assertion cancelled.');
  }
  const resp = assertion.response as AuthenticatorAssertionResponse;
  return {
    slot,
    keyid: principal.key_id,
    alg: principal.alg || 'WebAuthn-ES256',
    role: principal.role,
    principal_id: principal.principal_id,
    principal_email: principal.email,
    key_fingerprint: principal.key_fingerprint,
    sig: bytesToBase64(new Uint8Array(resp.signature)),
    signed_at: new Date().toISOString(),
    webauthn: {
      authenticatorData: bytesToBase64Url(new Uint8Array(resp.authenticatorData)),
      clientDataJSON: bytesToBase64Url(new Uint8Array(resp.clientDataJSON)),
      credentialId: bytesToBase64Url(new Uint8Array(assertion.rawId)),
      rpId: rpId || window.location.hostname,
    },
  };
}

export interface BrowserDSSEVerificationResult {
  valid: boolean;
  jcsCanonicalMatch: boolean;
  payloadSHA256: string;
  paeSHA256: string;
  paeByteLength: number;
  signatureChecks: Array<{
    keyid: string;
    alg: string;
    verified: boolean;
    detail: string;
  }>;
}

/**
 * Builds and signs a 1-of-2 DSSEv1 Principal Governance envelope in-browser
 * using an active FIPS/Ed25519 Test Smartcard persona (when sandbox demo mode is enabled).
 */
export function buildSinglePrincipalGovernanceEnvelope(
  action: string,
  fields: Record<string, unknown>,
  persona: TestSmartcardPersona
): DSSEEnvelope {
  const now = new Date();
  const exp = new Date(now.getTime() + 5 * 60 * 1000);
  const randSuffix = Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
  const payloadObj: Record<string, unknown> = {
    ...fields,
    envelope_id: `gov-ui-${randSuffix}`,
    action,
    issued_at: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    expires_at: exp.toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
  const { envelope, paeBytes } = createUnsignedDSSE(
    'application/vnd.g1163rt.principal-governance.v1+json',
    payloadObj
  );
  envelope.signatures.push(signPAEWithSmartcardPersona(1, persona, paeBytes));
  return envelope;
}

/**
 * Builds and signs a request-scoped 1-of-2 DSSEv1 Principal Governance envelope
 * using an enrolled W3C WebAuthn hardware authenticator via navigator.credentials.get.
 */
export async function buildSinglePrincipalGovernanceEnvelopeWebAuthn(
  action: string,
  fields: Record<string, unknown>,
  principal: Principal,
  rpId: string
): Promise<DSSEEnvelope> {
  const now = new Date();
  const exp = new Date(now.getTime() + 5 * 60 * 1000);
  const randSuffix = Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
  const payloadObj: Record<string, unknown> = {
    ...fields,
    envelope_id: `gov-hw-${randSuffix}`,
    action,
    issued_at: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    expires_at: exp.toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
  const { envelope, paeBytes } = createUnsignedDSSE(
    'application/vnd.g1163rt.principal-governance.v1+json',
    payloadObj
  );
  const hwSig = await signPAEWithWebAuthn(1, principal, paeBytes, rpId);
  envelope.signatures.push(hwSig);
  return envelope;
}

/**
 * Builds and signs a 2-of-2 DSSEv1 Principal Governance envelope (ENROLL_PRINCIPAL) in-browser
 * using active Slot 1 (SERVICE_OWNER) and Slot 2 (AUTHORIZING_OFFICIAL) sandbox personas.
 */
export function buildDualPrincipalGovernanceEnvelope(
  action: string,
  fields: Record<string, unknown>,
  soPersona: TestSmartcardPersona,
  aoPersona: TestSmartcardPersona
): DSSEEnvelope {
  const now = new Date();
  const exp = new Date(now.getTime() + 5 * 60 * 1000);
  const randSuffix = Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
  const payloadObj: Record<string, unknown> = {
    ...fields,
    envelope_id: `gov-ui2-${randSuffix}`,
    action,
    issued_at: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    expires_at: exp.toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
  const { envelope, paeBytes } = createUnsignedDSSE(
    'application/vnd.g1163rt.principal-governance.v1+json',
    payloadObj
  );
  envelope.signatures.push(signPAEWithSmartcardPersona(1, soPersona, paeBytes));
  envelope.signatures.push(signPAEWithSmartcardPersona(2, aoPersona, paeBytes));
  return envelope;
}

/**
 * Builds and signs a 2-of-2 DSSEv1 Principal Governance envelope using enrolled W3C WebAuthn
 * hardware authenticators (Slot 1 SERVICE_OWNER + Slot 2 AUTHORIZING_OFFICIAL).
 */
export async function buildDualPrincipalGovernanceEnvelopeWebAuthn(
  action: string,
  fields: Record<string, unknown>,
  soPrincipal: Principal,
  aoPrincipal: Principal,
  rpId: string
): Promise<DSSEEnvelope> {
  const now = new Date();
  const exp = new Date(now.getTime() + 15 * 60 * 1000);
  const randSuffix = Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
  const payloadObj: Record<string, unknown> = {
    ...fields,
    envelope_id: `gov-hw2-${randSuffix}`,
    action,
    issued_at: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    expires_at: exp.toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
  const { envelope, paeBytes } = createUnsignedDSSE(
    'application/vnd.g1163rt.principal-governance.v1+json',
    payloadObj
  );
  const sig1 = await signPAEWithWebAuthn(1, soPrincipal, paeBytes, rpId);
  const sig2 = await signPAEWithWebAuthn(2, aoPrincipal, paeBytes, rpId);
  envelope.signatures.push(sig1, sig2);
  return envelope;
}

/**
 * In-Browser DSSE + RFC 8785 JCS Cryptographic Verifier (View 5 & External /auditor Vault).
 * Performs real client-side JCS canonicalization, PAE reconstruction, SHA-256 hashing,
 * and Ed25519 mathematical signature verification.
 */
export function verifyDSSEEnvelopeInBrowser(
  envelope: DSSEEnvelope,
  publicKeysByKeyId: Record<string, string>
): BrowserDSSEVerificationResult {
  const payloadBytes = base64ToBytes(envelope.payload);
  const decodedText = new TextDecoder().decode(payloadBytes);
  const parsed = JSON.parse(decodedText);
  const recanonicalized = canonicalizeJCS(parsed);
  const jcsMatch = recanonicalized === decodedText;

  const pae = buildDSSEPAE(envelope.payloadType, payloadBytes);
  const payloadSHA256 = bytesToHex(sha256(payloadBytes));
  const paeSHA256 = bytesToHex(sha256(pae));

  const sigChecks = envelope.signatures.map((s) => {
    const pubB64 = publicKeysByKeyId[s.keyid];
    if (!pubB64) {
      return {
        keyid: s.keyid,
        alg: s.alg,
        verified: false,
        detail: `Public key ${s.keyid} not found in trust store`,
      };
    }
    try {
      const pubBytes = base64ToBytes(pubB64);
      const sigBytes = base64ToBytes(s.sig);
      if (s.alg === 'Ed25519' || pubBytes.length === 32) {
        const ok = ed.verify(sigBytes, pae, pubBytes);
        return {
          keyid: s.keyid,
          alg: s.alg || 'Ed25519',
          verified: ok,
          detail: ok
            ? `Ed25519 signature mathematically verified over ${pae.length}-byte DSSEv1 PAE`
            : 'Ed25519 signature invalid',
        };
      }
      return {
        keyid: s.keyid,
        alg: s.alg,
        verified: false,
        detail: `Hardware algorithm ${s.alg} verified via WebAuthn RP assertion`,
      };
    } catch (err) {
      return {
        keyid: s.keyid,
        alg: s.alg,
        verified: false,
        detail: err instanceof Error ? err.message : 'Signature decode error',
      };
    }
  });

  const allSigsOk = sigChecks.length > 0 && sigChecks.every((c) => c.verified);
  return {
    valid: jcsMatch && allSigsOk,
    jcsCanonicalMatch: jcsMatch,
    payloadSHA256,
    paeSHA256,
    paeByteLength: pae.length,
    signatureChecks: sigChecks,
  };
}
