import React, { useEffect, useState } from 'react';
import { ShieldCheck, Lock, Smartphone, KeyRound, Sun, Moon, ArrowRight, CheckCircle2, AlertTriangle, Zap } from 'lucide-react';
import type { ThemeMode } from '../lib/theme';

export interface ConsoleSessionPrincipal {
  email: string;
  display_name: string;
  role: string;
  clearance: string;
  auth_method: string;
  iat: number;
  exp: number;
}

interface DemoAccount {
  email: string;
  display_name: string;
  role: string;
  clearance: string;
  passphrase: string;
  mfa_code: string;
}

interface PushChallengeState {
  challenge_id: string;
  provider: string;
  provider_title: string;
  device: string;
  endpoint: string;
  match_number: string;
}

interface LoginPortalProps {
  theme: ThemeMode;
  onToggleTheme: () => void;
  onAuthenticated: (principal: ConsoleSessionPrincipal) => void;
}

export const LoginPortal: React.FC<LoginPortalProps> = ({
  theme,
  onToggleTheme,
  onAuthenticated,
}) => {
  const [email, setEmail] = useState('ops@g1163rt.ai');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [demoAccounts, setDemoAccounts] = useState<DemoAccount[]>([]);
  const [demoEnabled, setDemoEnabled] = useState(false);
  const [airgapMode, setAirgapMode] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [alert, setAlert] = useState<{ text: string; isError: boolean } | null>(null);
  const [pushChallenge, setPushChallenge] = useState<PushChallengeState | null>(null);

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const res = await fetch('/api/v1/auth/mfa-providers', { cache: 'no-store' });
        if (!res.ok || !active) return;
        const data = await res.json();
        setAirgapMode(Boolean(data.airgap_mode));
        setDemoEnabled(Boolean(data.demo_accounts_enabled));
        if (Array.isArray(data.demo_accounts)) {
          setDemoAccounts(data.demo_accounts);
        }
      } catch {
        // Fail silently; form still allows standard login
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setAlert(null);
    try {
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email.trim(),
          password,
          mfa_code: mfaCode.trim(),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAlert({ text: data.error || `Authentication failed (HTTP ${res.status})`, isError: true });
        return;
      }
      if (data.principal) {
        onAuthenticated(data.principal as ConsoleSessionPrincipal);
      }
    } catch (err) {
      setAlert({ text: err instanceof Error ? err.message : 'Network error during authentication', isError: true });
    } finally {
      setSubmitting(false);
    }
  };

  const handleAutoFillMFA = () => {
    const match = demoAccounts.find(
      (a) => a.email.toLowerCase() === email.trim().toLowerCase()
    ) || demoAccounts[0];
    if (!match) {
      setAlert({ text: 'Auto-fill is only available for sandbox demo accounts.', isError: true });
      return;
    }
    setEmail(match.email);
    if (!password) {
      setPassword(match.passphrase);
    }
    setMfaCode(match.mfa_code);
    setAlert({ text: `Populated sandbox TOTP code (${match.mfa_code}) for ${match.email}.`, isError: false });
  };

  const handleFillDemoAccount = (acct: DemoAccount) => {
    setEmail(acct.email);
    setPassword(acct.passphrase);
    setMfaCode(acct.mfa_code);
    setPushChallenge(null);
    setAlert({
      text: `Loaded demo credentials for ${acct.email} (${acct.role}). Click "Authenticate & Open Console" to sign in.`,
      isError: false,
    });
  };

  const handleQuickLogin = async (targetEmail?: string) => {
    setSubmitting(true);
    setAlert(null);
    try {
      const res = await fetch('/api/v1/auth/dev-quick-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: targetEmail || 'ops@g1163rt.ai' }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAlert({ text: data.error || `Quick login failed (HTTP ${res.status})`, isError: true });
        return;
      }
      if (data.principal) {
        onAuthenticated(data.principal as ConsoleSessionPrincipal);
      }
    } catch (err) {
      setAlert({ text: err instanceof Error ? err.message : 'Quick login request failed', isError: true });
    } finally {
      setSubmitting(false);
    }
  };

  const handleDispatchPush = async (provider: 'duo' | 'okta') => {
    setAlert(null);
    setPushChallenge(null);
    if (!password) {
      const match = demoAccounts.find((a) => a.email.toLowerCase() === email.trim().toLowerCase());
      if (match) {
        setPassword(match.passphrase);
      } else {
        setAlert({ text: 'Enter your operator passphrase before dispatching a federated push challenge.', isError: true });
        return;
      }
    }
    const effectivePassword =
      password ||
      demoAccounts.find((a) => a.email.toLowerCase() === email.trim().toLowerCase())?.passphrase ||
      '';
    setSubmitting(true);
    try {
      const res = await fetch('/api/v1/auth/push-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email.trim(),
          password: effectivePassword,
          provider,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAlert({ text: data.error || `Push dispatch failed (HTTP ${res.status})`, isError: true });
        return;
      }
      setPushChallenge(data as PushChallengeState);
    } catch (err) {
      setAlert({ text: err instanceof Error ? err.message : 'Push dispatch error', isError: true });
    } finally {
      setSubmitting(false);
    }
  };

  const handleApprovePush = async () => {
    if (!pushChallenge) return;
    setSubmitting(true);
    setAlert(null);
    try {
      const res = await fetch('/api/v1/auth/push-verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challenge_id: pushChallenge.challenge_id,
          match_number: pushChallenge.match_number,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAlert({ text: data.error || `Push verification failed (HTTP ${res.status})`, isError: true });
        return;
      }
      if (data.principal) {
        onAuthenticated(data.principal as ConsoleSessionPrincipal);
      }
    } catch (err) {
      setAlert({ text: err instanceof Error ? err.message : 'Push verify error', isError: true });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col">
      {/* Top Institutional Status Bar */}
      <header className="w-full bg-white border-b border-slate-200 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <img
            src="/g1-logo.jpg"
            alt="G1-Warrant Logo"
            className="w-8 h-8 rounded object-contain bg-white border border-slate-200 p-0.5"
          />
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold tracking-tight text-slate-900">G1-WARRANT</span>
              <span className="px-1.5 py-0.5 rounded border border-slate-200 bg-slate-100 text-[10px] font-mono font-semibold text-slate-700">
                v1.4.1
              </span>
            </div>
            <div className="text-[11px] font-mono text-slate-500">
              G1163RT Security Labs // Zero-Trust MFA Ingress Gate
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          {demoEnabled && (
            <button
              type="button"
              onClick={() => handleQuickLogin('ops@g1163rt.ai')}
              disabled={submitting}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-slate-300 bg-slate-900 hover:bg-slate-800 text-white text-xs font-mono font-semibold cursor-pointer disabled:opacity-50"
              title="Sandbox Mode Admin Quick-Login"
            >
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              <span>DEV ADMIN LOGIN</span>
            </button>
          )}
          <button
            type="button"
            onClick={onToggleTheme}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 text-xs font-mono font-semibold cursor-pointer"
            title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
          >
            {theme === 'dark' ? <Sun className="w-3.5 h-3.5 text-amber-500" /> : <Moon className="w-3.5 h-3.5 text-slate-600" />}
            <span>{theme === 'dark' ? 'Light' : 'Dark'}</span>
          </button>
        </div>
      </header>

      {/* Main Asymmetric Institutional Layout */}
      <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-10 grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left Column (5/12): Security Posture Brief & Sandbox Demo Accounts */}
        <section className="lg:col-span-5 space-y-6">
          <div className="space-y-2">
            <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded border border-emerald-300 bg-emerald-50 text-emerald-800 text-[11px] font-mono font-semibold">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>WORM LEDGER &amp; NIST AC-5 ENFORCED</span>
            </div>
            <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
              SecOps Administrative &amp; MFA Portal
            </h1>
            <p className="text-sm text-slate-600 leading-relaxed max-w-[65ch]">
              Authenticate with a PBKDF2-HMAC-SHA256 operator principal and 6-digit RFC 6238 TOTP
              or Federated Push challenge to access the 5-View G1-Warrant Deterministic Control Plane.
            </p>
          </div>

          {demoEnabled ? (
            <div className="bg-white border border-slate-200 rounded-md overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-200 bg-slate-100 flex items-center justify-between">
                <div>
                  <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-900">
                    Sandbox Demo Accounts
                  </h2>
                  <p className="text-[11px] text-slate-600 mt-0.5">
                    Disabled automatically in Kubernetes / Live production posture.
                  </p>
                </div>
                <span className="px-2 py-0.5 rounded border border-amber-300 bg-amber-50 text-amber-900 text-[10px] font-mono font-semibold">
                  SANDBOX
                </span>
              </div>

              <div className="divide-y divide-slate-200">
                {demoAccounts.map((acct) => (
                  <div key={acct.email} className="p-3.5 space-y-2">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="text-xs font-semibold text-slate-900">{acct.display_name}</div>
                        <div className="text-[11px] font-mono text-slate-600 mt-0.5">{acct.email}</div>
                      </div>
                      <span className="px-1.5 py-0.5 rounded border border-slate-200 bg-slate-100 text-[10px] font-mono font-semibold text-slate-700 shrink-0">
                        {acct.role}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-[11px] font-mono bg-slate-50 border border-slate-200 rounded px-2.5 py-1.5">
                      <div>
                        <span className="text-slate-500">Pass: </span>
                        <span className="text-slate-900 select-all">{acct.passphrase}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">TOTP: </span>
                        <span className="text-slate-900 font-semibold select-all">{acct.mfa_code}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 pt-0.5">
                      <button
                        type="button"
                        onClick={() => handleFillDemoAccount(acct)}
                        className="px-2.5 py-1 rounded border border-slate-300 bg-white hover:bg-slate-100 text-slate-800 text-[11px] font-mono font-semibold cursor-pointer"
                      >
                        Fill Form
                      </button>
                      <button
                        type="button"
                        disabled={submitting}
                        onClick={() => handleQuickLogin(acct.email)}
                        className="px-2.5 py-1 rounded border border-slate-900 bg-slate-900 hover:bg-slate-800 text-white text-[11px] font-mono font-semibold cursor-pointer disabled:opacity-50"
                      >
                        Sign In as {acct.role.split('_')[0]}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="bg-white border border-slate-200 rounded-md p-4 text-xs text-slate-600 space-y-1.5">
              <div className="font-semibold text-slate-900 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-slate-700" />
                <span>Production Posture Active</span>
              </div>
              <p>
                Sandbox demo accounts are disabled. Authenticate with an operator account provisioned
                via <code className="font-mono text-slate-800">WARRANT_CONSOLE_USERS_FILE</code> or
                your enterprise SSO/MFA provider.
              </p>
            </div>
          )}
        </section>

        {/* Right Column (7/12): G1-Combine-Style MFA Login Card */}
        <section className="lg:col-span-7">
          <div className="bg-white border border-slate-200 rounded-md p-6 space-y-5">
            {/* Card Header */}
            <div className="flex items-center justify-between border-b border-slate-200 pb-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-md bg-slate-50 border border-slate-200 flex items-center justify-center p-1">
                  <img src="/g1-logo.jpg" alt="G1-Warrant" className="w-full h-full object-contain" />
                </div>
                <div>
                  <h2 className="text-base font-semibold tracking-tight text-slate-900">
                    Operator Sign-In
                  </h2>
                  <p className="text-xs font-mono text-slate-500">
                    Deterministic Control Plane · 5-View Console
                  </p>
                </div>
              </div>
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded border border-emerald-300 bg-emerald-50 text-[10px] font-mono font-semibold text-emerald-800">
                <span className="w-1.5 h-1.5 rounded-sm bg-emerald-600" />
                <span>MFA REQUIRED</span>
              </span>
            </div>

            {/* Alert Box */}
            {alert && (
              <div
                role="alert"
                className={`rounded-md p-3 text-xs font-mono border flex items-start gap-2 ${
                  alert.isError
                    ? 'bg-rose-50 border-rose-300 text-rose-900'
                    : 'bg-emerald-50 border-emerald-300 text-emerald-900'
                }`}
              >
                {alert.isError ? (
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-700" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-700" />
                )}
                <span>{alert.text}</span>
              </div>
            )}

            {/* Login Form */}
            <form onSubmit={handleLoginSubmit} className="space-y-4">
              <div>
                <label
                  htmlFor="warrantLoginEmail"
                  className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-700 mb-1"
                >
                  Operator Principal (Account / Email)
                </label>
                <input
                  id="warrantLoginEmail"
                  name="email"
                  type="text"
                  required
                  autoComplete="username"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="ops@g1163rt.ai"
                  className="w-full bg-slate-50 border border-slate-300 focus:border-blue-600 focus:bg-white rounded-md px-3 py-2 text-xs font-mono text-slate-900 focus:outline-none"
                />
              </div>

              <div>
                <label
                  htmlFor="warrantLoginPassword"
                  className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-700 mb-1"
                >
                  Operator Passphrase (PBKDF2-HMAC-SHA256)
                </label>
                <input
                  id="warrantLoginPassword"
                  name="password"
                  type="password"
                  required
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter operator passphrase"
                  className="w-full bg-slate-50 border border-slate-300 focus:border-blue-600 focus:bg-white rounded-md px-3 py-2 text-xs font-mono text-slate-900 focus:outline-none"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label
                    htmlFor="warrantLoginMfa"
                    className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-700"
                  >
                    6-Digit TOTP / Authenticator Code
                  </label>
                  {demoEnabled && (
                    <button
                      type="button"
                      onClick={handleAutoFillMFA}
                      className="text-[11px] font-mono font-semibold text-blue-600 hover:underline cursor-pointer"
                    >
                      Auto-Fill MFA Token
                    </button>
                  )}
                </div>
                <input
                  id="warrantLoginMfa"
                  name="mfa_code"
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  required
                  autoComplete="one-time-code"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  placeholder="482910 (RFC 6238 / Duo / Okta TOTP)"
                  className="w-full bg-slate-50 border border-slate-300 focus:border-blue-600 focus:bg-white rounded-md px-3 py-2 text-xs font-mono tracking-widest text-slate-900 focus:outline-none"
                />
              </div>

              {/* Enterprise Federated Push 2FA */}
              <div className="pt-1 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
                    Enterprise Federated Push 2FA
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-slate-200 bg-slate-100 text-slate-700">
                    DUO · OKTA · TOTP
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2.5">
                  <button
                    type="button"
                    disabled={submitting || airgapMode}
                    onClick={() => handleDispatchPush('duo')}
                    className="inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-md border border-slate-300 bg-white hover:bg-slate-100 text-slate-800 text-xs font-mono font-semibold cursor-pointer disabled:opacity-50"
                  >
                    <Smartphone className="w-3.5 h-3.5 text-emerald-700" />
                    <span>Send Duo Push</span>
                  </button>
                  <button
                    type="button"
                    disabled={submitting || airgapMode}
                    onClick={() => handleDispatchPush('okta')}
                    className="inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-md border border-slate-300 bg-white hover:bg-slate-100 text-slate-800 text-xs font-mono font-semibold cursor-pointer disabled:opacity-50"
                  >
                    <KeyRound className="w-3.5 h-3.5 text-blue-700" />
                    <span>Verify with Okta</span>
                  </button>
                </div>
                {airgapMode && (
                  <div className="text-[11px] font-mono text-amber-900 bg-amber-50 border border-amber-300 rounded-md px-3 py-1.5">
                    Strict Air-Gap Active: Cloud Push disabled; use offline RFC 6238 TOTP.
                  </div>
                )}
              </div>

              {/* Interactive Push Number-Matching Challenge Panel */}
              {pushChallenge && (
                <div className="rounded-md p-3.5 bg-slate-50 border border-blue-300 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-semibold text-slate-900">
                      {pushChallenge.provider_title}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">
                      {pushChallenge.endpoint}
                    </span>
                  </div>
                  <div className="flex items-center justify-between bg-white border border-slate-200 rounded px-3 py-2">
                    <div className="text-[11px] font-mono text-slate-600">
                      <div>
                        Device: <span className="text-slate-900 font-semibold">{pushChallenge.device}</span>
                      </div>
                      <div className="mt-0.5">Confirm number match on device:</div>
                    </div>
                    <div className="text-lg font-mono font-bold text-slate-900 px-3 py-1 rounded bg-amber-50 border border-amber-300">
                      {pushChallenge.match_number}
                    </div>
                  </div>
                  <button
                    type="button"
                    disabled={submitting}
                    onClick={handleApprovePush}
                    className="w-full py-2 px-3 rounded-md bg-emerald-700 hover:bg-emerald-800 text-white font-mono font-semibold text-xs cursor-pointer disabled:opacity-50"
                  >
                    Approve Push &amp; Open Console
                  </button>
                </div>
              )}

              <button
                type="submit"
                disabled={submitting}
                className="w-full py-2.5 px-4 rounded-md bg-slate-900 hover:bg-slate-800 text-white font-mono font-semibold text-xs uppercase tracking-wider inline-flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
              >
                <span>{submitting ? 'Authenticating...' : 'Authenticate & Open Console'}</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </form>

            {/* Security Controls Footer */}
            <div className="pt-4 border-t border-slate-200 space-y-1.5 text-[11px] font-mono text-slate-600">
              <div className="flex items-center justify-between">
                <span>Session Cookie:</span>
                <span className="text-slate-900">HMAC-SHA256 · HttpOnly · SameSite=Strict</span>
              </div>
              <div className="flex items-center justify-between">
                <span>Password KDF:</span>
                <span className="text-emerald-800 font-semibold">100,000-Round Salted PBKDF2-HMAC-SHA256</span>
              </div>
              <div className="flex items-center justify-between">
                <span>Auditor Portal:</span>
                <a href="/auditor" className="text-blue-600 hover:underline">
                  Open 3PAO Read-Only Vault (/auditor)
                </a>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
};
