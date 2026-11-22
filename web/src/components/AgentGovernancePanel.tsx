import React, { useState } from 'react';
import { Bot, Building2, ShieldOff, AlertTriangle, RefreshCw, UserCheck } from 'lucide-react';
import type {
  AgentIdentity,
  CommissioningFunction,
  PendingSponsorTransfer,
  Principal,
} from '../types';
import { formatDurationSeconds, shortHash } from '../lib/templates';

interface AgentGovernancePanelProps {
  commissioningFunctions: CommissioningFunction[];
  agents: AgentIdentity[];
  pendingTransfers: PendingSponsorTransfer[];
  principals: Principal[];
  nowMs: number;
  onRevokeAgent: (agentId: string, reasonCode: string) => Promise<void>;
  onEmitIGAEvent: (eventType: string, principalId: string) => Promise<void>;
  onTransferSponsors: (fn: CommissioningFunction, newPrimarySO: string, newPrimaryAO: string) => Promise<void>;
}

export const AgentGovernancePanel: React.FC<AgentGovernancePanelProps> = ({
  commissioningFunctions,
  agents,
  pendingTransfers,
  principals,
  nowMs,
  onRevokeAgent,
  onEmitIGAEvent,
  onTransferSponsors,
}) => {
  const [igaType, setIgaType] = useState('ROLE_TRANSFER');
  const [igaPrincipal, setIgaPrincipal] = useState('');
  const [panelMsg, setPanelMsg] = useState<string | null>(null);
  const [panelErr, setPanelErr] = useState<string | null>(null);

  const activeSOs = principals.filter((p) => !p.revoked && p.role === 'SERVICE_OWNER');
  const activeAOs = principals.filter((p) => !p.revoked && p.role === 'AUTHORIZING_OFFICIAL');

  const formatCountdown = (iso?: string) => {
    if (!iso) return '—';
    const diffSec = Math.max(0, Math.floor((new Date(iso).getTime() - nowMs) / 1000));
    return diffSec === 0 ? 'EXPIRED (0s)' : formatDurationSeconds(diffSec);
  };

  const stateBadgeClass = (state: string) => {
    switch (state) {
      case 'ACTIVE':
        return 'bg-emerald-50 border-emerald-300 text-emerald-950';
      case 'ACTIVE_SECONDARY_CONTINUITY':
        return 'bg-sky-50 border-sky-400 text-sky-950';
      case 'SPONSOR_GRACE_ESCALATED':
        return 'bg-amber-50 border-amber-400 text-amber-950';
      default:
        return 'bg-red-600 border-red-700 text-white';
    }
  };

  return (
    <div className="space-y-4">
      {/* Action Inbox: Pending Sponsor Succession Alerts */}
      {pendingTransfers.length > 0 && (
        <section
          aria-label="Pending Commissioning Sponsor Transfers"
          className="bg-amber-50 border border-amber-400 rounded p-4 space-y-2.5"
        >
          <div className="flex items-center justify-between gap-2">
            <h2 className="text-xs font-bold uppercase tracking-wider text-amber-950 flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-amber-700" />
              Action Inbox: Pending Sponsor Succession ({pendingTransfers.length})
            </h2>
            <span className="text-[11px] font-mono text-amber-900">
              2-of-2 TRANSFER_COMMISSIONING_SPONSOR Required Before Grace Expiry
            </span>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-2.5">
            {pendingTransfers.map((tr) => {
              const fnObj = commissioningFunctions.find((f) => f.function_id === tr.function_id);
              const candidateSO = activeSOs[0]?.principal_id || '';
              const candidateAO = activeAOs[0]?.principal_id || '';
              return (
                <div key={tr.function_id} className="bg-white border border-amber-300 rounded p-3 text-xs space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono font-bold text-slate-900">{tr.function_id}</span>
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${stateBadgeClass(tr.continuity_status)}`}>
                      {tr.continuity_status}
                    </span>
                  </div>
                  <div className="text-slate-700">
                    Org: <span className="font-mono">{tr.owning_org_unit}</span> · Escalation:{' '}
                    <span className="font-mono">{tr.escalation_contact}</span> · Affected Agents: {tr.affected_agents_count}
                  </div>
                  {tr.earliest_grace_expiry_at && (
                    <div className="text-[11px] font-mono font-semibold text-amber-900">
                      Orphan Quarantine Countdown: {formatCountdown(tr.earliest_grace_expiry_at)}
                    </div>
                  )}
                  {fnObj && candidateSO && candidateAO && (
                    <div className="pt-1">
                      <button
                        type="button"
                        aria-label={`Execute 2-of-2 sponsor transfer for ${tr.function_id}`}
                        onClick={async () => {
                          setPanelErr(null);
                          setPanelMsg(null);
                          try {
                            await onTransferSponsors(fnObj, candidateSO, candidateAO);
                            setPanelMsg(`Completed 2-of-2 TRANSFER_COMMISSIONING_SPONSOR on ${tr.function_id}`);
                          } catch (err) {
                            setPanelErr(err instanceof Error ? err.message : 'Sponsor transfer failed');
                          }
                        }}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-white text-[11px] font-mono font-bold"
                      >
                        <UserCheck className="w-3.5 h-3.5 text-emerald-400" />
                        2-of-2 Re-Anchor to Active Sponsors ({candidateSO} + {candidateAO})
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      )}

      {panelMsg && (
        <div role="status" className="p-2.5 rounded border border-emerald-400 bg-emerald-50 text-emerald-950 text-xs font-mono">
          {panelMsg}
        </div>
      )}
      {panelErr && (
        <div role="alert" className="p-2.5 rounded border border-red-400 bg-red-50 text-red-950 text-xs font-mono">
          {panelErr}
        </div>
      )}

      {/* Commissioning Functions & Event-Driven IGA Simulator */}
      <section className="bg-white border border-slate-200 rounded p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-1.5">
              <Building2 className="w-4 h-4 text-slate-700" />
              Commissioning Functions &amp; Event-Driven IGA Sponsorship ({commissioningFunctions.length})
            </h2>
            <p className="text-xs text-slate-600">
              Agents bind to organizational functions with primary + backup SO/AO succession rather than brittle single-user IDs.
            </p>
          </div>
          {principals.length > 0 && (
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                const target = igaPrincipal || principals[0]?.principal_id || '';
                if (!target) return;
                setPanelErr(null);
                setPanelMsg(null);
                try {
                  await onEmitIGAEvent(igaType, target);
                  setPanelMsg(`Processed IGA ${igaType} event for ${target}`);
                } catch (err) {
                  setPanelErr(err instanceof Error ? err.message : 'IGA event failed');
                }
              }}
              className="flex flex-wrap items-center gap-2 text-xs"
            >
              <label htmlFor="iga-event-type" className="sr-only">
                IGA Lifecycle Event Type
              </label>
              <select
                id="iga-event-type"
                aria-label="IGA Lifecycle Event Type"
                value={igaType}
                onChange={(e) => setIgaType(e.target.value)}
                className="border border-slate-300 rounded px-2 py-1 font-mono text-xs bg-white"
              >
                <option value="ROLE_TRANSFER">IGA: ROLE_TRANSFER</option>
                <option value="ORG_REORG">IGA: ORG_REORG</option>
                <option value="LEAVE_OF_ABSENCE">IGA: LEAVE_OF_ABSENCE</option>
                <option value="TERMINATION">IGA: TERMINATION</option>
                <option value="KEY_COMPROMISE">IGA: KEY_COMPROMISE (0s Kill)</option>
              </select>
              <label htmlFor="iga-principal-select" className="sr-only">
                Affected Sponsor Principal
              </label>
              <select
                id="iga-principal-select"
                aria-label="Affected Sponsor Principal"
                value={igaPrincipal || principals[0]?.principal_id || ''}
                onChange={(e) => setIgaPrincipal(e.target.value)}
                className="border border-slate-300 rounded px-2 py-1 font-mono text-xs bg-white"
              >
                {principals.map((p) => (
                  <option key={p.principal_id} value={p.principal_id}>
                    {p.principal_id} ({p.role})
                  </option>
                ))}
              </select>
              <button
                type="submit"
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-800 bg-slate-900 hover:bg-slate-800 text-white font-mono font-bold text-xs"
              >
                <RefreshCw className="w-3 h-3" /> Emit IGA Signal
              </button>
            </form>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {commissioningFunctions.map((fn) => (
            <div key={fn.function_id} className="border border-slate-200 rounded p-3 bg-slate-50/70 text-xs space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <div>
                  <div className="font-mono font-bold text-slate-900">{fn.function_id}</div>
                  <div className="text-[11px] text-slate-600">{fn.display_name}</div>
                </div>
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${stateBadgeClass(fn.continuity_status)}`}>
                  {fn.continuity_status}
                </span>
              </div>
              <div className="text-[11px] font-mono text-slate-700">
                Org={fn.owning_org_unit} · CostCenter={fn.cost_center || 'N/A'} · Grace={fn.orphan_grace_hours}h · ActiveQuorum=
                {fn.active_so_count}SO/{fn.active_ao_count}AO
              </div>
              <div className="text-[11px] font-mono text-slate-600">
                SOs: {fn.primary_so_principal_id}
                {fn.secondary_so_principal_id ? ` / ${fn.secondary_so_principal_id}` : ''} · AOs: {fn.primary_ao_principal_id}
                {fn.secondary_ao_principal_id ? ` / ${fn.secondary_ao_principal_id}` : ''}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Agent Workload Identity Registry & 1-Click Kill-Switch */}
      <section className="bg-white border border-slate-200 rounded p-4 space-y-3">
        <div>
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-1.5">
            <Bot className="w-4 h-4 text-slate-700" />
            Agent Workload Identity Registry &amp; 3-Way Builder != Commissioner Provenance ({agents.length})
          </h2>
          <p className="text-xs text-slate-600">
            Holder-of-Key Ed25519 workload identities bounded by OPA permission intersection, recertification leases (&lt;=90d), and 0-second kill-switch revocation.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="bg-slate-100 border-y border-slate-300 text-[11px] uppercase text-slate-700">
                <th className="p-2">Agent ID / Kind</th>
                <th className="p-2">Commissioning Function</th>
                <th className="p-2">Builder Provenance (3-Way SoD)</th>
                <th className="p-2">Capability Ceiling &amp; Egress</th>
                <th className="p-2">Sponsorship &amp; Lease / Grace</th>
                <th className="p-2">Kill-Switch</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {agents.map((ag) => {
                const isDead =
                  ag.revoked ||
                  ag.sponsorship_state === 'ORPHAN_QUARANTINED' ||
                  ag.sponsorship_state === 'LEASE_EXPIRED_QUARANTINED' ||
                  ag.sponsorship_state === 'REVOKED_COMPROMISE' ||
                  ag.sponsorship_state === 'REVOKED_KILL_SWITCH';
                return (
                  <tr key={ag.agent_id} className={isDead ? 'bg-red-50/60' : 'hover:bg-slate-50'}>
                    <td className="p-2">
                      <div className="font-bold text-slate-900">{ag.agent_id}</div>
                      <div className="text-[10px] text-slate-500">
                        {ag.agent_kind} · fp:{shortHash(ag.key_fingerprint, 12)}
                      </div>
                    </td>
                    <td className="p-2">
                      <div className="font-semibold text-slate-800">{ag.commissioning_function_id}</div>
                      <div className="text-[10px] text-slate-500">
                        MaxTTL={ag.max_ttl_seconds}s · Depth&lt;={ag.max_delegation_depth}
                      </div>
                    </td>
                    <td className="p-2 text-[11px]">
                      <div className="font-semibold text-slate-800">{ag.builder_principal_id}</div>
                      <div className="text-[10px] text-emerald-800">
                        {shortHash(ag.artifact_digest, 20)} (Builder != SO/AO)
                      </div>
                    </td>
                    <td className="p-2 text-[11px]">
                      <div className="truncate max-w-[220px]" title={ag.allowed_actions.join(', ')}>
                        {ag.allowed_actions.join(', ')}
                      </div>
                      <div className="text-[10px] text-slate-600">{ag.allowed_egress_profile}</div>
                    </td>
                    <td className="p-2">
                      <span className={`inline-block text-[10px] font-bold px-2 py-0.5 rounded border ${stateBadgeClass(ag.sponsorship_state)}`}>
                        {ag.sponsorship_state}
                      </span>
                      <div className="text-[10px] text-slate-600 mt-0.5">
                        {ag.grace_active && ag.grace_expires_at
                          ? `Grace: ${formatCountdown(ag.grace_expires_at)}`
                          : `Lease: ${formatCountdown(ag.recertify_expires_at)}`}
                      </div>
                    </td>
                    <td className="p-2">
                      {!ag.revoked ? (
                        <button
                          type="button"
                          aria-label={`Kill-switch revoke agent ${ag.agent_id}`}
                          onClick={async () => {
                            setPanelErr(null);
                            setPanelMsg(null);
                            try {
                              await onRevokeAgent(ag.agent_id, 'CONSOLE_1OF2_AGENT_KILL_SWITCH');
                              setPanelMsg(`Executed 0s kill-switch revocation on ${ag.agent_id}`);
                            } catch (err) {
                              setPanelErr(err instanceof Error ? err.message : 'Agent revocation failed');
                            }
                          }}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded border border-red-400 bg-red-600 hover:bg-red-700 text-white text-[11px] font-bold"
                        >
                          <ShieldOff className="w-3 h-3" /> Kill-Switch
                        </button>
                      ) : (
                        <span className="text-[10px] font-bold text-red-800">{ag.revoke_reason || 'REVOKED'}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
