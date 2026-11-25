export interface WebAuthnMetadata {
  authenticatorData: string;
  clientDataJSON: string;
  credentialId: string;
  rpId: string;
}

export interface DSSESignature {
  slot?: number;
  keyid: string;
  alg: string;
  role?: string;
  principal_id?: string;
  principal_email?: string;
  key_fingerprint?: string;
  sig: string;
  signed_at?: string;
  webauthn?: WebAuthnMetadata;
}

export interface DSSEEnvelope {
  payloadType: string;
  payload: string;
  signatures: DSSESignature[];
}

export interface FreezeState {
  mode: 'OPERATIONAL' | 'FREEZE_HOLD' | 'FREEZE_ROLLBACK';
  actor: string;
  reason_code: string;
  freeze_epoch: number;
  updated_at: string;
  thaw_dsse?: DSSEEnvelope;
}

export interface BootstrapState {
  sealed: boolean;
  sealed_by?: string;
  sealed_reason?: string;
  sealed_at?: string;
  genesis_principal_max_seq?: number;
  genesis_revocation_max_seq?: number;
  genesis_manifest_sha256?: string;
}

export interface GlobalScoreboard {
  freeze_state: FreezeState;
  witness_mode?: 'EXTERNAL_NOTARY' | 'IN_PROCESS_LOCAL';
  active_warrants_count: number;
  active_agents_count?: number;
  quarantined_agents_count?: number;
  pending_sponsor_transfers_count?: number;
  fleet_median_ttvr_seconds: number;
  active_bridges_armed: number;
  median_bridge_age_seconds: number;
  autonomous_eligibility_pct: number;
  eligible_services_count: number;
  total_services_count: number;
  awaiting_dual_key_inbox_count: number;
  active_drift_violations_count: number;
  rollback_failures_count: number;
  unmapped_vendor_findings_count?: number;
  partial_closures_count?: number;
}

export interface Principal {
  principal_id: string;
  email: string;
  display_name: string;
  role: string;
  key_id: string;
  alg: string;
  public_key_b64: string;
  key_fingerprint: string;
  authenticator_mode: string;
  credential_id?: string;
  revoked: boolean;
  revoke_reason?: string;
  created_at: string;
}

export interface TestSmartcardPersona {
  principal_id: string;
  email: string;
  display_name: string;
  role: string;
  key_id: string;
  alg: string;
  public_key_b64: string;
  key_fingerprint: string;
  badge_label: string;
}

export interface DeclaredCloneSource {
  source_system: string;
  image_identity: string;
  platform_family?: string;
  selected_server_id?: string;
  selected_server_hostname?: string;
  snapshot_sha256?: string;
  query_identity?: string;
  source_mode: 'ESTATE_LOADER' | 'MANUAL';
  image_created_at?: string;
  image_age_seconds_at_sign?: number;
  declared_at: string;
}

export interface WarrantRecord {
  warrant_id: string;
  warrant_class: string;
  scope_services: string[];
  scope_assets?: string[];
  authorized_vendor_detections?: string[];
  clone_sources?: DeclaredCloneSource[];
  estate_snapshot_sha256?: string;
  estate_drift_policy?: 'RECORD_ONLY' | 'FAIL_CLOSED';
  estate_drift_tolerance_pct?: number;
  max_cvss: number;
  kev_eligible: boolean;
  max_blast_radius_replicas: number;
  allow_stateful_patches: boolean;
  allow_secret_rotation?: boolean;
  auto_remediate_cwes?: string[];
  sla_bridge_minutes: number;
  max_p99_latency_ms: number;
  issued_at: string;
  expires_at: string;
  dsse_envelope: DSSEEnvelope;
  slot1_principal_id: string;
  slot1_email: string;
  slot1_key_fp: string;
  slot1_role: string;
  slot2_principal_id: string;
  slot2_email: string;
  slot2_key_fp: string;
  slot2_role: string;
  live_status: 'ACTIVE' | 'EXPIRED' | 'REVOKED_SIGNER';
  revocation_reason?: string;
  prev_hash: string;
  entry_hash: string;
  created_at: string;
}

export interface ApprovalPressureStat {
  warrant_class: string;
  active_warrants: number;
  pending_exceptions: number;
  overrides_last_24h: number;
  pressure_score: number;
  pressure_status: 'NOMINAL' | 'ELEVATED' | 'PRESSURE_HIGH';
}

export interface EligibilityCheckItem {
  criterion_code: string;
  passed: boolean;
  observed_value: string;
  required_threshold: string;
  action_code: string;
}

export interface EstateService {
  service_id: string;
  display_name: string;
  namespace: string;
  tier: string;
  warrant_class: string;
  current_digest: string;
  current_purl: string;
  replicas: number;
  test_coverage_pct: number;
  otel_health_probes: boolean;
  readonly_shadow_replica: boolean;
  rollback_automation_verified: boolean;
  readonly_root_filesystem?: boolean;
  noexec_tmp_mounts?: boolean;
  allowed_egress_services?: string[];
  baseline_syscalls: string[];
  eligible: boolean;
  autonomy_tier?: string;
  shadow_db_mode?: string;
  eligibility_checklist: EligibilityCheckItem[];
  updated_at: string;
}

export interface SchemaFieldDiff {
  json_path: string;
  baseline_type: string;
  canary_type: string;
  change_kind: string;
  breaking: boolean;
}

export interface ShadowComparisonReport {
  run_id: string;
  remediation_id: string;
  service_id: string;
  stage_weight: number;
  shadow_isolation_verified: boolean;
  readonly_db_bound: boolean;
  outbound_mutation_sink_active: boolean;
  normalized_baseline_sample: string;
  normalized_canary_sample: string;
  volatile_fields_masked: string[];
  schema_breaking_diffs: number;
  schema_field_diffs: SchemaFieldDiff[] | null;
  status_code_drift_pct: number;
  baseline_latency: { p50_ms: number; p95_ms: number; p99_ms: number };
  canary_latency: { p50_ms: number; p95_ms: number; p99_ms: number };
  max_p99_latency_ms: number;
  baseline_syscalls: string[];
  canary_syscalls: string[];
  unauthorized_syscalls: string[];
  passed: boolean;
  failure_code?: string;
  evaluated_at: string;
}

export interface ExtractedPatchMetadata {
  schema_version: string;
  patched_digest: string;
  files_changed: number;
  ddl_migrations: number;
  detected_ddl_keywords: string[];
  orm_model_mutations: number;
  detected_orm_tokens: string[];
  serialization_breaks: number;
  api_backward_compatible: boolean;
  declared_syscall_delta: string[];
  stateless_eligible: boolean;
  raw_input_sha256: string;
  typed_output_sha256: string;
  extractor_digest: string;
}

export interface RemediationItem {
  remediation_id: string;
  cve_id: string;
  cwe_id: string;
  is_kev: boolean;
  cvss_score: number;
  service_id: string;
  warrant_id: string;
  remediation_kind?: string;
  secret_resource_name?: string;
  chained_exploit_enabler?: boolean;
  vulnerable_digest: string;
  patched_digest: string;
  package_purl: string;
  vulnerable_symbol: string;
  exploit_vector: string;
  stage: 'INTAKE_REPRO' | 'BRIDGED_CONTAINED' | 'SHADOW_CANARY' | 'VERIFYING_LOCKING' | 'ATTESTED_CLOSED';
  status_health:
    | 'NORMAL'
    | 'BRIDGED'
    | 'INGESTED_UNBOUND'
    | 'EXCEPTION_ROUTED'
    | 'ROLLBACK_FAILED'
    | 'QUARANTINED_ROLLBACK'
    | 'DRIFT_VIOLATION'
    | 'FROZEN'
    | 'ATTESTED';
  blocker_code?: string;
  canary_weight: number;
  stateless_passed: boolean | null;
  schema_diff_passed: boolean | null;
  syscall_diff_passed: boolean | null;
  twin_replay_status: string;
  assurance_tier?: string;
  pod_sweep_matched: number;
  pod_sweep_total: number;
  lockout_policy_id?: string;
  bridge_id?: string;
  bridge_sla_minutes: number;
  attestation_id?: string;
  finder_vendor?: string;
  vendor_detection_id?: string;
  cve_mapping_status?: 'MAPPED' | 'UNMAPPED_VENDOR_ADVISORY' | 'ABSENT' | string;
  class_binding_status?: 'BOUND' | 'UNBOUND' | string;
  patch_target_layer?: 'USERSPACE_SOFTWARE' | 'KERNEL' | 'BOOT_LAYER' | string;
  clone_twin_proving?: {
    proving_run_id: string;
    proving_namespace: string;
    twin_runtime: string;
    patch_target_layer: string;
    clone_count: number;
    services_up_count: number;
    smoke_passed_count: number;
    acceptance_passed_count: number;
    all_passed: boolean;
    failure_reason_code?: string;
    transcript_sha256: string;
  };
  normalized_detection_state?: string;
  asset_identity?: AssetIdentity;
  distributor_id?: string;
  latest_order_id?: string;
  targeted_asset_count?: number;
  landed_asset_count?: number;
  reboot_waiting_count?: number;
  failed_asset_count?: number;
  pending_asset_count?: number;
  rolled_back_asset_count?: number;
  closure_completeness?: 'FULL' | 'PARTIAL' | 'DISPATCH_ONLY' | string;
  patch_metadata?: ExtractedPatchMetadata;
  shadow_report?: ShadowComparisonReport;
  created_at: string;
  bridged_at?: string;
  closed_at?: string;
  updated_at: string;
}

export interface TraceEvent {
  trace_id: string;
  remediation_id: string;
  engine: string;
  step_code: string;
  outcome: string;
  actor_or_token: string;
  evidence_hash: string;
  fields: Record<string, string>;
  occurred_at: string;
}

export interface CeilingException {
  exception_id: string;
  remediation_id: string;
  service_id: string;
  cve_id: string;
  warrant_class: string;
  trigger_code: string;
  ddl_count: number;
  orm_mutations: number;
  serialization_breaks: number;
  api_backward_compatible: boolean;
  shadow_replay_status: string;
  syscall_diff_summary: string;
  active_bridge_id: string;
  status: 'PENDING_DUAL_KEY' | 'APPROVED' | 'REJECTED';
  resolution_dsse?: DSSEEnvelope;
  created_at: string;
  resolved_at?: string;
}

export interface ContainmentBridge {
  bridge_id: string;
  remediation_id: string;
  service_id: string;
  cve_id: string;
  bridge_type: string;
  substrate_family?: string;
  containment_mode?: string;
  rulepack_id?: string;
  metadata_plane_blocked?: boolean;
  allowed_egress_peers?: string[];
  status: 'ARMED' | 'RETIRED' | 'REARMED_DRIFT';
  sla_minutes: number;
  blocker_reason_code: string;
  cilium_manifest_yaml: string;
  k8s_netpol_yaml: string;
  envoy_filter_json: string;
  native_shield_manifest?: string;
  native_retire_spec?: string;
  armed_at: string;
  retired_at?: string;
  rearmed_count: number;
}

export interface AdmissionLockout {
  lockout_id: string;
  remediation_id: string;
  service_id: string;
  cve_id: string;
  banned_digest: string;
  patched_digest: string;
  policy_name: string;
  vap_manifest_yaml: string;
  gatekeeper_rego: string;
  enforced_at: string;
  drift_count: number;
  last_drift_at?: string;
}

export interface DriftIncident {
  incident_id: string;
  lockout_id: string;
  remediation_id: string;
  service_id: string;
  cve_id: string;
  drift_kind?: string;
  violating_artifact?: string;
  pod_cordoned?: boolean;
  pod_recycled?: boolean;
  detected_digest: string;
  rogue_pod_name: string;
  rearmed_bridge_id: string;
  detection_latency_ms: number;
  detected_at: string;
  resolved_at?: string;
}

export interface PodDigestEntry {
  pod_name: string;
  node_name: string;
  running_digest: string;
  loaded_libs: string[];
}

export interface AttestationRecord {
  attestation_id: string;
  remediation_id: string;
  service_id: string;
  cve_id: string;
  is_kev: boolean;
  warrant_id: string;
  slot1_principal_id: string;
  slot1_email: string;
  slot2_principal_id: string;
  slot2_email: string;
  twin_transcript_sha256: string;
  assurance_tier?: string;
  signer_backend?: string;
  distributor_id?: string;
  deployment_order_id?: string;
  closure_completeness?: 'FULL' | 'PARTIAL' | 'DISPATCH_ONLY' | string;
  targeted_asset_count?: number;
  landed_asset_count?: number;
  reboot_waiting_count?: number;
  failed_asset_count?: number;
  fleet_digest_manifest: PodDigestEntry[];
  lockout_policy_id: string;
  reverify_expires_at: string;
  dsse_envelope: DSSEEnvelope;
  oscal_poam_json: Record<string, unknown>;
  ttvr_seconds: number;
  prev_hash: string;
  entry_hash: string;
  minted_at: string;
}

export interface ActorClaim {
  agent_id: string;
  key_id: string;
  key_fingerprint: string;
  commissioning_function_id: string;
  sponsorship_state: string;
  act?: ActorClaim;
}

export interface CommissioningFunction {
  function_id: string;
  display_name: string;
  owning_org_unit: string;
  cost_center: string;
  primary_so_principal_id: string;
  secondary_so_principal_id?: string;
  primary_ao_principal_id: string;
  secondary_ao_principal_id?: string;
  escalation_contact: string;
  orphan_grace_hours: number;
  active_so_count: number;
  active_ao_count: number;
  continuity_status: string;
  pending_sponsor_succession: boolean;
  departed_sponsors?: string[];
  prev_hash?: string;
  entry_hash?: string;
  created_at: string;
}

export interface AgentIdentity {
  agent_id: string;
  display_name: string;
  agent_kind: 'INTERNAL_WORKER' | 'EXTERNAL_AUTONOMOUS_AGENT';
  commissioning_function_id: string;
  key_id: string;
  alg: string;
  public_key_b64: string;
  key_fingerprint: string;
  spiffe_id?: string;
  artifact_digest: string;
  builder_principal_id: string;
  builder_key_fingerprint: string;
  allowed_actions: string[];
  allowed_services: string[];
  allowed_egress_profile: string;
  max_ttl_seconds: number;
  max_delegation_depth: number;
  allow_autonomous_intake: boolean;
  recertify_expires_at: string;
  commissioner_so_principal_id: string;
  commissioner_ao_principal_id: string;
  sponsorship_state: string;
  sponsor_compromised: boolean;
  grace_active: boolean;
  grace_expires_at?: string;
  revoked: boolean;
  revoke_reason?: string;
  prev_hash?: string;
  entry_hash?: string;
  enrolled_at: string;
}

export interface PendingSponsorTransfer {
  function_id: string;
  display_name: string;
  owning_org_unit: string;
  escalation_contact: string;
  continuity_status: string;
  departed_principals?: string[];
  affected_agents_count: number;
  earliest_grace_expiry_at?: string;
}

export interface AgentLedgerEntry {
  action_id: string;
  task_token_id: string;
  warrant_id: string;
  remediation_id: string;
  authority_mode?: string;
  commissioning_function_id?: string;
  agent_id?: string;
  delegation_depth?: number;
  act_chain?: ActorClaim;
  worker_name: string;
  target_asset: string;
  action_type: string;
  slot1_principal_id: string;
  slot2_principal_id: string;
  egress_profile: string;
  raw_input_sha256: string;
  extractor_digest: string;
  typed_output_sha256: string;
  token_ttl_sec: number;
  status: string;
  violation_code?: string;
  prev_hash: string;
  entry_hash: string;
  executed_at: string;
}

export interface ChainStatusItem {
  table_name: string;
  row_count: number;
  valid: boolean;
  terminal_hash: string;
  broken_at_row_index: number;
  failure_detail?: string;
}

export interface LedgerVerificationReport {
  all_valid: boolean;
  witness_mode?: 'EXTERNAL_NOTARY' | 'IN_PROCESS_LOCAL';
  external_anchor_verified?: boolean;
  latest_checkpoint_id?: string;
  latest_combined_merkle_root?: string;
  superuser_tamper_detail?: string;
  verified_at: string;
  tables: ChainStatusItem[];
  agent_authority_tables?: ChainStatusItem[];
}

export interface FeedRuntimeConfig {
  mode: 'offline' | 'live';
  cisa_kev_url: string;
  kev_poll_interval: string;
  osv_api_url: string;
  trivy_enabled: boolean;
  updated_at: string;
}

export interface ExtractedOSVEntry {
  osv_id: string;
  cve_id: string;
  cwe_id: string;
  service_id: string;
  package_purl: string;
  cvss_score: number;
  fixed_version: string;
  is_kev: boolean;
}

export interface FeedSyncRun {
  sync_id: string;
  feed_source: 'CISA_KEV' | 'GOOGLE_OSV' | 'TRIVY_SARIF';
  status: string;
  catalog_version?: string;
  items_ingested: number;
  kev_matches: number;
  raw_input_sha256: string;
  typed_output_sha256: string;
  extractor_digest: string;
  error_message?: string;
  synced_at: string;
}

export interface LiveFeedStatus {
  config: FeedRuntimeConfig;
  cisa_kev_catalog_count: number;
  latest_catalog_version?: string;
  last_kev_sync_at?: string;
  osv_advisories: ExtractedOSVEntry[];
  recent_sync_runs: FeedSyncRun[];
}

export interface BootstrapSnapshot {
  scoreboard: GlobalScoreboard;
  witness_mode?: 'EXTERNAL_NOTARY' | 'IN_PROCESS_LOCAL';
  bootstrap_state?: BootstrapState;
  principals: Principal[];
  test_personas: TestSmartcardPersona[];
  warrants: WarrantRecord[];
  pressure: ApprovalPressureStat[];
  estate: EstateService[];
  remediations: RemediationItem[];
  exceptions: CeilingException[];
  bridges: ContainmentBridge[];
  lockouts: AdmissionLockout[];
  drifts: DriftIncident[];
  shadow_runs: ShadowComparisonReport[];
  attestations: AttestationRecord[];
  agent_actions: AgentLedgerEntry[];
  commissioning_functions?: CommissioningFunction[];
  agents?: AgentIdentity[];
  pending_sponsor_transfers?: PendingSponsorTransfer[];
  distributors?: DistributorDescriptor[];
  estate_sources?: EstateSourceDescriptor[];
  vendor_connectors?: VendorConnectorConfigStatus[];
  deployment_orders?: DeploymentOrder[];
  deployment_results?: DeploymentResult[];
  asset_aliases?: AssetIdentityAlias[];
  feed_status?: LiveFeedStatus;
  kernel_public_key: {
    key_id: string;
    alg: string;
    public_key_b64: string;
    key_fingerprint: string;
  };
  webauthn: {
    rp_id: string;
    origins: string[];
  };
}

export interface AssetIdentity {
  asset_key: string;
  hostname?: string;
  fqdn?: string;
  ipv4?: string;
  cloud_instance_id?: string;
  vendor_asset_id?: string;
  platform_family?: string;
}

export interface AssetIdentityAlias {
  alias_key: string;
  service_id: string;
  canonical_asset_key: string;
  platform_family: string;
  hostname?: string;
  ipv4?: string;
  updated_at: string;
}

export interface DistributorCapabilities {
  supports_native_rings: boolean;
  reports_per_asset_state: boolean;
  supports_reboot_tracking: boolean;
  platform_families: string[];
  default_rollback_strategy: string;
}

export interface DistributorDescriptor {
  distributor_id: string;
  display_name: string;
  family: string;
  capabilities: DistributorCapabilities;
  endpoint_configured: boolean;
}

export interface NativeRollbackSpec {
  strategy: string;
  uninstall_kb?: string;
  previous_package_nevra?: string;
  previous_digest?: string;
  rollback_playbook_id?: string;
  git_revert_commit?: string;
}

export interface DeploymentOrder {
  order_id: string;
  remediation_id: string;
  warrant_id: string;
  service_id: string;
  distributor_id: string;
  platform_family: string;
  fix_identity: {
    cve_id: string;
    kb_article_id?: string;
    package_nevra?: string;
    target_digest?: string;
  };
  target_assets: Array<{ asset_key: string; service_id: string; hostname?: string; ipv4?: string }>;
  rollback_instruction: NativeRollbackSpec;
  native_job_ref?: string;
  wave_number: number;
  total_waves: number;
  created_at: string;
}

export interface DeploymentResult {
  result_id: string;
  order_id: string;
  remediation_id?: string;
  distributor_id: string;
  native_job_ref?: string;
  evidence_granularity: string;
  targeted_count: number;
  landed_count: number;
  reboot_waiting_count: number;
  failed_count: number;
  pending_count: number;
  rolled_back_count: number;
  is_rollback?: boolean;
  rollback_reason?: string;
  observed_at: string;
}

export interface EstateSourceDescriptor {
  source_system: string;
  display_name: string;
  source_tier: 'TIER_A_MACHINE' | 'TIER_B_WORKLOAD' | 'TIER_C_CENSUS';
  handler_family: string;
  read_env_prefix: string;
  read_configured: boolean;
  can_propose_clone_sources: boolean;
}

export interface EstateSelectableServer {
  server_id: string;
  hostname: string;
  service_id?: string;
  source_system: string;
  os_family: string;
  os_version_or_build: string;
  kernel_release?: string;
  primary_package?: string;
  twin_image_identity: string;
  platform_family: string;
  patch_target_layers?: string[];
  image_created_at?: string;
  image_age_seconds?: number;
}

export interface VendorConnectorConfigStatus {
  source_system: string;
  display_name: string;
  source_tier: 'TIER_A_MACHINE' | 'TIER_B_WORKLOAD' | 'TIER_C_CENSUS';
  handler_family: string;
  can_propose_clone_sources: boolean;
  supports_wn8_dispatch: boolean;
  connection_mode: 'LIVE_CUSTOM' | 'DEMO_MOCK' | 'LOCAL_CLUSTER' | 'UNCONFIGURED';
  read_env_prefix: string;
  read_url: string;
  read_token_configured: boolean;
  read_token_masked?: string;
  read_configured: boolean;
  dispatch_env_prefix?: string;
  dispatch_url?: string;
  dispatch_token_configured: boolean;
  dispatch_token_masked?: string;
  dispatch_configured: boolean;
  demo_mock_available: boolean;
}

export interface VendorConnectorTestResult {
  source_system: string;
  reachable: boolean;
  connection_mode: string;
  class_membership_count: number;
  candidate_source_count: number;
  selectable_servers?: EstateSelectableServer[];
  freshness_age_seconds: number;
  snapshot_sha256?: string;
  tested_at: string;
}

export interface EstateProposalResponse {
  proposal_id: string;
  primary_snapshot: {
    snapshot_id: string;
    source_system: string;
    source_tier: string;
    handler_family: string;
    query_identity: string;
    class_membership_count: number;
    os_build_kernel_distribution: Array<{
      os_family: string;
      os_version_or_build: string;
      kernel_release?: string;
      cpe23?: string;
      count: number;
    }>;
    software_version_distribution: Array<{
      component_name: string;
      version: string;
      cpe23?: string;
      swid_tag_id?: string;
      purl?: string;
      count: number;
    }>;
    candidate_clone_sources: Array<{
      source_system: string;
      image_identity: string;
      platform_family: string;
      created_at: string;
      image_age_seconds: number;
    }>;
    ephemeral_servers?: EstateSelectableServer[];
    source_inventory_freshness_at: string;
    source_freshness_age_seconds: number;
    observed_at: string;
    snapshot_sha256: string;
  };
  primary_evidence_id: string;
  census_snapshot?: {
    source_system: string;
    class_membership_count: number;
    source_freshness_age_seconds: number;
    snapshot_sha256: string;
  };
  census_count_delta?: number;
  census_delta_pct?: number;
  census_advisory?: string;
  proposed_clone_sources: DeclaredCloneSource[];
  selectable_servers?: EstateSelectableServer[];
  proposed_estate_snapshot_sha256: string;
  recommended_drift_policy: 'RECORD_ONLY' | 'FAIL_CLOSED';
  recommended_drift_tolerance_pct: number;
}
