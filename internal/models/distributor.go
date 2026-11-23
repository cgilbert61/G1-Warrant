package models

import "time"

// WN-8 Distributor Evidence Granularity, Per-Asset States & Closure Completeness (v1.2.0)
const (
	EvidenceGranularityPerAsset      = "PER_ASSET_VERIFIED"
	EvidenceGranularityWaveAggregate = "WAVE_AGGREGATE_ONLY"
	EvidenceGranularityDispatchAck   = "DISPATCH_ACK_ONLY"

	AssetDeployLanded        = "LANDED"
	AssetDeployFailed        = "FAILED"
	AssetDeployPending       = "PENDING"
	AssetDeployRebootWaiting = "REBOOT_WAITING"
	AssetDeployUnreachable   = "UNREACHABLE"
	AssetDeployRolledBack    = "ROLLED_BACK"

	ClosureCompletenessFull         = "FULL"
	ClosureCompletenessPartial      = "PARTIAL"
	ClosureCompletenessDispatchOnly = "DISPATCH_ONLY"
)

// Canonical Distributor IDs across all 6 enterprise patch deployment families.
const (
	DistributorK8sCiliumNative    = "k8s-cilium-native"
	DistributorArgoCD             = "argocd"
	DistributorFlux               = "flux"
	DistributorMSIntune           = "ms-intune"
	DistributorMSMECM             = "ms-mecm"
	DistributorMSWSUS             = "ms-wsus"
	DistributorAnsibleAWX         = "ansible-awx"
	DistributorRedHatSatellite    = "redhat-satellite"
	DistributorJamfPro            = "jamf-pro"
	DistributorAWSSSM             = "aws-ssm"
	DistributorAzureUpdateManager = "azure-update-manager"
	DistributorGCPOSConfig        = "gcp-os-config"
	DistributorTaniumPatch        = "tanium-patch"
	DistributorIvantiNeurons      = "ivanti-neurons"
	DistributorAutomox            = "automox"
)

// FixIdentity identifies the exact remediation artifact in the distributor's native domain.
type FixIdentity struct {
	CVEID          string `json:"cve_id"`
	KBArticleID    string `json:"kb_article_id,omitempty"`
	PackageNEVRA   string `json:"package_nevra,omitempty"`
	AdvisoryID     string `json:"advisory_id,omitempty"`
	TargetDigest   string `json:"target_digest,omitempty"`
	PatchBundleURI string `json:"patch_bundle_uri,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
}

// AssetTarget identifies one bounded asset authorized inside a DeploymentOrder.
type AssetTarget struct {
	AssetKey       string `json:"asset_key"`
	ServiceID      string `json:"service_id"`
	Hostname       string `json:"hostname,omitempty"`
	IPv4           string `json:"ipv4,omitempty"`
	NativeDeviceID string `json:"native_device_id,omitempty"`
	PlatformFamily string `json:"platform_family,omitempty"`
}

// RolloutWave defines one progressive deployment ring/batch (e.g., 5% -> 25% -> 100%).
type RolloutWave struct {
	WaveNumber        int      `json:"wave_number"`
	Percentage        int      `json:"percentage"`
	TargetAssetKeys   []string `json:"target_asset_keys,omitempty"`
	StageDwellSeconds int      `json:"stage_dwell_seconds"`
}

// RolloutPlan specifies progressive ring/wave constraints for a DeploymentOrder.
type RolloutPlan struct {
	Waves                []RolloutWave `json:"waves"`
	MaxFailureRatePct    float64       `json:"max_failure_rate_pct"`
	StageDwellSeconds    int           `json:"stage_dwell_seconds"`
	MaintenanceWindowUTC string        `json:"maintenance_window_utc,omitempty"`
}

// NativeRollbackSpec is persisted immutably in PostgreSQL BEFORE Wave 1 executes so any
// wave regression, failure threshold breach, or stall reverses cleanly via the same distributor.
type NativeRollbackSpec struct {
	Strategy             string `json:"strategy"`
	UninstallKB          string `json:"uninstall_kb,omitempty"`
	PreviousPackageNEVRA string `json:"previous_package_nevra,omitempty"`
	PreviousDigest       string `json:"previous_digest,omitempty"`
	RollbackPlaybookID   string `json:"rollback_playbook_id,omitempty"`
	GitRevertCommit      string `json:"git_revert_commit,omitempty"`
	RawNativePayloadJCS  string `json:"raw_native_payload_jcs,omitempty"`
}

// DeploymentOrder is the single canonical outbound contract emitted by G1-Warrant to any DistributorTranslator.
type DeploymentOrder struct {
	OrderID             string             `json:"order_id"`
	WarrantID           string             `json:"warrant_id"`
	TaskTokenID         string             `json:"task_token_id"`
	RemediationID       string             `json:"remediation_id"`
	ServiceID           string             `json:"service_id"`
	DistributorID       string             `json:"distributor_id"`
	PlatformFamily      string             `json:"platform_family"`
	FixIdentity         FixIdentity        `json:"fix_identity"`
	TargetAssets        []AssetTarget      `json:"target_assets"`
	RolloutPlan         RolloutPlan        `json:"rollout_plan"`
	RollbackInstruction NativeRollbackSpec `json:"rollback_instruction"`
	NativeJobRef        string             `json:"native_job_ref,omitempty"`
	WaveNumber          int                `json:"wave_number"`
	TotalWaves          int                `json:"total_waves"`
	CreatedAt           time.Time          `json:"created_at"`
}

// DeploymentDispatchReceipt acknowledges distributor acceptance of a DeploymentOrder wave.
type DeploymentDispatchReceipt struct {
	OrderID              string    `json:"order_id"`
	DistributorID        string    `json:"distributor_id"`
	NativeJobRef         string    `json:"native_job_ref"`
	SupportsNativeRings  bool      `json:"supports_native_rings"`
	ReportsPerAssetState bool      `json:"reports_per_asset_state"`
	DispatchedAt         time.Time `json:"dispatched_at"`
}

// AssetDeploymentStatus reports honest per-asset execution telemetry returned by the distributor's own API.
type AssetDeploymentStatus struct {
	AssetKey        string    `json:"asset_key"`
	NativeDeviceID  string    `json:"native_device_id,omitempty"`
	State           string    `json:"state"` // "LANDED" | "FAILED" | "PENDING" | "REBOOT_WAITING" | "UNREACHABLE" | "ROLLED_BACK"
	NativeExitCode  int       `json:"native_exit_code"`
	NativeErrorCode string    `json:"native_error_code,omitempty"`
	ReportedAt      time.Time `json:"reported_at"`
}

// DeploymentResult is the single canonical inbound mirror contract normalized from any DistributorTranslator.
type DeploymentResult struct {
	ResultID                   string                  `json:"result_id"`
	OrderID                    string                  `json:"order_id"`
	RemediationID              string                  `json:"remediation_id,omitempty"`
	DistributorID              string                  `json:"distributor_id"`
	NativeJobRef               string                  `json:"native_job_ref,omitempty"`
	WaveNumber                 int                     `json:"wave_number"`
	ObservedAt                 time.Time               `json:"observed_at"`
	EvidenceGranularity        string                  `json:"evidence_granularity"` // "PER_ASSET_VERIFIED" | "WAVE_AGGREGATE_ONLY" | "DISPATCH_ACK_ONLY"
	AssetResults               []AssetDeploymentStatus `json:"asset_results"`
	TargetedCount              int                     `json:"targeted_count"`
	LandedCount                int                     `json:"landed_count"`
	FailedCount                int                     `json:"failed_count"`
	PendingCount               int                     `json:"pending_count"`
	RebootWaitingCount         int                     `json:"reboot_waiting_count"`
	UnreachableCount           int                     `json:"unreachable_count"`
	RolledBackCount            int                     `json:"rolled_back_count"`
	Stalled                    bool                    `json:"stalled,omitempty"`
	IsRollback                 bool                    `json:"is_rollback,omitempty"`
	RollbackReason             string                  `json:"rollback_reason,omitempty"`
	RawDistributorReportSHA256 string                  `json:"raw_distributor_report_sha256"`
}

// RecomputeCounts deterministically tallies AssetResults into DeploymentResult summary counts.
func (r *DeploymentResult) RecomputeCounts() {
	if len(r.AssetResults) == 0 {
		return
	}
	r.LandedCount = 0
	r.FailedCount = 0
	r.PendingCount = 0
	r.RebootWaitingCount = 0
	r.UnreachableCount = 0
	r.RolledBackCount = 0
	for _, ar := range r.AssetResults {
		switch ar.State {
		case AssetDeployLanded:
			r.LandedCount++
		case AssetDeployFailed:
			r.FailedCount++
		case AssetDeployPending:
			r.PendingCount++
		case AssetDeployRebootWaiting:
			r.RebootWaitingCount++
		case AssetDeployUnreachable:
			r.UnreachableCount++
		case AssetDeployRolledBack:
			r.RolledBackCount++
		}
	}
	if r.TargetedCount < len(r.AssetResults) {
		r.TargetedCount = len(r.AssetResults)
	}
}

// DistributorCapabilities declares what progressive-ring, per-asset telemetry, and reboot-tracking primitives a distributor supports.
type DistributorCapabilities struct {
	SupportsNativeRings     bool     `json:"supports_native_rings"`
	ReportsPerAssetState    bool     `json:"reports_per_asset_state"`
	SupportsRebootTracking  bool     `json:"supports_reboot_tracking"`
	PlatformFamilies        []string `json:"platform_families"`
	DefaultRollbackStrategy string   `json:"default_rollback_strategy"`
}

// DistributorDescriptor describes a registered DistributorTranslator for Console/CLI/SDK discovery.
type DistributorDescriptor struct {
	DistributorID      string                  `json:"distributor_id"`
	DisplayName        string                  `json:"display_name"`
	Family             string                  `json:"family"`
	Capabilities       DistributorCapabilities `json:"capabilities"`
	EndpointConfigured bool                    `json:"endpoint_configured"`
}
