package adapters

import (
	"context"

	"github.com/g1163rt-labs/g1-warrant/internal/fleetsim"
	"github.com/g1163rt-labs/g1-warrant/internal/models"
)

// SignedPatchArtifact represents an upstream binary/patch artifact with cryptographic publisher provenance.
type SignedPatchArtifact struct {
	ServiceID          string `json:"service_id"`
	CVEID              string `json:"cve_id"`
	PatchedDigest      string `json:"patched_digest"`
	PublisherID        string `json:"publisher_id"`
	PublisherKeyID     string `json:"publisher_key_id"`
	ProvenanceSigB64   string `json:"provenance_sig_b64"`
	UnifiedDiff        string `json:"unified_diff"`
}

// BridgeApplyRequest carries deterministic parameters to compile and apply a containment bridge.
type BridgeApplyRequest struct {
	BridgeID                 string
	RemediationID            string
	ServiceID                string
	Namespace                string
	CVEID                    string
	CWEID                    string
	ExploitVector            string
	AffectedPort             int
	BlockedPaths             []string
	AllowedEgressServices    []string
	AllowKubeAPIServerEgress bool
	SLABridgeMinutes         int
	BlockerReasonCode        string
	RearmCount               int
}

// ScannerIntake ingests untrusted vulnerability scan reports via N4 + warrant-extractor.
type ScannerIntake interface {
	IngestSARIF(ctx context.Context, rawSARIF []byte) (*models.ExtractedFindingSet, error)
}

// FixProvider resolves and verifies cryptographic publisher provenance on candidate patches.
type FixProvider interface {
	ResolveSignedPatch(ctx context.Context, finding models.ExtractedFinding, patchProfile string) (*SignedPatchArtifact, error)
	VerifyProvenance(artifact SignedPatchArtifact) error
}

// ShieldEnforcer compiles and enforces declarative Cilium / K8s NetworkPolicy / Envoy mTLS containment bridges.
type ShieldEnforcer interface {
	CompileAndApplyBridge(ctx context.Context, req BridgeApplyRequest) (*models.ContainmentBridge, error)
	RetireBridge(ctx context.Context, bridgeID string) error
}

// DeploymentTarget drives container image rollouts, shadow mirroring, rollback, pod sweeps, and Admission Lockouts.
type DeploymentTarget interface {
	ProgressCanary(ctx context.Context, serviceID string, req fleetsim.StageRolloutRequest) (*fleetsim.StageRolloutResponse, error)
	RollbackCanary(ctx context.Context, serviceID string) error
	RollbackToDigest(ctx context.Context, serviceID, targetDigest string) error
	InspectLiveWorkload(ctx context.Context, serviceID string) (*fleetsim.WorkloadState, error)
	EnforceAdmissionLockout(ctx context.Context, remediationID, serviceID, cveID, bannedDigest, patchedDigest string) (*models.AdmissionLockout, error)
	SuspendAdmissionLockout(ctx context.Context, lockoutID, policyName, reason string) error
	RotateWorkloadSecret(ctx context.Context, serviceID, secretResourceKind, secretResourceName string) (*fleetsim.SecretRotationResult, error)
	CordonAndRecyclePod(ctx context.Context, serviceID, podName, cleanDigest string) (recycledPod string, err error)
	InjectDriftSimulation(ctx context.Context, serviceID, bannedDigest string) (roguePod string, injectedUnixMs int64, err error)
	InjectFilesystemDriftSimulation(ctx context.Context, serviceID, filePath, processName string) (podName string, injectedUnixMs int64, err error)
	RegisterImageProfile(ctx context.Context, prof fleetsim.ImageBehaviorProfile) error
}

// TwinRunner dispatches isolated exploit reproduction runs against an ephemeral shadow twin workload.
type TwinRunner interface {
	RunExploitReplay(ctx context.Context, req fleetsim.TwinReplayRequest) (*fleetsim.TwinReplayResponse, error)
}
