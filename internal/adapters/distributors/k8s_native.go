package distributors

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/fleetsim"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/google/uuid"
)

// K8sCiliumNativeTranslator wraps G1-Warrant's existing K8sRolloutAdapter / LiveKubernetesAdapter (DeploymentTarget)
// as Distributor #1 ("k8s-cilium-native"), preserving 100% existing container digest-pinning & lockout behavior.
type K8sCiliumNativeTranslator struct {
	deploy adapters.DeploymentTarget
	mu     sync.Mutex
	orders map[string]models.DeploymentOrder
}

func NewK8sCiliumNativeTranslator(deploy adapters.DeploymentTarget) *K8sCiliumNativeTranslator {
	return &K8sCiliumNativeTranslator{
		deploy: deploy,
		orders: make(map[string]models.DeploymentOrder),
	}
}

func (k *K8sCiliumNativeTranslator) DistributorID() string   { return models.DistributorK8sCiliumNative }
func (k *K8sCiliumNativeTranslator) DisplayName() string     { return "Kubernetes + Cilium Native Rollout" }
func (k *K8sCiliumNativeTranslator) Family() string          { return "CONTAINERS_GITOPS" }
func (k *K8sCiliumNativeTranslator) EndpointConfigured() bool { return k.deploy != nil }

func (k *K8sCiliumNativeTranslator) Capabilities() models.DistributorCapabilities {
	return models.DistributorCapabilities{
		SupportsNativeRings:     true,
		ReportsPerAssetState:    true,
		SupportsRebootTracking:  false,
		PlatformFamilies:        []string{"CONTAINER_LINUX"},
		DefaultRollbackStrategy: "PIN_PREVIOUS_OCI_DIGEST",
	}
}

func (k *K8sCiliumNativeTranslator) WithTransport(_ http.RoundTripper) adapters.DistributorTranslator {
	return k
}

func (k *K8sCiliumNativeTranslator) DispatchOrder(ctx context.Context, order models.DeploymentOrder) (*models.DeploymentDispatchReceipt, error) {
	if k.deploy == nil {
		return nil, fmt.Errorf("k8s-cilium-native DeploymentTarget is nil")
	}
	waves := order.RolloutPlan.Waves
	if len(waves) == 0 {
		waves = []models.RolloutWave{
			{WaveNumber: 1, Percentage: 5},
			{WaveNumber: 2, Percentage: 25},
			{WaveNumber: 3, Percentage: 100},
		}
	}
	for _, w := range waves {
		pct := w.Percentage
		if pct <= 0 {
			pct = 100
		}
		_, err := k.deploy.ProgressCanary(ctx, order.ServiceID, fleetsim.StageRolloutRequest{
			PatchedDigest: order.FixIdentity.TargetDigest,
			StageWeight:   pct,
		})
		if err != nil {
			return nil, err
		}
	}
	jobRef := fmt.Sprintf("k8s-rollout:%s:%s", order.ServiceID, order.OrderID)
	k.mu.Lock()
	k.orders[jobRef] = order
	k.orders[order.OrderID] = order
	k.mu.Unlock()

	return &models.DeploymentDispatchReceipt{
		OrderID:              order.OrderID,
		DistributorID:        k.DistributorID(),
		NativeJobRef:         jobRef,
		SupportsNativeRings:  true,
		ReportsPerAssetState: true,
		DispatchedAt:         time.Now().UTC(),
	}, nil
}

func (k *K8sCiliumNativeTranslator) PollResult(ctx context.Context, orderID string, nativeJobRef string) (*models.DeploymentResult, error) {
	k.mu.Lock()
	order, ok := k.orders[nativeJobRef]
	if !ok {
		order, ok = k.orders[orderID]
	}
	k.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("k8s-cilium-native order %q not found", orderID)
	}

	wl, err := k.deploy.InspectLiveWorkload(ctx, order.ServiceID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	assets := make([]models.AssetDeploymentStatus, 0, len(wl.Pods))
	for _, pod := range wl.Pods {
		st := models.AssetDeployPending
		if pod.RunningDigest == order.FixIdentity.TargetDigest {
			st = models.AssetDeployLanded
		}
		assets = append(assets, models.AssetDeploymentStatus{
			AssetKey:       pod.PodName,
			NativeDeviceID: pod.NodeName + "/" + pod.PodName,
			State:          st,
			NativeExitCode: 0,
			ReportedAt:     now,
		})
	}
	reportHash, _, _ := crypto.CanonicalSHA256Hex(assets)
	res := &models.DeploymentResult{
		ResultID:                   "dres-" + uuid.NewString()[:8],
		OrderID:                    orderID,
		RemediationID:              order.RemediationID,
		DistributorID:              k.DistributorID(),
		NativeJobRef:               nativeJobRef,
		WaveNumber:                 max(1, len(order.RolloutPlan.Waves)),
		ObservedAt:                 now,
		EvidenceGranularity:        models.EvidenceGranularityPerAsset,
		AssetResults:               assets,
		TargetedCount:              len(assets),
		RawDistributorReportSHA256: reportHash,
	}
	res.RecomputeCounts()
	return res, nil
}

func (k *K8sCiliumNativeTranslator) ExecuteRollback(ctx context.Context, order models.DeploymentOrder, nativeJobRef string, reason string) (*models.DeploymentResult, error) {
	prevDigest := order.RollbackInstruction.PreviousDigest
	if prevDigest != "" {
		if err := k.deploy.RollbackToDigest(ctx, order.ServiceID, prevDigest); err != nil {
			return nil, err
		}
	} else {
		if err := k.deploy.RollbackCanary(ctx, order.ServiceID); err != nil {
			return nil, err
		}
	}
	wl, err := k.deploy.InspectLiveWorkload(ctx, order.ServiceID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	assets := make([]models.AssetDeploymentStatus, 0, len(wl.Pods))
	for _, pod := range wl.Pods {
		assets = append(assets, models.AssetDeploymentStatus{
			AssetKey:       pod.PodName,
			NativeDeviceID: pod.NodeName + "/" + pod.PodName,
			State:          models.AssetDeployRolledBack,
			NativeExitCode: 0,
			ReportedAt:     now,
		})
	}
	reportHash, _, _ := crypto.CanonicalSHA256Hex(assets)
	res := &models.DeploymentResult{
		ResultID:                   "dres-" + uuid.NewString()[:8],
		OrderID:                    order.OrderID,
		RemediationID:              order.RemediationID,
		DistributorID:              k.DistributorID(),
		NativeJobRef:               nativeJobRef,
		ObservedAt:                 now,
		EvidenceGranularity:        models.EvidenceGranularityPerAsset,
		AssetResults:               assets,
		TargetedCount:              len(assets),
		IsRollback:                 true,
		RollbackReason:             reason,
		RawDistributorReportSHA256: reportHash,
	}
	res.RecomputeCounts()
	return res, nil
}
