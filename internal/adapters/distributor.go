package adapters

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// DistributorCapabilities aliases models.DistributorCapabilities for concise translator signatures.
type DistributorCapabilities = models.DistributorCapabilities

// DistributorTranslator is the single outbound/inbound translation boundary for every WN-8 estate patch distributor.
// Adding any vendor is a bounded implementation of this interface — never a new kernel pipeline.
type DistributorTranslator interface {
	DistributorID() string
	DisplayName() string
	Family() string
	Capabilities() DistributorCapabilities
	EndpointConfigured() bool
	WithTransport(rt http.RoundTripper) DistributorTranslator
	DispatchOrder(ctx context.Context, order models.DeploymentOrder) (*models.DeploymentDispatchReceipt, error)
	PollResult(ctx context.Context, orderID string, nativeJobRef string) (*models.DeploymentResult, error)
	ExecuteRollback(ctx context.Context, order models.DeploymentOrder, nativeJobRef string, reason string) (*models.DeploymentResult, error)
}

// DistributorRegistry indexes registered WN-8 DistributorTranslators by canonical DistributorID.
type DistributorRegistry struct {
	mu          sync.RWMutex
	translators map[string]DistributorTranslator
}

// NewDistributorRegistry creates an empty thread-safe DistributorRegistry.
func NewDistributorRegistry() *DistributorRegistry {
	return &DistributorRegistry{
		translators: make(map[string]DistributorTranslator),
	}
}

// Register adds or replaces a DistributorTranslator in the registry.
func (r *DistributorRegistry) Register(tr DistributorTranslator) {
	if r == nil || tr == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.translators[strings.ToLower(strings.TrimSpace(tr.DistributorID()))] = tr
}

// Get retrieves a registered DistributorTranslator by ID.
func (r *DistributorRegistry) Get(distributorID string) (DistributorTranslator, error) {
	if r == nil {
		return nil, fmt.Errorf("distributor registry not initialized")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	key := strings.ToLower(strings.TrimSpace(distributorID))
	tr, ok := r.translators[key]
	if !ok {
		return nil, fmt.Errorf("UNKNOWN_DISTRIBUTOR_ID: %q", distributorID)
	}
	return tr, nil
}

// ListDescriptors returns sorted DistributorDescriptors for Console, CLI, and SDK inspection.
func (r *DistributorRegistry) ListDescriptors() []models.DistributorDescriptor {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]models.DistributorDescriptor, 0, len(r.translators))
	for _, tr := range r.translators {
		out = append(out, models.DistributorDescriptor{
			DistributorID:      tr.DistributorID(),
			DisplayName:        tr.DisplayName(),
			Family:             tr.Family(),
			Capabilities:       tr.Capabilities(),
			EndpointConfigured: tr.EndpointConfigured(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].DistributorID < out[j].DistributorID
	})
	return out
}
