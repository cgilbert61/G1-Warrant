package estatereader

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// Registry manages all registered EstateReader instances across all 5 handler families (18 builtin systems + pluggable declarative REST).
type Registry struct {
	mu      sync.RWMutex
	readers map[string]EstateReader
}

func NewRegistry() *Registry {
	return &Registry{
		readers: make(map[string]EstateReader),
	}
}

func normalizeSystemID(id string) string {
	s := strings.ToLower(strings.TrimSpace(id))
	switch s {
	case "qualys", "qualys-vmdr":
		return "qualys_vmdr"
	case "tenable_io", "tenable_sc", "tenable-io-sc", "tenable_io_sc":
		return "tenable"
	case "rapid7", "insightvm", "rapid7-insightvm":
		return "rapid7_insightvm"
	default:
		return s
	}
}

func (r *Registry) Register(er EstateReader) {
	if r == nil || er == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.readers[normalizeSystemID(er.SourceSystem())] = er
}

// RegisterDeclarativeREST registers a proprietary REST endpoint manager using ONLY a declarative RESTMappingSpec
// (zero new Go handler code required).
func (r *Registry) RegisterDeclarativeREST(
	spec RESTMappingSpec,
	readURL, readToken, dispatchToken string,
	rt http.RoundTripper,
) error {
	if strings.TrimSpace(spec.SourceSystem) == "" || strings.TrimSpace(spec.InventoryPath) == "" {
		return fmt.Errorf("invalid RESTMappingSpec: source_system and inventory_path are required")
	}
	r.Register(NewDeclarativeRESTEstateReader(spec, readURL, readToken, dispatchToken, rt))
	return nil
}

func (r *Registry) Get(sourceSystem string) (EstateReader, error) {
	if r == nil {
		return nil, fmt.Errorf("ESTATE_READER_REGISTRY_UNINITIALIZED")
	}
	norm := normalizeSystemID(sourceSystem)
	r.mu.RLock()
	defer r.mu.RUnlock()
	er, ok := r.readers[norm]
	if !ok {
		return nil, fmt.Errorf("UNKNOWN_ESTATE_SOURCE_SYSTEM: %q", sourceSystem)
	}
	return er, nil
}

func (r *Registry) ListDescriptors() []models.EstateSourceDescriptor {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]models.EstateSourceDescriptor, 0, len(r.readers))
	for _, er := range r.readers {
		out = append(out, models.EstateSourceDescriptor{
			SourceSystem:           er.SourceSystem(),
			DisplayName:            er.DisplayName(),
			SourceTier:             er.SourceTier(),
			HandlerFamily:          er.HandlerFamily(),
			ReadEnvPrefix:          er.ReadEnvPrefix(),
			ReadConfigured:         er.ReadConfigured(),
			CanProposeCloneSources: er.SourceTier() != models.EstateSourceTierCCensus,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceTier != out[j].SourceTier {
			return out[i].SourceTier < out[j].SourceTier
		}
		return out[i].SourceSystem < out[j].SourceSystem
	})
	return out
}

// IsAnyRegisteredReadToken returns true if tok matches ANY registered EstateReader's read-only token.
// Used by WN-8 dispatch/mutation/signing routes to enforce Rule 2 (read credentials MUST be rejected on dispatch/signing routes).
func (r *Registry) IsAnyRegisteredReadToken(tok string) (string, bool) {
	t := strings.TrimSpace(tok)
	if r == nil || t == "" {
		return "", false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, er := range r.readers {
		switch impl := er.(type) {
		case *MicrosoftFamilyEstateReader:
			if impl.IsMatchingReadToken(t) {
				return impl.SourceSystem(), true
			}
		case *CloudFamilyEstateReader:
			if impl.IsMatchingReadToken(t) {
				return impl.SourceSystem(), true
			}
		case *KubernetesFamilyEstateReader:
			if impl.IsMatchingReadToken(t) {
				return impl.SourceSystem(), true
			}
		case *DeclarativeRESTEstateReader:
			if impl.IsMatchingReadToken(t) {
				return impl.SourceSystem(), true
			}
		case *ScannerCensusEstateReader:
			if impl.IsMatchingReadToken(t) {
				return impl.SourceSystem(), true
			}
		}
	}
	return "", false
}

// IsAnyRegisteredDispatchToken returns true if tok matches ANY registered system's WN-8 dispatch token.
// Used by /api/v1/estate-loader/* routes to enforce Rule 2 (dispatch credentials MUST be rejected on estate-read routes).
func (r *Registry) IsAnyRegisteredDispatchToken(tok string) (string, bool) {
	t := strings.TrimSpace(tok)
	if r == nil || t == "" {
		return "", false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, er := range r.readers {
		switch impl := er.(type) {
		case *MicrosoftFamilyEstateReader:
			if impl.IsMatchingDispatchToken(t) {
				return impl.SourceSystem(), true
			}
		case *CloudFamilyEstateReader:
			if impl.IsMatchingDispatchToken(t) {
				return impl.SourceSystem(), true
			}
		case *KubernetesFamilyEstateReader:
			if impl.IsMatchingDispatchToken(t) {
				return impl.SourceSystem(), true
			}
		case *DeclarativeRESTEstateReader:
			if impl.IsMatchingDispatchToken(t) {
				return impl.SourceSystem(), true
			}
		case *ScannerCensusEstateReader:
			if impl.IsMatchingDispatchToken(t) {
				return impl.SourceSystem(), true
			}
		}
	}
	return "", false
}

// RegisterAllBuiltinEstateReaders registers all 18 connected systems across strictly 5 handler families:
//   - Tier A (12): ms-intune, azure-update-manager, ms-mecm, ms-wsus, aws-ssm, gcp-os-config,
//     tanium-patch, ivanti-neurons, automox, jamf-pro, redhat-satellite, ansible-awx
//   - Tier B (3):  k8s-cilium-native, argocd, flux
//   - Tier C (3):  qualys_vmdr, tenable, rapid7_insightvm
func RegisterAllBuiltinEstateReaders(
	reg *Registry,
	localK8sInspector LocalK8sWorkloadReader,
	defaultTransport http.RoundTripper,
	getenv func(string) string,
) error {
	if reg == nil {
		return nil
	}
	if getenv == nil {
		getenv = func(string) string { return "" }
	}

	// Family (a): Microsoft Estate (4 Tier A systems)
	reg.Register(NewMicrosoftFamilyEstateReader(
		"ms-intune", "Microsoft Intune (Graph Managed Devices)", "WARRANT_MS_INTUNE",
		getenv("WARRANT_MS_INTUNE_READ_URL"), getenv("WARRANT_MS_INTUNE_READ_TOKEN"), getenv("WARRANT_MS_INTUNE_TOKEN"),
		defaultTransport,
	))
	reg.Register(NewMicrosoftFamilyEstateReader(
		"azure-update-manager", "Azure Update Manager & Resource Graph", "WARRANT_AZURE_UPDATE",
		getenv("WARRANT_AZURE_UPDATE_READ_URL"), getenv("WARRANT_AZURE_UPDATE_READ_TOKEN"), getenv("WARRANT_AZURE_UPDATE_TOKEN"),
		defaultTransport,
	))
	reg.Register(NewMicrosoftFamilyEstateReader(
		"ms-mecm", "Microsoft Configuration Manager (AdminService CIM)", "WARRANT_MS_MECM",
		getenv("WARRANT_MS_MECM_READ_URL"), getenv("WARRANT_MS_MECM_READ_TOKEN"), getenv("WARRANT_MS_MECM_TOKEN"),
		defaultTransport,
	))
	reg.Register(NewMicrosoftFamilyEstateReader(
		"ms-wsus", "Microsoft WSUS Computer Target Inventory", "WARRANT_MS_WSUS",
		getenv("WARRANT_MS_WSUS_READ_URL"), getenv("WARRANT_MS_WSUS_READ_TOKEN"), getenv("WARRANT_MS_WSUS_TOKEN"),
		defaultTransport,
	))

	// Family (b): Cloud Inventory (2 Tier A systems)
	reg.Register(NewCloudFamilyEstateReader(
		"aws-ssm", "AWS Systems Manager Inventory & QA AMI Catalog", "WARRANT_AWS_SSM",
		getenv("WARRANT_AWS_SSM_READ_URL"), getenv("WARRANT_AWS_SSM_READ_TOKEN"), getenv("WARRANT_AWS_SSM_TOKEN"),
		defaultTransport,
	))
	reg.Register(NewCloudFamilyEstateReader(
		"gcp-os-config", "Google Cloud OS Config & Asset Inventory", "WARRANT_GCP_OSCONFIG",
		getenv("WARRANT_GCP_OSCONFIG_READ_URL"), getenv("WARRANT_GCP_OSCONFIG_READ_TOKEN"), getenv("WARRANT_GCP_OSCONFIG_TOKEN"),
		defaultTransport,
	))

	// Family (c): Unified Kubernetes API (3 Tier B systems)
	reg.Register(NewKubernetesFamilyEstateReader(
		"k8s-cilium-native", "Kubernetes API & Cilium Workload Digests", "WARRANT_KUBE",
		getenv("WARRANT_KUBE_READ_URL"), getenv("WARRANT_KUBE_READ_TOKEN"), getenv("WARRANT_KUBE_API_TOKEN"),
		localK8sInspector, defaultTransport,
	))
	reg.Register(NewKubernetesFamilyEstateReader(
		"argocd", "Argo CD Application & Kubernetes Workload Inventory", "WARRANT_ARGOCD",
		getenv("WARRANT_ARGOCD_READ_URL"), getenv("WARRANT_ARGOCD_READ_TOKEN"), getenv("WARRANT_ARGOCD_TOKEN"),
		nil, defaultTransport,
	))
	reg.Register(NewKubernetesFamilyEstateReader(
		"flux", "Flux GitOps & Kubernetes OCI Workload Inventory", "WARRANT_FLUX",
		getenv("WARRANT_FLUX_READ_URL"), getenv("WARRANT_FLUX_READ_TOKEN"), getenv("WARRANT_FLUX_TOKEN"),
		nil, defaultTransport,
	))

	// Family (d): Declarative Proprietary REST Endpoint Managers (6 Tier A systems loaded from embedded JSON mappings)
	specs, err := LoadEmbeddedRESTMappingSpecs()
	if err != nil {
		return err
	}
	for _, spec := range specs {
		readPrefix := spec.ReadEnvPrefix
		dispPrefix := firstStr(spec.DispatchEnvPrefix, readPrefix)
		reg.Register(NewDeclarativeRESTEstateReader(
			spec,
			getenv(readPrefix+"_READ_URL"),
			getenv(readPrefix+"_READ_TOKEN"),
			getenv(dispPrefix+"_TOKEN"),
			defaultTransport,
		))
	}

	// Optional pluggable osquery / CMDB Tier A registration when configured via env (never required)
	if osqURL := strings.TrimSpace(getenv("WARRANT_OSQUERY_FLEET_READ_URL")); osqURL != "" {
		reg.Register(NewDeclarativeRESTEstateReader(
			RESTMappingSpec{
				SourceSystem:         "osquery-fleet",
				DisplayName:          "FleetDM / osquery Host Telemetry",
				SourceTier:           models.EstateSourceTierAMachine,
				ReadEnvPrefix:        "WARRANT_OSQUERY_FLEET",
				DispatchEnvPrefix:    "WARRANT_OSQUERY_FLEET",
				InventoryMethod:      http.MethodGet,
				InventoryPath:        "/api/v1/fleet/hosts/summary",
				ClassQueryParam:      "team",
				DefaultPlatform:      "LINUX_DEB",
				DefaultOSFamily:      "LINUX",
				RecordsArrayPath:     "hosts",
				TotalCountPath:       "count",
				FreshnessPath:        "updated_at",
				OSFamilyField:        "platform",
				OSVersionField:       "os_version",
				KernelReleaseField:   "kernel_version",
				SoftwareNameField:    "primary_package",
				SoftwareVersionField: "primary_version",
				CandidatesArrayPath:  "golden_images",
				CandidateIDField:     "image_id",
			},
			osqURL,
			getenv("WARRANT_OSQUERY_FLEET_READ_TOKEN"),
			"",
			defaultTransport,
		))
	}

	// Family (e): Vulnerability Scanners — Tier C Corroborating Census ONLY (3 systems, 0 clone sources)
	reg.Register(NewScannerCensusEstateReader(
		"qualys_vmdr", "Qualys VMDR Asset Census (Tier C Corroboration Only)", "WARRANT_QUALYS",
		getenv("WARRANT_QUALYS_READ_URL"), getenv("WARRANT_QUALYS_READ_TOKEN"), getenv("WARRANT_INTAKE_TOKEN"),
		defaultTransport,
	))
	reg.Register(NewScannerCensusEstateReader(
		"tenable", "Tenable.io/sc Asset Census (Tier C Corroboration Only)", "WARRANT_TENABLE",
		getenv("WARRANT_TENABLE_READ_URL"), getenv("WARRANT_TENABLE_READ_TOKEN"), getenv("WARRANT_INTAKE_TOKEN"),
		defaultTransport,
	))
	reg.Register(NewScannerCensusEstateReader(
		"rapid7_insightvm", "Rapid7 InsightVM Asset Census (Tier C Corroboration Only)", "WARRANT_RAPID7",
		getenv("WARRANT_RAPID7_READ_URL"), getenv("WARRANT_RAPID7_READ_TOKEN"), getenv("WARRANT_INTAKE_TOKEN"),
		defaultTransport,
	))

	return nil
}
