package distributors

import (
	"net/http"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
)

// RegisterAllBuiltinDistributors populates reg with all 15 canonical WN-8 DistributorTranslators
// across all 6 enterprise patch deployment families, reading optional vendor URLs/tokens from getenv.
func RegisterAllBuiltinDistributors(
	reg *adapters.DistributorRegistry,
	deploy adapters.DeploymentTarget,
	defaultTransport http.RoundTripper,
	getenv func(string) string,
) {
	if reg == nil {
		return
	}
	if getenv == nil {
		getenv = func(string) string { return "" }
	}

	// 1. Containers & GitOps Family
	reg.Register(NewK8sCiliumNativeTranslator(deploy))
	reg.Register(NewArgoCDTranslator(getenv("WARRANT_ARGOCD_URL"), getenv("WARRANT_ARGOCD_TOKEN"), defaultTransport))
	reg.Register(NewFluxGitOpsTranslator(getenv("WARRANT_FLUX_URL"), getenv("WARRANT_FLUX_TOKEN"), defaultTransport))

	// 2. Microsoft Estate Family
	reg.Register(NewMSIntuneTranslator(getenv("WARRANT_MS_INTUNE_URL"), getenv("WARRANT_MS_INTUNE_TOKEN"), defaultTransport))
	reg.Register(NewMSMECMTranslator(getenv("WARRANT_MS_MECM_URL"), getenv("WARRANT_MS_MECM_TOKEN"), defaultTransport))
	reg.Register(NewMSWSUSTranslator(getenv("WARRANT_MS_WSUS_URL"), getenv("WARRANT_MS_WSUS_TOKEN"), defaultTransport))

	// 3. Linux Automation Family
	reg.Register(NewAnsibleAWXTranslator(getenv("WARRANT_ANSIBLE_AWX_URL"), getenv("WARRANT_ANSIBLE_AWX_TOKEN"), defaultTransport))
	reg.Register(NewRedHatSatelliteTranslator(getenv("WARRANT_REDHAT_SATELLITE_URL"), getenv("WARRANT_REDHAT_SATELLITE_TOKEN"), defaultTransport))

	// 4. Apple Estate Family
	reg.Register(NewJamfProTranslator(getenv("WARRANT_JAMF_PRO_URL"), getenv("WARRANT_JAMF_PRO_TOKEN"), defaultTransport))

	// 5. Cloud-Native Patchers Family
	reg.Register(NewAWSSSMTranslator(getenv("WARRANT_AWS_SSM_URL"), getenv("WARRANT_AWS_SSM_TOKEN"), defaultTransport))
	reg.Register(NewAzureUpdateManagerTranslator(getenv("WARRANT_AZURE_UPDATE_URL"), getenv("WARRANT_AZURE_UPDATE_TOKEN"), defaultTransport))
	reg.Register(NewGCPOSConfigTranslator(getenv("WARRANT_GCP_OSCONFIG_URL"), getenv("WARRANT_GCP_OSCONFIG_TOKEN"), defaultTransport))

	// 6. Multi-Platform Patch Family
	reg.Register(NewTaniumPatchTranslator(getenv("WARRANT_TANIUM_URL"), getenv("WARRANT_TANIUM_TOKEN"), defaultTransport))
	reg.Register(NewIvantiNeuronsTranslator(getenv("WARRANT_IVANTI_URL"), getenv("WARRANT_IVANTI_TOKEN"), defaultTransport))
	reg.Register(NewAutomoxTranslator(getenv("WARRANT_AUTOMOX_URL"), getenv("WARRANT_AUTOMOX_TOKEN"), defaultTransport))
}
