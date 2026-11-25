-- 013_multi_substrate_shields.sql
-- Extends containment_bridges to support Universal Multi-Substrate Sub-Second Shielding
-- across Kubernetes/Containers, Cloud VMs (AWS EC2 SG+IMDSv2, Azure NSG, GCP Firewall),
-- Linux Hosts (atomic nftables), and Windows Hosts (Windows Filtering Platform NetFirewallRule).

ALTER TABLE containment_bridges
    DROP CONSTRAINT IF EXISTS containment_bridges_bridge_type_check;

ALTER TABLE containment_bridges
    ADD CONSTRAINT containment_bridges_bridge_type_check CHECK (
        bridge_type IN (
            'CILIUM_L7_NETPOL',
            'ENVOY_MTLS_WAF',
            'K8S_NETPOL',
            'AWS_EC2_SG_IMDS',
            'AZURE_NSG_QUARANTINE',
            'GCP_VPC_FIREWALL',
            'LINUX_NFTABLES_SHIELD',
            'WINDOWS_WFP_NETFIREWALL'
        )
    );

ALTER TABLE containment_bridges
    ADD COLUMN IF NOT EXISTS substrate_family TEXT NOT NULL DEFAULT 'KUBERNETES',
    ADD COLUMN IF NOT EXISTS native_shield_manifest TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS native_retire_spec TEXT NOT NULL DEFAULT '';
