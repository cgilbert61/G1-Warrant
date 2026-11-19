package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/g1163rt-labs/g1-warrant/internal/models"
)

func main() {
	baseURL := strings.TrimRight(os.Getenv("WARRANT_API_URL"), "/")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	client := &http.Client{Timeout: 20 * time.Second}
	cmd := os.Args[1]

	switch cmd {
	case "status":
		var sb models.GlobalScoreboard
		mustGetJSON(client, baseURL+"/api/v1/scoreboard", &sb)
		fmt.Printf("G1-WARRANT CONTROL PLANE STATUS\n")
		fmt.Printf("  Posture:               %s (Actor: %s | Reason: %s)\n", sb.FreezeState.Mode, sb.FreezeState.Actor, sb.FreezeState.ReasonCode)
		fmt.Printf("  Active Warrants:       %d\n", sb.ActiveWarrantsCount)
		fmt.Printf("  30d Fleet Median TTVR: %ds\n", sb.FleetMedianTTVRSeconds)
		fmt.Printf("  Active Bridges Armed:  %d (Median Age: %ds)\n", sb.ActiveBridgesArmed, sb.MedianBridgeAgeSeconds)
		fmt.Printf("  Estate Eligibility:    %.1f%% (%d/%d services)\n", sb.AutonomousEligibilityPct, sb.EligibleServicesCount, sb.TotalServicesCount)
		fmt.Printf("  Awaiting Dual-Key:     %d\n", sb.AwaitingDualKeyInboxCount)
		fmt.Printf("  Drift Violations:      %d\n", sb.ActiveDriftViolationsCount)

	case "warrants":
		sub := argOrDefault(os.Args, 2, "list")
		if sub == "list" {
			var list []models.WarrantRecord
			mustGetJSON(client, baseURL+"/api/v1/warrants", &list)
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "WARRANT_ID\tCLASS\tSTATUS\tSLOT1_SO\tSLOT2_AO\tMAX_CVSS\tEXPIRES_AT")
			for _, w := range list {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%.1f\t%s\n",
					w.WarrantID, w.WarrantClass, w.LiveStatus, w.Slot1PrincipalID, w.Slot2PrincipalID, w.MaxCVSS, w.ExpiresAt.Format(time.RFC3339))
			}
			_ = tw.Flush()
		} else if sub == "verify" && len(os.Args) >= 4 {
			var out map[string]any
			mustPostJSON(client, baseURL+"/api/v1/warrants/"+os.Args[3]+"/verify", map[string]any{}, &out)
			raw, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(raw))
		} else {
			printUsage()
			os.Exit(1)
		}

	case "pipeline":
		sub := argOrDefault(os.Args, 2, "list")
		if sub == "list" {
			var list []models.RemediationItem
			mustGetJSON(client, baseURL+"/api/v1/pipeline", &list)
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "REMEDIATION_ID\tCVE\tKEV\tSERVICE\tSTAGE\tHEALTH\tCANARY\tLOCKOUT")
			for _, r := range list {
				fmt.Fprintf(tw, "%s\t%s\t%t\t%s\t%s\t%s\t%d%%\t%s\n",
					r.RemediationID, r.CVEID, r.IsKEV, r.ServiceID, r.Stage, r.StatusHealth, r.CanaryWeight, r.LockoutPolicyID)
			}
			_ = tw.Flush()
		} else if sub == "trace" && len(os.Args) >= 4 {
			var traces []models.TraceEvent
			mustGetJSON(client, baseURL+"/api/v1/pipeline/"+os.Args[3]+"/traces", &traces)
			for _, t := range traces {
				fmt.Printf("[%s] %-7s %-36s %-9s actor=%s hash=%s\n",
					t.OccurredAt.Format("15:04:05.000"), t.Engine, t.StepCode, t.Outcome, t.ActorOrToken, t.EvidenceHash[:16])
			}
		} else {
			printUsage()
			os.Exit(1)
		}

	case "estate":
		var list []models.EstateService
		mustGetJSON(client, baseURL+"/api/v1/estate", &list)
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SERVICE_ID\tTIER\tELIGIBLE\tCOVERAGE\tOTEL\tSHADOW_RO\tROLLBACK_OK")
		for _, s := range list {
			fmt.Fprintf(tw, "%s\t%s\t%t\t%.1f%%\t%t\t%t\t%t\n",
				s.ServiceID, s.Tier, s.Eligible, s.TestCoveragePct, s.OtelHealthProbes, s.ReadonlyShadowReplica, s.RollbackAutomationVerified)
		}
		_ = tw.Flush()

	case "freeze":
		sub := argOrDefault(os.Args, 2, "")
		fsFlags := flag.NewFlagSet("freeze", flag.ExitOnError)
		actor := fsFlags.String("actor", "cli-operator", "Actor triggering emergency freeze")
		reason := fsFlags.String("reason", "CLI_EMERGENCY_ACTION", "Reason code")
		if len(os.Args) > 3 {
			_ = fsFlags.Parse(os.Args[3:])
		}
		switch sub {
		case "hold", "rollback":
			mode := models.FreezeModeHold
			if sub == "rollback" {
				mode = models.FreezeModeRollback
			}
			var out models.FreezeState
			mustPostJSON(client, baseURL+"/api/v1/freeze", map[string]string{
				"mode":        mode,
				"actor":       *actor,
				"reason_code": *reason,
			}, &out)
			fmt.Printf("Emergency Freeze Activated: %s by %s at %s\n", out.Mode, out.Actor, out.UpdatedAt.Format(time.RFC3339))
		case "thaw":
			personas := crypto.BuiltinTestPersonas()
			var alice, bob crypto.TestSmartcardPersona
			for _, p := range personas {
				if p.PrincipalID == "usr-alice-so" {
					alice = p
				}
				if p.PrincipalID == "usr-bob-ao" {
					bob = p
				}
			}
			env, _, err := crypto.NewUnsignedEnvelope(crypto.PayloadTypeThaw, map[string]any{
				"action":       "THAW_FLEET",
				"requested_at": time.Now().UTC().Format(time.RFC3339),
			})
			if err != nil {
				fatalf("envelope err: %v", err)
			}
			_ = env.SignEd25519(1, alice.ToPrincipalKey(), alice.PrivateKey)
			_ = env.SignEd25519(2, bob.ToPrincipalKey(), bob.PrivateKey)
			var out models.FreezeState
			mustPostJSON(client, baseURL+"/api/v1/freeze/thaw", env, &out)
			fmt.Printf("Fleet Thawed via 2-of-2 DSSE Ceremony: %s (%s)\n", out.Mode, out.Actor)
		default:
			printUsage()
			os.Exit(1)
		}

	case "intake":
		if len(os.Args) < 4 || os.Args[2] != "sarif" {
			printUsage()
			os.Exit(1)
		}
		raw, err := os.ReadFile(os.Args[3])
		if err != nil {
			fatalf("read sarif file: %v", err)
		}
		resp, err := client.Post(baseURL+"/api/v1/intake/sarif", "application/json", bytes.NewReader(raw))
		if err != nil {
			fatalf("post sarif: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 300 {
			fatalf("HTTP %d: %s", resp.StatusCode, string(body))
		}
		fmt.Println(string(body))

	case "ledger":
		var rep models.LedgerVerificationReport
		mustPostJSON(client, baseURL+"/api/v1/ledger/verify", map[string]any{}, &rep)
		fmt.Printf("LEDGER CRYPTOGRAPHIC CHAIN VERIFICATION: all_valid=%t (at %s)\n", rep.AllValid, rep.VerifiedAt.Format(time.RFC3339))
		for _, tbl := range rep.Tables {
			fmt.Printf("  - %-22s rows=%-4d valid=%-5t terminal_sha256=%s\n", tbl.TableName, tbl.RowCount, tbl.Valid, tbl.TerminalHash)
		}
		if !rep.AllValid {
			os.Exit(2)
		}

	case "oscal":
		if len(os.Args) < 4 || os.Args[2] != "export" {
			printUsage()
			os.Exit(1)
		}
		id := os.Args[3]
		resp, err := client.Get(baseURL + "/api/v1/attestations/" + id + "/oscal")
		if err != nil {
			fatalf("fetch oscal: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 300 {
			fatalf("HTTP %d: %s", resp.StatusCode, string(body))
		}
		if len(os.Args) >= 5 {
			if err := os.WriteFile(os.Args[4], body, 0600); err != nil {
				fatalf("write file: %v", err)
			}
			fmt.Printf("Wrote signed NIST OSCAL 1.1.2 POA&M bundle to %s\n", os.Args[4])
		} else {
			fmt.Println(string(body))
		}

	case "feeds":
		sub := argOrDefault(os.Args, 2, "status")
		switch sub {
		case "status":
			var st models.LiveFeedStatus
			mustGetJSON(client, baseURL+"/api/v1/feeds/status", &st)
			fmt.Printf("G1-WARRANT LIVE THREAT & SCANNER FEED STATUS\n")
			fmt.Printf("  Mode:                %s\n", st.Config.Mode)
			fmt.Printf("  CISA KEV URL:        %s (Poll: %s)\n", st.Config.CISAKEVURL, st.Config.KEVPollInterval)
			fmt.Printf("  CISA KEV Catalog:    %d CVEs (Version: %s)\n", st.CISAKEVCatalogCount, st.LatestCatalogVersion)
			fmt.Printf("  Google OSV URL:      %s (%d SBOM Advisories)\n", st.Config.OSVAPIURL, len(st.OSVAdvisories))
			fmt.Printf("  Trivy Sidecar:       %t\n", st.Config.TrivyEnabled)
		case "mode":
			if len(os.Args) < 4 {
				printUsage()
				os.Exit(1)
			}
			var st models.LiveFeedStatus
			mustGetJSON(client, baseURL+"/api/v1/feeds/status", &st)
			st.Config.Mode = os.Args[3]
			var out models.FeedRuntimeConfig
			mustPostJSON(client, baseURL+"/api/v1/feeds/config", st.Config, &out)
			fmt.Printf("Feed runtime mode updated to: %s\n", out.Mode)
		case "sync-kev":
			var run models.FeedSyncRun
			mustPostJSON(client, baseURL+"/api/v1/feeds/sync/kev", map[string]any{}, &run)
			fmt.Printf("CISA KEV Sync %s: catalog=%s ingested=%d kev_matches=%d typed_sha256=%s\n",
				run.Status, run.CatalogVersion, run.ItemsIngested, run.KEVMatches, run.TypedOutputSHA256)
		case "sync-osv":
			var out map[string]any
			mustPostJSON(client, baseURL+"/api/v1/feeds/sync/osv", map[string]any{}, &out)
			raw, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(raw))
		default:
			printUsage()
			os.Exit(1)
		}

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`G1-Warrant CLI (warrant) — G1163RT Security Labs, Inc.
Usage:
  warrant status
  warrant warrants [list | verify <warrant-id>]
  warrant pipeline [list | trace <remediation-id>]
  warrant estate list
  warrant feeds [status | mode <offline|live> | sync-kev | sync-osv]
  warrant freeze [hold | rollback] --actor <id> --reason <code>
  warrant freeze thaw
  warrant intake sarif <path-to-sarif.json>
  warrant ledger verify
  warrant oscal export <attestation-or-remediation-id> [output.json]`)
}

func argOrDefault(args []string, idx int, def string) string {
	if len(args) > idx {
		return args[idx]
	}
	return def
}

func mustGetJSON(c *http.Client, url string, dst any) {
	resp, err := c.Get(url)
	if err != nil {
		fatalf("GET %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		fatalf("GET %s returned HTTP %d: %s", url, resp.StatusCode, string(body))
	}
	if err := json.Unmarshal(body, dst); err != nil {
		fatalf("decode %s: %v", url, err)
	}
}

func mustPostJSON(c *http.Client, url string, reqBody any, dst any) {
	raw, _ := json.Marshal(reqBody)
	resp, err := c.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		fatalf("POST %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		fatalf("POST %s returned HTTP %d: %s", url, resp.StatusCode, string(body))
	}
	if dst != nil {
		if err := json.Unmarshal(body, dst); err != nil {
			fatalf("decode %s: %v", url, err)
		}
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
