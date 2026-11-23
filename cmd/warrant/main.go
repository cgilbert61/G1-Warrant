package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/cgilbert61/G1-Warrant/pkg/warrantsdk"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	baseURL := strings.TrimRight(os.Getenv("WARRANT_API_URL"), "/")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	opToken := strings.TrimSpace(os.Getenv("WARRANT_OPERATOR_TOKEN"))
	autoToken := strings.TrimSpace(os.Getenv("WARRANT_AUTOMATION_TOKEN"))
	inToken := strings.TrimSpace(os.Getenv("WARRANT_INTAKE_TOKEN"))
	globalSignerPath := strings.TrimSpace(os.Getenv("WARRANT_SIGNER_KEY"))
	jsonOutput := false

	// Extract global leading/trailing flags (--url, --json, --operator-token, --automation-token, --signer-key) while preserving positional args
	args := make([]string, 0, len(os.Args)-1)
	rawArgs := os.Args[1:]
	for i := 0; i < len(rawArgs); i++ {
		a := rawArgs[i]
		switch {
		case a == "--json":
			jsonOutput = true
		case a == "--url" && i+1 < len(rawArgs):
			baseURL = strings.TrimRight(rawArgs[i+1], "/")
			i++
		case strings.HasPrefix(a, "--url="):
			baseURL = strings.TrimRight(strings.TrimPrefix(a, "--url="), "/")
		case a == "--operator-token" && i+1 < len(rawArgs):
			opToken = strings.TrimSpace(rawArgs[i+1])
			i++
		case strings.HasPrefix(a, "--operator-token="):
			opToken = strings.TrimSpace(strings.TrimPrefix(a, "--operator-token="))
		case a == "--automation-token" && i+1 < len(rawArgs):
			autoToken = strings.TrimSpace(rawArgs[i+1])
			i++
		case strings.HasPrefix(a, "--automation-token="):
			autoToken = strings.TrimSpace(strings.TrimPrefix(a, "--automation-token="))
		case a == "--signer-key" && i+1 < len(rawArgs):
			globalSignerPath = strings.TrimSpace(rawArgs[i+1])
			i++
		case strings.HasPrefix(a, "--signer-key="):
			globalSignerPath = strings.TrimSpace(strings.TrimPrefix(a, "--signer-key="))
		case a == "-h" || a == "--help" || a == "help":
			printUsage()
			return
		case a == "version" || a == "--version":
			fmt.Printf("warrant CLI v%s (G1163RT Security Labs, Inc.)\n", warrantsdk.Version)
			return
		default:
			args = append(args, a)
		}
	}

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	clientOpts := []warrantsdk.Option{}
	if opToken != "" {
		clientOpts = append(clientOpts, warrantsdk.WithOperatorToken(opToken))
	}
	if autoToken != "" {
		clientOpts = append(clientOpts, warrantsdk.WithAutomationToken(autoToken))
	}
	if inToken != "" {
		clientOpts = append(clientOpts, warrantsdk.WithIntakeToken(inToken))
	}
	if globalSignerPath != "" {
		sb, sErr := loadPrivateSignerFile(globalSignerPath)
		must(sErr)
		clientOpts = append(clientOpts, warrantsdk.WithSignerBundle(sb))
	}
	cli := warrantsdk.NewClient(baseURL, clientOpts...)
	cmd := args[0]

	switch cmd {
	case "status":
		sb, err := cli.Scoreboard(ctx)
		must(err)
		if jsonOutput {
			printJSON(sb)
			return
		}
		fmt.Printf("G1-WARRANT CONTROL PLANE STATUS (%s)\n", cli.BaseURL())
		fmt.Printf("  Posture:               %s (Actor: %s | Reason: %s)\n", sb.FreezeState.Mode, sb.FreezeState.Actor, sb.FreezeState.ReasonCode)
		fmt.Printf("  Active Warrants:       %d\n", sb.ActiveWarrantsCount)
		fmt.Printf("  30d Fleet Median TTVR: %ds\n", sb.FleetMedianTTVRSeconds)
		fmt.Printf("  Active Bridges Armed:  %d (Median Age: %ds)\n", sb.ActiveBridgesArmed, sb.MedianBridgeAgeSeconds)
		fmt.Printf("  Estate Eligibility:    %.1f%% (%d/%d services)\n", sb.AutonomousEligibilityPct, sb.EligibleServicesCount, sb.TotalServicesCount)
		fmt.Printf("  Awaiting Dual-Key:     %d\n", sb.AwaitingDualKeyInboxCount)
		fmt.Printf("  Drift Violations:      %d\n", sb.ActiveDriftViolationsCount)
		fmt.Printf("  Rollback Failures:     %d\n", sb.RollbackFailuresCount)

	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		id := fs.String("id", "usr-operator-so", "Principal ID")
		email := fs.String("email", "so@agency.gov", "Principal institutional email")
		name := fs.String("name", "Service Owner", "Display name")
		role := fs.String("role", warrantsdk.RoleServiceOwner, "AC-5 role: SERVICE_OWNER or AUTHORIZING_OFFICIAL")
		outPrefix := fs.String("out", "", "Output prefix (writes <name>.priv.json [0600] and <name>.pub.json [0644])")
		_ = fs.Parse(args[1:])

		bundle, err := warrantsdk.GenerateEd25519SignerBundle(*id, *email, *name, *role)
		must(err)
		if *outPrefix != "" {
			privPath, pubPath, wErr := warrantsdk.WriteSplitKeyPairFiles(*outPrefix, bundle)
			must(wErr)
			fmt.Printf("Generated split Ed25519 AC-5 keypair (%s | key_id=%s):\n  Private Signing Key (0600): %s\n  Public Identity   (0644): %s\n",
				bundle.Role, bundle.KeyID, privPath, pubPath)
			return
		}
		raw, _ := json.MarshalIndent(bundle.ToPublicIdentity(), "", "  ")
		fmt.Println(string(raw))

	case "principals":
		sub := argOrDefault(args, 1, "list")
		switch sub {
		case "list":
			list, err := cli.ListPrincipals(ctx)
			must(err)
			if jsonOutput {
				printJSON(list)
				return
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "PRINCIPAL_ID\tROLE\tMODE\tREVOKED\tKEY_ID\tEMAIL")
			for _, p := range list {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%t\t%s\t%s\n",
					p.PrincipalID, p.Role, p.AuthenticatorMode, p.Revoked, p.KeyID, p.Email)
			}
			_ = tw.Flush()
		case "register":
			fs := flag.NewFlagSet("principals register", flag.ExitOnError)
			pubFile := fs.String("pub", "", "Path to <name>.pub.json public identity file (private keys rejected)")
			adminTok := fs.String("admin-token", os.Getenv("WARRANT_BOOTSTRAP_ADMIN_TOKEN"), "One-shot genesis bootstrap token (before seal)")
			slot1Key := fs.String("slot1-key", "", "Post-seal Slot 1 (SERVICE_OWNER) .priv.json for 2-of-2 DSSE enrollment")
			slot2Key := fs.String("slot2-key", "", "Post-seal Slot 2 (AUTHORIZING_OFFICIAL) .priv.json for 2-of-2 DSSE enrollment")
			_ = fs.Parse(args[2:])
			if *pubFile == "" {
				fatalf("--pub <name.pub.json> is required (never pass a private-key file to network registration)")
			}
			pb, pErr := os.ReadFile(*pubFile)
			must(pErr)
			pubBundle, bErr := warrantsdk.LoadPublicIdentityFile(pb)
			must(bErr)

			var enrolled *warrantsdk.Principal
			if *slot1Key != "" || *slot2Key != "" {
				if *slot1Key == "" || *slot2Key == "" {
					fatalf("both --slot1-key <so.priv.json> and --slot2-key <ao.priv.json> are required for post-seal 2-of-2 DSSE enrollment")
				}
				s1, err1 := loadPrivateSignerFile(*slot1Key)
				must(err1)
				s2, err2 := loadPrivateSignerFile(*slot2Key)
				must(err2)
				env, _, dErr := warrantsdk.DraftPrincipalEnrollEnvelope(pubBundle.ToRegisterRequest(), 5*time.Minute)
				must(dErr)
				must(s1.SignEnvelope(1, env))
				must(s2.SignEnvelope(2, env))
				var rErr error
				enrolled, rErr = cli.RegisterPrincipalDualSigned(ctx, *env)
				must(rErr)
			} else {
				if strings.TrimSpace(*adminTok) == "" {
					fatalf("--admin-token (genesis unsealed) OR --slot1-key + --slot2-key (2-of-2 DSSE) is required")
				}
				adminCli := warrantsdk.NewClient(baseURL, warrantsdk.WithAdminToken(*adminTok))
				var rErr error
				enrolled, rErr = adminCli.RegisterPrincipal(ctx, pubBundle.ToRegisterRequest())
				must(rErr)
			}
			if jsonOutput {
				printJSON(enrolled)
				return
			}
			fmt.Printf("Enrolled AC-5 Principal %s (%s | %s | key_id=%s)\n",
				enrolled.PrincipalID, enrolled.Role, enrolled.Email, enrolled.KeyID)
		case "seal":
			fs := flag.NewFlagSet("principals seal", flag.ExitOnError)
			adminTok := fs.String("admin-token", os.Getenv("WARRANT_BOOTSTRAP_ADMIN_TOKEN"), "Genesis bootstrap admin token")
			keyFile := fs.String("key", globalSignerPath, "Active principal .priv.json key to sign SEAL_BOOTSTRAP DSSE")
			_ = fs.Parse(args[2:])
			var st *warrantsdk.BootstrapState
			if strings.TrimSpace(*keyFile) != "" {
				signer, sErr := loadPrivateSignerFile(*keyFile)
				must(sErr)
				sealCli := warrantsdk.NewClient(baseURL, warrantsdk.WithSignerBundle(signer))
				var err error
				st, err = sealCli.SealBootstrap(ctx)
				must(err)
			} else {
				if strings.TrimSpace(*adminTok) == "" {
					fatalf("--admin-token or --key <active.priv.json> is required to seal genesis bootstrap")
				}
				sealCli := warrantsdk.NewClient(baseURL, warrantsdk.WithAdminToken(*adminTok))
				var err error
				st, err = sealCli.SealBootstrap(ctx)
				must(err)
			}
			if jsonOutput {
				printJSON(st)
				return
			}
			fmt.Printf("Genesis Bootstrap Sealed: sealed=%t by=%s reason=%s\n", st.Sealed, st.SealedBy, st.SealedReason)
		case "revoke":
			fs := flag.NewFlagSet("principals revoke", flag.ExitOnError)
			pid := fs.String("principal", "", "Target Principal ID to revoke")
			fp := fs.String("fingerprint", "", "Optional target SHA-256 key fingerprint")
			reason := fs.String("reason", "CLI_KEY_REVOCATION", "Revocation reason code")
			keyFile := fs.String("key", globalSignerPath, "Self .priv.json signing 1-of-2 self-revocation REVOKE_PRINCIPAL DSSE")
			slot1Key := fs.String("slot1-key", "", "Slot 1 (SERVICE_OWNER) .priv.json for 2-of-2 peer revocation")
			slot2Key := fs.String("slot2-key", "", "Slot 2 (AUTHORIZING_OFFICIAL) .priv.json for 2-of-2 peer revocation")
			_ = fs.Parse(args[2:])
			if *pid == "" && *fp == "" {
				fatalf("--principal or --fingerprint is required")
			}
			if *slot1Key != "" || *slot2Key != "" {
				if *slot1Key == "" || *slot2Key == "" {
					fatalf("both --slot1-key <so.priv.json> and --slot2-key <ao.priv.json> are required for 2-of-2 peer revocation")
				}
				s1, err1 := loadPrivateSignerFile(*slot1Key)
				must(err1)
				s2, err2 := loadPrivateSignerFile(*slot2Key)
				must(err2)
				env, _, dErr := warrantsdk.DraftPrincipalRevokeEnvelope(*pid, *fp, *reason, 5*time.Minute)
				must(dErr)
				must(s1.SignEnvelope(1, env))
				must(s2.SignEnvelope(2, env))
				rev, rErr := cli.RevokePrincipalSigned(ctx, *env)
				must(rErr)
				printJSON(rev)
				return
			}
			if strings.TrimSpace(*keyFile) == "" {
				fatalf("--key <self.priv.json> (1-of-2 self-revocation) OR --slot1-key + --slot2-key (2-of-2 peer revocation) is required")
			}
			signer, sErr := loadPrivateSignerFile(*keyFile)
			must(sErr)
			revCli := warrantsdk.NewClient(baseURL, warrantsdk.WithSignerBundle(signer))
			rev, err := revCli.RevokePrincipal(ctx, warrantsdk.RevokePrincipalRequest{
				PrincipalID:    *pid,
				KeyFingerprint: *fp,
				ReasonCode:     *reason,
			})
			must(err)
			printJSON(rev)
		case "rotate-and-revoke":
			fs := flag.NewFlagSet("principals rotate-and-revoke", flag.ExitOnError)
			pubFile := fs.String("pub", "", "Path to replacement <name>.pub.json public identity file")
			targetID := fs.String("principal", "", "Target Principal ID to revoke atomically")
			targetFP := fs.String("fingerprint", "", "Optional target SHA-256 key fingerprint to revoke")
			reason := fs.String("reason", "CLI_ATOMIC_ROTATE_AND_REVOKE", "Rotation/revocation reason code")
			slot1Key := fs.String("slot1-key", "", "Slot 1 (SERVICE_OWNER) .priv.json")
			slot2Key := fs.String("slot2-key", "", "Slot 2 (AUTHORIZING_OFFICIAL) .priv.json")
			_ = fs.Parse(args[2:])
			if *pubFile == "" || (*targetID == "" && *targetFP == "") || *slot1Key == "" || *slot2Key == "" {
				fatalf("--pub <new.pub.json>, --principal <target-id>, --slot1-key <so.priv.json>, and --slot2-key <ao.priv.json> are required")
			}
			pb, pErr := os.ReadFile(*pubFile)
			must(pErr)
			pubBundle, bErr := warrantsdk.LoadPublicIdentityFile(pb)
			must(bErr)
			s1, err1 := loadPrivateSignerFile(*slot1Key)
			must(err1)
			s2, err2 := loadPrivateSignerFile(*slot2Key)
			must(err2)
			env, _, dErr := warrantsdk.DraftPrincipalRotateAndRevokeEnvelope(pubBundle.ToRegisterRequest(), *targetID, *targetFP, *reason, 5*time.Minute)
			must(dErr)
			must(s1.SignEnvelope(1, env))
			must(s2.SignEnvelope(2, env))
			rotRes, rErr := cli.RotateAndRevokePrincipal(ctx, *env)
			must(rErr)
			printJSON(rotRes)
		default:
			printUsage()
			os.Exit(1)
		}

	case "warrants":
		sub := argOrDefault(args, 1, "list")
		switch sub {
		case "list":
			list, err := cli.ListWarrants(ctx)
			must(err)
			if jsonOutput {
				printJSON(list)
				return
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "WARRANT_ID\tCLASS\tSTATUS\tSLOT1_SO\tSLOT2_AO\tMAX_CVSS\tEXPIRES_AT")
			for _, w := range list {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%.1f\t%s\n",
					w.WarrantID, w.WarrantClass, w.LiveStatus, w.Slot1PrincipalID, w.Slot2PrincipalID, w.MaxCVSS, w.ExpiresAt.Format(time.RFC3339))
			}
			_ = tw.Flush()

		case "verify":
			if len(args) < 3 {
				fatalf("usage: warrant warrants verify <warrant-id>")
			}
			res, err := cli.VerifyWarrant(ctx, args[2])
			must(err)
			printJSON(res)
			if !res.Valid {
				os.Exit(2)
			}

		case "draft":
			fs := flag.NewFlagSet("warrants draft", flag.ExitOnError)
			wClass := fs.String("class", "KEV-TIER1-STATELESS", "Warrant class (e.g. KEV-TIER1-STATELESS, SECRET-ROTATION-STATELESS)")
			services := fs.String("services", "payments-ledger-api,identity-sso-gateway", "Comma-separated service IDs")
			maxCVSS := fs.Float64("max-cvss", 10.0, "Maximum CVSS ceiling")
			maxRep := fs.Int("max-replicas", 8, "Maximum replica blast radius")
			slaMin := fs.Int("sla-minutes", 60, "Containment bridge SLA in minutes")
			maxP99 := fs.Float64("max-p99-ms", 120.0, "Canary max p99 latency in ms")
			ttlDays := fs.Int("ttl-days", 30, "Hard expiration in days")
			allowSecRot := fs.Bool("allow-secret-rotation", false, "Authorize stateless secret/token rotation under this warrant")
			autoCWEs := fs.String("auto-cwes", "", "Optional comma-separated attack-path CWEs (e.g. CWE-209,CWE-918,CWE-434)")
			scopeAssets := fs.String("assets", "", "Optional comma-separated WN-8 target asset keys (defaults to scope_services)")
			vendorDetections := fs.String("vendor-detections", "", "Optional comma-separated WN-7 unmapped vendor detection IDs (e.g. QID-99101)")
			outFile := fs.String("out", "warrant-draft.dsse.json", "Output DSSE draft file")
			_ = fs.Parse(args[2:])

			svcList := splitCSV(*services)
			cweList := splitCSV(*autoCWEs)
			assetList := splitCSV(*scopeAssets)
			detList := splitCSV(*vendorDetections)
			env, payload, err := warrantsdk.DraftWarrantEnvelope(warrantsdk.WarrantDraftOptions{
				WarrantClass:               *wClass,
				ScopeServices:              svcList,
				ScopeAssets:                assetList,
				AuthorizedVendorDetections: detList,
				MaxCVSS:                    *maxCVSS,
				KEVEligible:            true,
				MaxBlastRadiusReplicas: *maxRep,
				AllowSecretRotation:    *allowSecRot,
				AutoRemediateCWEs:      cweList,
				SLABridgeMinutes:       *slaMin,
				MaxP99LatencyMs:        *maxP99,
				TTLDays:                *ttlDays,
			})
			must(err)
			raw, _ := json.MarshalIndent(env, "", "  ")
			must(os.WriteFile(*outFile, raw, 0600))
			fmt.Printf("Drafted unsigned DSSEv1 Standing Warrant (%s) -> %s\n", payload.WarrantID, *outFile)

		case "sign":
			fs := flag.NewFlagSet("warrants sign", flag.ExitOnError)
			inFile := fs.String("in", "warrant-draft.dsse.json", "Input DSSE envelope JSON")
			outFile := fs.String("out", "", "Output DSSE envelope JSON (defaults to --in)")
			slot := fs.Int("slot", 1, "AC-5 signature slot: 1 (SERVICE_OWNER) or 2 (AUTHORIZING_OFFICIAL)")
			keyFile := fs.String("key", "", "Path to SignerKeyBundle JSON")
			_ = fs.Parse(args[2:])

			if *keyFile == "" {
				fatalf("--key <bundle.json> is required (demo signers are prohibited in production CLIs)")
			}
			rawEnv, err := os.ReadFile(*inFile)
			must(err)
			var env warrantsdk.Envelope
			must(json.Unmarshal(rawEnv, &env))

			kb, kErr := os.ReadFile(*keyFile)
			must(kErr)
			signer, err := warrantsdk.LoadSignerBundleFile(kb)
			must(err)

			must(signer.SignEnvelope(*slot, &env))
			dest := *outFile
			if dest == "" {
				dest = *inFile
			}
			outBytes, _ := json.MarshalIndent(env, "", "  ")
			must(os.WriteFile(dest, outBytes, 0600))
			fmt.Printf("Appended Slot %d (%s | %s) Ed25519 signature -> %s (%d total signatures)\n",
				*slot, signer.Role, signer.PrincipalID, dest, len(env.Signatures))

		case "submit":
			if len(args) < 3 {
				fatalf("usage: warrant warrants submit <signed-warrant.dsse.json>")
			}
			rawEnv, err := os.ReadFile(args[2])
			must(err)
			var env warrantsdk.Envelope
			must(json.Unmarshal(rawEnv, &env))
			rec, err := cli.CreateWarrant(ctx, env)
			must(err)
			if jsonOutput {
				printJSON(rec)
				return
			}
			fmt.Printf("Minted Standing Warrant %s (%s) — Status: %s | EntryHash: %s\n",
				rec.WarrantID, rec.WarrantClass, rec.LiveStatus, rec.EntryHash)

		default:
			printUsage()
			os.Exit(1)
		}

	case "exceptions":
		sub := argOrDefault(args, 1, "list")
		switch sub {
		case "list":
			list, err := cli.ListExceptions(ctx)
			must(err)
			if jsonOutput {
				printJSON(list)
				return
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "EXCEPTION_ID\tREMEDIATION\tSERVICE\tCVE\tTRIGGER\tSTATUS")
			for _, ex := range list {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
					ex.ExceptionID, ex.RemediationID, ex.ServiceID, ex.CVEID, ex.TriggerCode, ex.Status)
			}
			_ = tw.Flush()

		case "approve", "reject":
			if len(args) < 3 {
				fatalf("usage: warrant exceptions [approve|reject] <exception-id> --slot1-key <so.json> --slot2-key <ao.json>")
			}
			exID := args[2]
			fs := flag.NewFlagSet("exceptions resolve", flag.ExitOnError)
			slot1Key := fs.String("slot1-key", "", "Path to Slot 1 (SERVICE_OWNER) SignerKeyBundle JSON")
			slot2Key := fs.String("slot2-key", "", "Path to Slot 2 (AUTHORIZING_OFFICIAL) SignerKeyBundle JSON")
			if len(args) > 3 {
				_ = fs.Parse(args[3:])
			}
			if *slot1Key == "" || *slot2Key == "" {
				fatalf("--slot1-key <so.json> and --slot2-key <ao.json> are required for 2-of-2 Four-Eyes resolution")
			}
			decision := "APPROVED"
			if sub == "reject" {
				decision = "REJECTED"
			}
			list, err := cli.ListExceptions(ctx)
			must(err)
			var target *warrantsdk.CeilingException
			for _, item := range list {
				if item.ExceptionID == exID {
					cp := item
					target = &cp
					break
				}
			}
			if target == nil {
				fatalf("exception %q not found", exID)
			}
			env, err := warrantsdk.DraftExceptionResolutionEnvelope(*target)
			must(err)
			s1Raw, err := os.ReadFile(*slot1Key)
			must(err)
			s2Raw, err := os.ReadFile(*slot2Key)
			must(err)
			s1, err := warrantsdk.LoadSignerBundleFile(s1Raw)
			must(err)
			s2, err := warrantsdk.LoadSignerBundleFile(s2Raw)
			must(err)
			must(s1.SignEnvelope(1, env))
			must(s2.SignEnvelope(2, env))
			resolved, rem, err := cli.ResolveException(ctx, exID, decision, *env)
			must(err)
			printJSON(map[string]any{"exception": resolved, "remediation": rem})

		default:
			printUsage()
			os.Exit(1)
		}

	case "pipeline":
		sub := argOrDefault(args, 1, "list")
		switch sub {
		case "list":
			list, err := cli.ListPipeline(ctx)
			must(err)
			if jsonOutput {
				printJSON(list)
				return
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "REMEDIATION_ID\tCVE\tKEV\tSERVICE\tSTAGE\tHEALTH\tCANARY\tLOCKOUT")
			for _, r := range list {
				fmt.Fprintf(tw, "%s\t%s\t%t\t%s\t%s\t%s\t%d%%\t%s\n",
					r.RemediationID, r.CVEID, r.IsKEV, r.ServiceID, r.Stage, r.StatusHealth, r.CanaryWeight, r.LockoutPolicyID)
			}
			_ = tw.Flush()
		case "trace":
			if len(args) < 3 {
				fatalf("usage: warrant pipeline trace <remediation-id>")
			}
			traces, err := cli.ListTraces(ctx, args[2])
			must(err)
			if jsonOutput {
				printJSON(traces)
				return
			}
			for _, t := range traces {
				fmt.Printf("[%s] %-7s %-36s %-9s actor=%s hash=%s\n",
					t.OccurredAt.Format("15:04:05.000"), t.Engine, t.StepCode, t.Outcome, t.ActorOrToken, t.EvidenceHash[:16])
			}
		case "rollback":
			if len(args) < 3 {
				fatalf("usage: warrant pipeline rollback <remediation-id> [--key <active.priv.json>] [--reason <code>]")
			}
			remID := args[2]
			fs := flag.NewFlagSet("pipeline rollback", flag.ExitOnError)
			actor := fs.String("actor", "cli-incident-commander", "Actor label")
			reason := fs.String("reason", "POST_PROMOTION_REGRESSION", "Rollback reason")
			keyFile := fs.String("key", globalSignerPath, "Active principal .priv.json signing 1-of-2 EMERGENCY_ROLLBACK DSSE")
			if len(args) > 3 {
				_ = fs.Parse(args[3:])
			}
			rbCli := cli
			if strings.TrimSpace(*keyFile) != "" {
				signer, sErr := loadPrivateSignerFile(*keyFile)
				must(sErr)
				rbCli = warrantsdk.NewClient(baseURL, warrantsdk.WithSignerBundle(signer), warrantsdk.WithOperatorToken(opToken))
			}
			rem, err := rbCli.EmergencyRollback(ctx, remID, *actor, *reason)
			must(err)
			printJSON(rem)
		default:
			printUsage()
			os.Exit(1)
		}

	case "estate":
		list, err := cli.ListEstate(ctx)
		must(err)
		if jsonOutput {
			printJSON(list)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SERVICE_ID\tTIER\tELIGIBLE\tCOVERAGE\tOTEL\tSHADOW_RO\tROLLBACK_OK")
		for _, s := range list {
			fmt.Fprintf(tw, "%s\t%s\t%t\t%.1f%%\t%t\t%t\t%t\n",
				s.ServiceID, s.Tier, s.Eligible, s.TestCoveragePct, s.OtelHealthProbes, s.ReadonlyShadowReplica, s.RollbackAutomationVerified)
		}
		_ = tw.Flush()

	case "shadow":
		runs, err := cli.ListShadowRuns(ctx)
		must(err)
		if jsonOutput {
			printJSON(runs)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "RUN_ID\tREMEDIATION\tSERVICE\tSTAGE\tPASSED\tP99_MS\tSCHEMA_DIFFS\tFAILURE")
		for _, r := range runs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d%%\t%t\t%.1fms\t%d\t%s\n",
				r.RunID, r.RemediationID, r.ServiceID, r.StageWeight, r.Passed, r.CanaryLatency.P99Ms, r.SchemaBreakingDiffs, r.FailureCode)
		}
		_ = tw.Flush()

	case "bridges":
		list, err := cli.ListBridges(ctx)
		must(err)
		if jsonOutput {
			printJSON(list)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "BRIDGE_ID\tSERVICE\tCVE\tTYPE\tSTATUS\tSLA_MIN\tREARMED")
		for _, b := range list {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%dm\t%d\n",
				b.BridgeID, b.ServiceID, b.CVEID, b.BridgeType, b.Status, b.SLABridgeMinutes, b.RearmedCount)
		}
		_ = tw.Flush()

	case "lockouts":
		list, err := cli.ListLockouts(ctx)
		must(err)
		if jsonOutput {
			printJSON(list)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "LOCKOUT_ID\tSERVICE\tCVE\tPOLICY_NAME\tDRIFT_COUNT\tENFORCED_AT")
		for _, l := range list {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n",
				l.LockoutID, l.ServiceID, l.CVEID, l.PolicyName, l.DriftCount, l.EnforcedAt.Format(time.RFC3339))
		}
		_ = tw.Flush()

	case "drift":
		list, err := cli.ListDriftIncidents(ctx)
		must(err)
		if jsonOutput {
			printJSON(list)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "INCIDENT_ID\tSERVICE\tCVE\tROGUE_POD\tLATENCY_MS\tREARMED_BRIDGE")
		for _, d := range list {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%dms\t%s\n",
				d.IncidentID, d.ServiceID, d.CVEID, d.RoguePodName, d.DetectionLatencyMs, d.RearmedBridgeID)
		}
		_ = tw.Flush()

	case "simulate":
		if len(args) < 2 {
			fatalf("usage: warrant simulate [inject-kev | bad-syscall | stateful-ddl | runtime-drift | secret-exposure | in-pod-webshell | poisoned-config]")
		}
		res, err := cli.SimulateScenario(ctx, args[1])
		must(err)
		printJSON(res)

	case "freeze":
		sub := argOrDefault(args, 1, "")
		fs := flag.NewFlagSet("freeze", flag.ExitOnError)
		actor := fs.String("actor", "cli-operator", "Actor label")
		reason := fs.String("reason", "CLI_EMERGENCY_ACTION", "Reason code")
		keyFile := fs.String("key", globalSignerPath, "Active principal .priv.json signing 1-of-2 EMERGENCY_FREEZE DSSE")
		slot1Key := fs.String("slot1-key", "", "Slot 1 (SERVICE_OWNER) .priv.json for thaw")
		slot2Key := fs.String("slot2-key", "", "Slot 2 (AUTHORIZING_OFFICIAL) .priv.json for thaw")
		envFile := fs.String("envelope", "", "Optional pre-signed 2-of-2 DSSE Thaw envelope JSON")
		if len(args) > 2 {
			_ = fs.Parse(args[2:])
		}
		switch sub {
		case "hold", "rollback":
			mode := warrantsdk.FreezeModeHold
			if sub == "rollback" {
				mode = warrantsdk.FreezeModeRollback
			}
			frCli := cli
			if strings.TrimSpace(*keyFile) != "" {
				signer, sErr := loadPrivateSignerFile(*keyFile)
				must(sErr)
				frCli = warrantsdk.NewClient(baseURL, warrantsdk.WithSignerBundle(signer), warrantsdk.WithOperatorToken(opToken))
			}
			out, err := frCli.TriggerFreeze(ctx, mode, *actor, *reason)
			must(err)
			if jsonOutput {
				printJSON(out)
				return
			}
			fmt.Printf("Emergency Freeze Activated: %s by %s at %s\n", out.Mode, out.Actor, out.UpdatedAt.Format(time.RFC3339))
		case "thaw":
			var thawEnv warrantsdk.Envelope
			if *envFile != "" {
				raw, rErr := os.ReadFile(*envFile)
				must(rErr)
				must(json.Unmarshal(raw, &thawEnv))
			} else {
				if *slot1Key == "" || *slot2Key == "" {
					fatalf("usage: warrant freeze thaw --slot1-key <so.json> --slot2-key <ao.json> (or --envelope <signed.dsse.json>)")
				}
				epoch := int64(2)
				if sb, sbErr := cli.Scoreboard(ctx); sbErr == nil && sb.FreezeState.FreezeEpoch > 0 {
					epoch = sb.FreezeState.FreezeEpoch
				}
				draft, dErr := warrantsdk.DraftThawEnvelopeForEpoch(epoch)
				must(dErr)
				s1Raw, rErr1 := os.ReadFile(*slot1Key)
				must(rErr1)
				s2Raw, rErr2 := os.ReadFile(*slot2Key)
				must(rErr2)
				s1, lErr1 := warrantsdk.LoadSignerBundleFile(s1Raw)
				must(lErr1)
				s2, lErr2 := warrantsdk.LoadSignerBundleFile(s2Raw)
				must(lErr2)
				must(s1.SignEnvelope(1, draft))
				must(s2.SignEnvelope(2, draft))
				thawEnv = *draft
			}
			out, err := cli.ThawFreeze(ctx, thawEnv)
			must(err)
			if jsonOutput {
				printJSON(out)
				return
			}
			fmt.Printf("Fleet Thawed via 2-of-2 DSSE Ceremony: %s (%s)\n", out.Mode, out.Actor)
		default:
			printUsage()
			os.Exit(1)
		}

	case "intake":
		if len(args) < 3 {
			fatalf("usage: warrant intake [sarif|secrets|qualys|tenable|rapid7] <path-to-report> [--service <id>] [--distributor <id>] [--profile <name>]")
		}
		subIntake := strings.ToLower(strings.TrimSpace(args[1]))
		reportPath := args[2]
		fs := flag.NewFlagSet("intake", flag.ExitOnError)
		svc := fs.String("service", "", "Optional target service override")
		distID := fs.String("distributor", "", "Optional WN-8 distributor translator ID (e.g. ms-intune, ansible-awx, aws-ssm)")
		profile := fs.String("profile", "", "Optional patch profile (STATELESS_CLEAN, STATEFUL_DDL, BAD_SYSCALL_EXECVE, POISONED_BUILD_CONFIG)")
		maxFindings := fs.Int("max-findings", 0, "Optional maximum findings to ingest")
		if len(args) > 3 {
			_ = fs.Parse(args[3:])
		}
		raw, err := os.ReadFile(reportPath)
		must(err)
		switch subIntake {
		case "secrets":
			items, sErr := cli.IngestSecretScan(ctx, raw, *svc)
			must(sErr)
			printJSON(items)
		case "sarif":
			items, sErr := cli.IngestSARIF(ctx, raw, warrantsdk.SARIFIntakeOptions{
				Profile:       *profile,
				TargetService: *svc,
				MaxFindings:   *maxFindings,
			})
			must(sErr)
			printJSON(items)
		case "qualys", "tenable", "rapid7":
			items, fErr := cli.SubmitFinderIntake(ctx, subIntake, raw, warrantsdk.FinderIntakeOptions{
				PatchProfile:  *profile,
				TargetService: *svc,
				DistributorID: *distID,
				MaxFindings:   *maxFindings,
			})
			must(fErr)
			printJSON(items)
		default:
			fatalf("usage: warrant intake [sarif|secrets|qualys|tenable|rapid7] <path-to-report> [--service <id>] [--distributor <id>] [--profile <name>]")
		}

	case "attestations":
		list, err := cli.ListAttestations(ctx)
		must(err)
		if jsonOutput {
			printJSON(list)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ATTESTATION_ID\tCVE\tKEV\tSERVICE\tWARRANT\tTTVR_SEC\tMINTED_AT")
		for _, a := range list {
			fmt.Fprintf(tw, "%s\t%s\t%t\t%s\t%s\t%ds\t%s\n",
				a.AttestationID, a.CVEID, a.IsKEV, a.ServiceID, a.WarrantID, a.TTVRSeconds, a.MintedAt.Format(time.RFC3339))
		}
		_ = tw.Flush()

	case "oscal":
		sub := argOrDefault(args, 1, "")
		switch sub {
		case "export":
			if len(args) < 3 {
				fatalf("usage: warrant oscal export <attestation-or-remediation-id> [output.json]")
			}
			body, err := cli.ExportOSCALBundle(ctx, args[2])
			must(err)
			if len(args) >= 4 {
				must(os.WriteFile(args[3], body, 0600))
				fmt.Printf("Wrote signed NIST OSCAL 1.1.2 POA&M bundle to %s\n", args[3])
			} else {
				fmt.Println(string(body))
			}

		case "verify-offline":
			if len(args) < 3 {
				fatalf("usage: warrant oscal verify-offline <bundle.json> [--pubkey <base64>]")
			}
			bundlePath := args[2]
			fs := flag.NewFlagSet("oscal verify-offline", flag.ExitOnError)
			pubKey := fs.String("pubkey", "", "Base64 Ed25519 kernel public key (auto-fetched from warrantd if omitted)")
			if len(args) > 3 {
				_ = fs.Parse(args[3:])
			}
			pkB64 := strings.TrimSpace(*pubKey)
			rawBundle, err := os.ReadFile(bundlePath)
			must(err)
			var res *warrantsdk.OfflineVerificationResult
			if pkB64 != "" {
				res, err = warrantsdk.VerifyOSCALBundleOffline(rawBundle, pkB64)
			} else {
				ring, rErr := cli.KernelPublicKeyRing(ctx)
				must(rErr)
				res, err = warrantsdk.VerifyOSCALBundleWithKeyRing(rawBundle, ring)
			}
			must(err)
			printJSON(res)

		default:
			printUsage()
			os.Exit(1)
		}

	case "auditor":
		sub := argOrDefault(args, 1, "")
		switch sub {
		case "mint-token":
			fs := flag.NewFlagSet("auditor mint-token", flag.ExitOnError)
			label := fs.String("label", "FedRAMP 3PAO Quarterly Review", "Engagement label")
			ttl := fs.Int("ttl-hours", 24, "Token TTL in hours")
			attIDs := fs.String("attestations", "", "Optional comma-separated attestation IDs (empty = all)")
			keyFile := fs.String("key", globalSignerPath, "Active principal .priv.json signing 1-of-2 MINT_AUDITOR_TOKEN DSSE")
			_ = fs.Parse(args[2:])
			var ids []string
			if strings.TrimSpace(*attIDs) != "" {
				ids = splitCSV(*attIDs)
			}
			audCli := cli
			if strings.TrimSpace(*keyFile) != "" {
				signer, sErr := loadPrivateSignerFile(*keyFile)
				must(sErr)
				audCli = warrantsdk.NewClient(baseURL, warrantsdk.WithSignerBundle(signer), warrantsdk.WithOperatorToken(opToken))
			}
			minted, err := audCli.MintAuditorToken(ctx, *label, ids, *ttl)
			must(err)
			printJSON(minted)

		case "inspect":
			fs := flag.NewFlagSet("auditor inspect", flag.ExitOnError)
			token := fs.String("token", os.Getenv("WARRANT_AUDITOR_TOKEN"), "Scoped g1aud_* bearer token")
			_ = fs.Parse(args[2:])
			if *token == "" {
				fatalf("--token <g1aud_...> (or WARRANT_AUDITOR_TOKEN) is required")
			}
			vault, err := cli.GetAuditorVault(ctx, *token)
			must(err)
			printJSON(vault)

		default:
			printUsage()
			os.Exit(1)
		}

	case "ledger":
		sub := argOrDefault(args, 1, "verify")
		switch sub {
		case "verify":
			rep, err := cli.VerifyLedgerChains(ctx)
			must(err)
			if jsonOutput {
				printJSON(rep)
			} else {
				fmt.Printf("LEDGER CRYPTOGRAPHIC CHAIN VERIFICATION: all_valid=%t (at %s)\n", rep.AllValid, rep.VerifiedAt.Format(time.RFC3339))
				for _, tbl := range rep.Tables {
					fmt.Printf("  - %-22s rows=%-4d valid=%-5t terminal_sha256=%s\n", tbl.TableName, tbl.RowCount, tbl.Valid, tbl.TerminalHash)
				}
			}
			if !rep.AllValid {
				os.Exit(2)
			}
		case "actions":
			list, err := cli.ListAgentActions(ctx)
			must(err)
			if jsonOutput {
				printJSON(list)
				return
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ACTION_ID\tWORKER\tACTION_TYPE\tTARGET\tEGRESS\tTTL\tSTATUS")
			for _, a := range list {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%ds\t%s\n",
					a.ActionID, a.WorkerName, a.ActionType, a.TargetAsset, a.EgressProfile, a.TokenTTLSec, a.Status)
			}
			_ = tw.Flush()
		case "checkpoints":
			list, err := cli.ListLedgerCheckpoints(ctx)
			must(err)
			printJSON(list)
		case "anchor":
			cp, err := cli.CreateLedgerCheckpoint(ctx)
			must(err)
			printJSON(cp)
		default:
			printUsage()
			os.Exit(1)
		}

	case "feeds":
		sub := argOrDefault(args, 1, "status")
		switch sub {
		case "status":
			st, err := cli.GetFeedStatus(ctx)
			must(err)
			if jsonOutput {
				printJSON(st)
				return
			}
			fmt.Printf("G1-WARRANT LIVE THREAT & SCANNER FEED STATUS\n")
			fmt.Printf("  Mode:                %s\n", st.Config.Mode)
			fmt.Printf("  CISA KEV URL:        %s (Poll: %s)\n", st.Config.CISAKEVURL, st.Config.KEVPollInterval)
			fmt.Printf("  CISA KEV Catalog:    %d CVEs (Version: %s)\n", st.CISAKEVCatalogCount, st.LatestCatalogVersion)
			fmt.Printf("  Google OSV URL:      %s (%d SBOM Advisories)\n", st.Config.OSVAPIURL, len(st.OSVAdvisories))
			fmt.Printf("  Trivy Sidecar:       %t\n", st.Config.TrivyEnabled)
		case "mode":
			if len(args) < 3 {
				fatalf("usage: warrant feeds mode <offline|live>")
			}
			st, err := cli.GetFeedStatus(ctx)
			must(err)
			st.Config.Mode = args[2]
			out, err := cli.UpdateFeedConfig(ctx, st.Config)
			must(err)
			fmt.Printf("Feed runtime mode updated to: %s\n", out.Mode)
		case "sync-kev":
			run, err := cli.SyncCISAKEV(ctx)
			must(err)
			if jsonOutput {
				printJSON(run)
				return
			}
			fmt.Printf("CISA KEV Sync %s: catalog=%s ingested=%d kev_matches=%d typed_sha256=%s\n",
				run.Status, run.CatalogVersion, run.ItemsIngested, run.KEVMatches, run.TypedOutputSHA256)
		case "sync-osv":
			out, err := cli.SyncOSV(ctx, false)
			must(err)
			printJSON(out)
		case "ingest-osv":
			if len(args) < 4 {
				fatalf("usage: warrant feeds ingest-osv <osv-id> <service-id>")
			}
			items, err := cli.IngestOSVAdvisory(ctx, args[2], args[3])
			must(err)
			printJSON(items)
		default:
			printUsage()
			os.Exit(1)
		}

	case "events":
		fmt.Fprintf(os.Stderr, "Streaming live SSE events from %s/api/v1/events/stream (Ctrl+C to stop)...\n", cli.BaseURL())
		err := cli.StreamEvents(ctx, func(ev warrantsdk.SSEEvent) error {
			fmt.Printf("[%s] event=%s data=%s\n", time.Now().UTC().Format("15:04:05.000"), ev.Event, string(ev.Data))
			return nil
		})
		if err != nil && ctx.Err() == nil {
			must(err)
		}

	case "functions":
		handleFunctionsCommand(ctx, cli, args, jsonOutput)

	case "agents":
		handleAgentsCommand(ctx, cli, args, jsonOutput)

	case "iga":
		handleIGACommand(ctx, cli, args, jsonOutput)

	case "distributors":
		handleDistributorsCommand(ctx, cli, baseURL, opToken, autoToken, globalSignerPath, args, jsonOutput)

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`G1-Warrant CLI (warrant v%s) — G1163RT Security Labs, Inc.
Global Flags:
  --url <http://host:8080>       Override WARRANT_API_URL (default: http://localhost:8080)
  --signer-key <name.priv.json>  Active principal key for 1-of-2 DSSE emergency/governance actions
  --operator-token <tok>         Optional WARRANT_OPERATOR_TOKEN for automated operator actions
  --json                         Emit machine-readable JSON output

Commands:
  warrant status
  warrant keygen --id <id> --email <email> --role <SERVICE_OWNER|AUTHORIZING_OFFICIAL> --out <prefix>
  warrant principals [list | register --pub <name.pub.json> [--admin-token <tok> | --slot1-key <so.priv.json> --slot2-key <ao.priv.json>] | seal | revoke --principal <id> --key <active.priv.json> | rotate-and-revoke --pub <new.pub.json> --principal <id> --slot1-key <so.priv.json> --slot2-key <ao.priv.json>]
  warrant functions [list | upsert --id <fn> --org <unit> --primary-so <so> --primary-ao <ao> --escalation <email> --slot1-key <so.priv.json> --slot2-key <ao.priv.json> | transfer ...]
  warrant agents [list | keygen --id <agt> --out <agt.json> | sign-provenance ... | enroll ... | recertify ... | revoke --agent <id> --key <priv.json> | token-exchange ...]
  warrant iga [list | emit --type <ROLE_TRANSFER|ORG_REORG|LEAVE_OF_ABSENCE|TERMINATION|KEY_COMPROMISE> --principal <id>]
  warrant warrants [list | verify <id> | draft | sign --key <name.priv.json> | submit <file.dsse.json>]
  warrant exceptions [list | approve <id> --slot1-key <so.priv.json> --slot2-key <ao.priv.json> | reject <id> ...]
  warrant pipeline [list | trace <remediation-id> | rollback <remediation-id> --key <active.priv.json>]
  warrant estate
  warrant shadow
  warrant bridges
  warrant lockouts
  warrant drift
  warrant simulate [inject-kev | bad-syscall | stateful-ddl | runtime-drift | secret-exposure | in-pod-webshell | poisoned-config]
  warrant intake [sarif|secrets|qualys|tenable|rapid7] <file> [--service <id>] [--distributor <id>] [--profile <STATELESS_CLEAN|STATEFUL_DDL|BAD_SYSCALL_EXECVE|POISONED_BUILD_CONFIG>]
  warrant distributors [list | orders [--remediation <id>] | results [--order <id>] | aliases | rollback <order-id> --key <active.priv.json> [--reason <code>]]
  warrant feeds [status | mode <offline|live> | sync-kev | sync-osv | ingest-osv <osv-id> <service-id>]
  warrant freeze [hold | rollback] --key <active.priv.json> [--reason <code>]
  warrant freeze thaw --slot1-key <so.priv.json> --slot2-key <ao.priv.json>
  warrant attestations
  warrant oscal [export <id> [out.json] | verify-offline <bundle.json> [--pubkey <b64>]]
  warrant auditor [mint-token --key <active.priv.json> --label <str> --ttl-hours <n> | inspect --token <g1aud_...>]
  warrant ledger [verify | actions | checkpoints | anchor]
  warrant events
`, warrantsdk.Version)
}

func loadPrivateSignerFile(path string) (*warrantsdk.SignerKeyBundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return warrantsdk.LoadSignerBundleFile(raw)
}

func argOrDefault(args []string, idx int, def string) string {
	if len(args) > idx {
		return args[idx]
	}
	return def
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func printJSON(v any) {
	raw, err := json.MarshalIndent(v, "", "  ")
	must(err)
	fmt.Println(string(raw))
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
