package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/cgilbert61/G1-Warrant/pkg/warrantsdk"
)

func handleFunctionsCommand(ctx context.Context, cli *warrantsdk.Client, args []string, jsonOutput bool) {
	sub := argOrDefault(args, 1, "list")
	switch sub {
	case "list":
		list, err := cli.ListCommissioningFunctions(ctx)
		must(err)
		if jsonOutput {
			printJSON(list)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "FUNCTION_ID\tORG_UNIT\tPRIMARY_SO\tPRIMARY_AO\tACTIVE_SO/AO\tGRACE_H\tCONTINUITY")
		for _, fn := range list {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d/%d\t%dh\t%s\n",
				fn.FunctionID, fn.OwningOrgUnit, fn.PrimarySOPrincipalID, fn.PrimaryAOPrincipalID,
				fn.ActiveSOCount, fn.ActiveAOCount, fn.OrphanGraceHours, fn.ContinuityStatus)
		}
		_ = tw.Flush()

	case "upsert", "transfer":
		fs := flag.NewFlagSet("functions-"+sub, flag.ExitOnError)
		fnID := fs.String("id", "", "CommissioningFunction ID (e.g., fn-fin-core-remediation)")
		name := fs.String("name", "", "Display name")
		org := fs.String("org", "", "Owning organizational unit")
		cc := fs.String("cost-center", "", "Cost center code")
		pso := fs.String("primary-so", "", "Primary SERVICE_OWNER principal ID")
		sso := fs.String("secondary-so", "", "Secondary backup SERVICE_OWNER principal ID")
		pao := fs.String("primary-ao", "", "Primary AUTHORIZING_OFFICIAL principal ID")
		sao := fs.String("secondary-ao", "", "Secondary backup AUTHORIZING_OFFICIAL principal ID")
		esc := fs.String("escalation", "", "Escalation email / PagerDuty target")
		grace := fs.Int("grace-hours", 168, "Orphan grace window hours (0..336)")
		reason := fs.String("reason", "", "Optional transfer reason code")
		slot1Key := fs.String("slot1-key", "", "Slot 1 SERVICE_OWNER .priv.json")
		slot2Key := fs.String("slot2-key", "", "Slot 2 AUTHORIZING_OFFICIAL .priv.json")
		if len(args) > 2 {
			_ = fs.Parse(args[2:])
		}
		if *fnID == "" || *org == "" || *pso == "" || *pao == "" || *esc == "" || *slot1Key == "" || *slot2Key == "" {
			fatalf("usage: warrant functions %s --id <fn-id> --org <unit> --primary-so <so> --primary-ao <ao> --escalation <email> --slot1-key <so.priv.json> --slot2-key <ao.priv.json>", sub)
		}
		s1, err := loadPrivateSignerFile(*slot1Key)
		must(err)
		s2, err := loadPrivateSignerFile(*slot2Key)
		must(err)
		env, err := warrantsdk.DraftCommissioningFunctionEnvelope(warrantsdk.CommissioningFunction{
			FunctionID:             *fnID,
			DisplayName:            *name,
			OwningOrgUnit:          *org,
			CostCenter:             *cc,
			PrimarySOPrincipalID:   *pso,
			SecondarySOPrincipalID: *sso,
			PrimaryAOPrincipalID:   *pao,
			SecondaryAOPrincipalID: *sao,
			EscalationContact:      *esc,
			OrphanGraceHours:       *grace,
		}, sub == "transfer", *reason)
		must(err)
		must(s1.SignEnvelope(1, env))
		must(s2.SignEnvelope(2, env))
		var out *warrantsdk.CommissioningFunction
		if sub == "transfer" {
			out, err = cli.TransferCommissioningSponsor(ctx, *fnID, *env)
		} else {
			out, err = cli.SubmitCommissioningFunction(ctx, *env)
		}
		must(err)
		if jsonOutput {
			printJSON(out)
			return
		}
		fmt.Printf("CommissioningFunction %s (%s) committed: continuity=%s active_so=%d active_ao=%d\n",
			out.FunctionID, sub, out.ContinuityStatus, out.ActiveSOCount, out.ActiveAOCount)

	default:
		printUsage()
		os.Exit(1)
	}
}

func handleAgentsCommand(ctx context.Context, cli *warrantsdk.Client, args []string, jsonOutput bool) {
	sub := argOrDefault(args, 1, "list")
	switch sub {
	case "list":
		list, err := cli.ListAgents(ctx)
		must(err)
		if jsonOutput {
			printJSON(list)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "AGENT_ID\tKIND\tFUNCTION\tSTATE\tMAX_TTL\tRECERTIFY_EXPIRES")
		for _, a := range list {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%ds\t%s\n",
				a.AgentID, a.AgentKind, a.CommissioningFunctionID, a.SponsorshipState,
				a.MaxTTLSeconds, a.RecertifyExpiresAt.Format(time.RFC3339))
		}
		_ = tw.Flush()

	case "keygen":
		fs := flag.NewFlagSet("agents-keygen", flag.ExitOnError)
		id := fs.String("id", "", "Agent or builder ID")
		name := fs.String("name", "", "Display name")
		outFile := fs.String("out", "", "Output key bundle JSON path")
		if len(args) > 2 {
			_ = fs.Parse(args[2:])
		}
		if *id == "" || *outFile == "" {
			fatalf("usage: warrant agents keygen --id <agt-id> --out <agent.key.json>")
		}
		kb, err := warrantsdk.GenerateAgentKeyBundle(*id, *name)
		must(err)
		raw, err := json.MarshalIndent(kb, "", "  ")
		must(err)
		must(os.WriteFile(*outFile, raw, 0600))
		fmt.Printf("Generated Ed25519 agent keypair %s -> %s (fp=%s)\n", kb.AgentID, *outFile, kb.KeyFingerprint)

	case "sign-provenance":
		fs := flag.NewFlagSet("agents-sign-provenance", flag.ExitOnError)
		agentID := fs.String("agent", "", "Agent ID")
		digest := fs.String("digest", "", "Container/artifact digest (sha256:...)")
		agentPub := fs.String("agent-pubkey", "", "Agent Ed25519 public_key_b64")
		builderKey := fs.String("builder-key", "", "Builder key JSON file (.priv.json or agent.key.json)")
		if len(args) > 2 {
			_ = fs.Parse(args[2:])
		}
		if *agentID == "" || *digest == "" || *agentPub == "" || *builderKey == "" {
			fatalf("usage: warrant agents sign-provenance --agent <id> --digest <sha256:...> --agent-pubkey <b64> --builder-key <builder.json>")
		}
		raw, err := os.ReadFile(*builderKey)
		must(err)
		var keyDoc struct {
			PrivateKeyB64 string `json:"private_key_b64"`
		}
		must(json.Unmarshal(raw, &keyDoc))
		sig, err := warrantsdk.SignBuilderProvenance(*agentID, *digest, *agentPub, keyDoc.PrivateKeyB64)
		must(err)
		fmt.Println(sig)

	case "enroll":
		fs := flag.NewFlagSet("agents-enroll", flag.ExitOnError)
		agentKeyPath := fs.String("agent-key", "", "Agent key JSON file (only public_key_b64 is extracted)")
		fnID := fs.String("function", "", "CommissioningFunction ID")
		digest := fs.String("digest", "", "Artifact digest (sha256:...)")
		builderKeyPath := fs.String("builder-key", "", "Builder key JSON file to sign provenance (Builder != Commissioner)")
		actions := fs.String("actions", "EXTRACT_SARIF_2_1_0,EXTRACT_PATCH_DIFF", "Comma-separated allowed actions")
		services := fs.String("services", "*", "Comma-separated allowed services")
		egress := fs.String("egress", warrantsdk.EgressProfileZeroIsolated, "Allowed egress profile")
		maxTTL := fs.Int("max-ttl", 120, "Max Task Warrant TTL seconds (1..300)")
		maxDepth := fs.Int("max-depth", 1, "Max sub-agent delegation depth (0..3)")
		allowIntake := fs.Bool("allow-intake", false, "Allow AUTONOMOUS_WORKLOAD_SPONSORED read-only intake")
		recertDays := fs.Int("recertify-days", 30, "Recertification lease days (<= 90)")
		slot1Key := fs.String("slot1-key", "", "Slot 1 SERVICE_OWNER .priv.json")
		slot2Key := fs.String("slot2-key", "", "Slot 2 AUTHORIZING_OFFICIAL .priv.json")
		if len(args) > 2 {
			_ = fs.Parse(args[2:])
		}
		if *agentKeyPath == "" || *fnID == "" || *digest == "" || *builderKeyPath == "" || *slot1Key == "" || *slot2Key == "" {
			fatalf("usage: warrant agents enroll --agent-key <agt.json> --function <fn-id> --digest <sha256:...> --builder-key <bld.json> --slot1-key <so.priv.json> --slot2-key <ao.priv.json>")
		}
		agRaw, err := os.ReadFile(*agentKeyPath)
		must(err)
		var agDoc warrantsdk.AgentKeyBundle
		must(json.Unmarshal(agRaw, &agDoc))

		bldRaw, err := os.ReadFile(*builderKeyPath)
		must(err)
		var bldDoc struct {
			AgentID        string `json:"agent_id"`
			PrincipalID    string `json:"principal_id"`
			PublicKeyB64   string `json:"public_key_b64"`
			PrivateKeyB64  string `json:"private_key_b64"`
			KeyFingerprint string `json:"key_fingerprint"`
		}
		must(json.Unmarshal(bldRaw, &bldDoc))
		builderID := bldDoc.AgentID
		if builderID == "" {
			builderID = bldDoc.PrincipalID
		}
		provSig, err := warrantsdk.SignBuilderProvenance(agDoc.AgentID, *digest, agDoc.PublicKeyB64, bldDoc.PrivateKeyB64)
		must(err)

		s1, err := loadPrivateSignerFile(*slot1Key)
		must(err)
		s2, err := loadPrivateSignerFile(*slot2Key)
		must(err)

		env, err := warrantsdk.DraftAgentEnrollEnvelope(warrantsdk.AgentEnrollDraftOptions{
			AgentID:                 agDoc.AgentID,
			DisplayName:             agDoc.DisplayName,
			CommissioningFunctionID: *fnID,
			KeyID:                   agDoc.KeyID,
			PublicKeyB64:            agDoc.PublicKeyB64,
			ArtifactDigest:          *digest,
			BuilderPrincipalID:      builderID,
			BuilderPublicKeyB64:     bldDoc.PublicKeyB64,
			BuilderKeyFingerprint:   bldDoc.KeyFingerprint,
			BuilderProvenanceSigB64: provSig,
			AllowedActions:          splitCSV(*actions),
			AllowedServices:         splitCSV(*services),
			AllowedEgressProfile:    *egress,
			MaxTTLSeconds:           *maxTTL,
			MaxDelegationDepth:      *maxDepth,
			AllowAutonomousIntake:   *allowIntake,
			RecertifyDays:           *recertDays,
		})
		must(err)
		must(s1.SignEnvelope(1, env))
		must(s2.SignEnvelope(2, env))
		out, err := cli.EnrollAgent(ctx, *env)
		must(err)
		if jsonOutput {
			printJSON(out)
			return
		}
		fmt.Printf("Enrolled AgentIdentity %s under %s (state=%s, recertify=%s)\n",
			out.AgentID, out.CommissioningFunctionID, out.SponsorshipState, out.RecertifyExpiresAt.Format(time.RFC3339))

	case "recertify":
		fs := flag.NewFlagSet("agents-recertify", flag.ExitOnError)
		agentID := fs.String("agent", "", "Agent ID")
		days := fs.Int("days", 90, "Recertification lease days (<= 90)")
		reason := fs.String("reason", "CLI_DUAL_KEY_RECERTIFICATION", "Reason code")
		slot1Key := fs.String("slot1-key", "", "Slot 1 SERVICE_OWNER .priv.json")
		slot2Key := fs.String("slot2-key", "", "Slot 2 AUTHORIZING_OFFICIAL .priv.json")
		if len(args) > 2 {
			_ = fs.Parse(args[2:])
		}
		if *agentID == "" || *slot1Key == "" || *slot2Key == "" {
			fatalf("usage: warrant agents recertify --agent <id> --slot1-key <so.priv.json> --slot2-key <ao.priv.json>")
		}
		s1, err := loadPrivateSignerFile(*slot1Key)
		must(err)
		s2, err := loadPrivateSignerFile(*slot2Key)
		must(err)
		env, err := warrantsdk.DraftAgentRecertifyEnvelope(*agentID, *days, *reason)
		must(err)
		must(s1.SignEnvelope(1, env))
		must(s2.SignEnvelope(2, env))
		out, err := cli.RecertifyAgent(ctx, *env)
		must(err)
		printJSON(out)

	case "revoke":
		fs := flag.NewFlagSet("agents-revoke", flag.ExitOnError)
		agentID := fs.String("agent", "", "Target Agent ID")
		reason := fs.String("reason", "CLI_AGENT_KILL_SWITCH", "Reason code")
		keyPath := fs.String("key", "", "1-of-2 human principal .priv.json OR agent self-key .json")
		if len(args) > 2 {
			_ = fs.Parse(args[2:])
		}
		if *agentID == "" || *keyPath == "" {
			fatalf("usage: warrant agents revoke --agent <id> --key <principal-or-agent.priv.json> [--reason <code>]")
		}
		env, err := warrantsdk.DraftAgentRevokeEnvelope(*agentID, *reason)
		must(err)
		if sb, pErr := loadPrivateSignerFile(*keyPath); pErr == nil {
			must(sb.SignEnvelope(1, env))
		} else {
			raw, rErr := os.ReadFile(*keyPath)
			must(rErr)
			var ak warrantsdk.AgentKeyBundle
			must(json.Unmarshal(raw, &ak))
			must(ak.SignEnvelope(env))
		}
		out, err := cli.RevokeAgent(ctx, *env)
		must(err)
		printJSON(out)

	case "token-exchange":
		fs := flag.NewFlagSet("agents-token-exchange", flag.ExitOnError)
		agentKeyPath := fs.String("agent-key", "", "Caller AgentKeyBundle JSON file")
		mode := fs.String("mode", warrantsdk.AuthorityModeWarrantComposite, "Authority mode (WARRANT_DELEGATED_COMPOSITE | AUTONOMOUS_WORKLOAD_SPONSORED)")
		warrantID := fs.String("warrant", "", "Standing Warrant ID (for WARRANT_DELEGATED_COMPOSITE)")
		asset := fs.String("asset", "", "Target asset / service ID")
		action := fs.String("action", "", "Requested action")
		ttl := fs.Int("ttl", 60, "Requested TTL seconds (<= 300)")
		if len(args) > 2 {
			_ = fs.Parse(args[2:])
		}
		if *agentKeyPath == "" || *asset == "" || *action == "" {
			fatalf("usage: warrant agents token-exchange --agent-key <agt.json> --asset <svc> --action <act> [--warrant <wrt-id>]")
		}
		raw, err := os.ReadFile(*agentKeyPath)
		must(err)
		var ak warrantsdk.AgentKeyBundle
		must(json.Unmarshal(raw, &ak))
		env, err := warrantsdk.SignTokenExchangeRequest(&ak, warrantsdk.AgentTokenExchangePayload{
			AgentID:             ak.AgentID,
			AuthorityMode:       *mode,
			WarrantID:           *warrantID,
			TargetAsset:         *asset,
			RequestedAction:     *action,
			RequestedTTLSeconds: *ttl,
		}, nil)
		must(err)
		res, err := cli.ExchangeAgentToken(ctx, *env)
		must(err)
		printJSON(res)

	default:
		printUsage()
		os.Exit(1)
	}
}

func handleIGACommand(ctx context.Context, cli *warrantsdk.Client, args []string, jsonOutput bool) {
	sub := argOrDefault(args, 1, "list")
	switch sub {
	case "list":
		list, err := cli.ListIGAEvents(ctx)
		must(err)
		printJSON(list)

	case "emit":
		fs := flag.NewFlagSet("iga-emit", flag.ExitOnError)
		evType := fs.String("type", "", "IGA event type (ROLE_TRANSFER | ORG_REORG | LEAVE_OF_ABSENCE | TERMINATION | KEY_COMPROMISE)")
		principal := fs.String("principal", "", "Affected principal ID")
		reason := fs.String("reason", "", "Reason code")
		igaTok := fs.String("iga-token", os.Getenv("WARRANT_IGA_TOKEN"), "Optional WARRANT_IGA_TOKEN")
		hmacSec := fs.String("hmac-secret", os.Getenv("WARRANT_IGA_WEBHOOK_HMAC_SECRET"), "Optional WARRANT_IGA_WEBHOOK_HMAC_SECRET")
		keyPath := fs.String("key", "", "Optional 1-of-2 active principal .priv.json")
		if len(args) > 2 {
			_ = fs.Parse(args[2:])
		}
		if *evType == "" || *principal == "" {
			fatalf("usage: warrant iga emit --type <ROLE_TRANSFER|ORG_REORG|LEAVE_OF_ABSENCE|TERMINATION|KEY_COMPROMISE> --principal <id> [--key <so-or-ao.priv.json>]")
		}
		igaCli := cli
		if *keyPath != "" {
			sb, err := loadPrivateSignerFile(*keyPath)
			must(err)
			igaCli = warrantsdk.NewClient(cli.BaseURL(), warrantsdk.WithSignerBundle(sb))
		}
		out, err := igaCli.EmitIGAEvent(ctx, warrantsdk.IGAEventRequest{
			EventType:   *evType,
			PrincipalID: *principal,
			ReasonCode:  *reason,
		}, *igaTok, *hmacSec)
		must(err)
		if jsonOutput {
			printJSON(out)
			return
		}
		printJSON(out)

	default:
		printUsage()
		os.Exit(1)
	}
}
