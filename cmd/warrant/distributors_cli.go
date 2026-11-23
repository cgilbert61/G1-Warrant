package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cgilbert61/G1-Warrant/pkg/warrantsdk"
)

func handleDistributorsCommand(
	ctx context.Context,
	cli *warrantsdk.Client,
	baseURL, opToken, autoToken, globalSignerPath string,
	args []string,
	jsonOutput bool,
) {
	sub := argOrDefault(args, 1, "list")
	switch sub {
	case "list":
		dists, err := cli.ListDistributors(ctx)
		must(err)
		if jsonOutput {
			printJSON(dists)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "DISTRIBUTOR_ID\tFAMILY\tNATIVE_RINGS\tPER_ASSET_STATE\tDEFAULT_ROLLBACK\tPLATFORMS")
		for _, d := range dists {
			fmt.Fprintf(tw, "%s\t%s\t%t\t%t\t%s\t%s\n",
				d.DistributorID,
				d.Family,
				d.Capabilities.SupportsNativeRings,
				d.Capabilities.ReportsPerAssetState,
				d.Capabilities.DefaultRollbackStrategy,
				strings.Join(d.Capabilities.PlatformFamilies, ","),
			)
		}
		_ = tw.Flush()

	case "orders":
		fs := flag.NewFlagSet("distributors orders", flag.ExitOnError)
		remID := fs.String("remediation", "", "Optional remediation ID filter")
		if len(args) > 2 {
			_ = fs.Parse(args[2:])
		}
		orders, err := cli.ListDeploymentOrders(ctx, *remID)
		must(err)
		if jsonOutput {
			printJSON(orders)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ORDER_ID\tREMEDIATION\tDISTRIBUTOR\tWARRANT\tTARGETS\tROLLBACK_STRATEGY\tWAVE\tCREATED_AT")
		for _, o := range orders {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%d/%d\t%s\n",
				o.OrderID,
				o.RemediationID,
				o.DistributorID,
				o.WarrantID,
				len(o.TargetAssets),
				o.RollbackInstruction.Strategy,
				o.WaveNumber,
				o.TotalWaves,
				o.CreatedAt.Format(time.RFC3339),
			)
		}
		_ = tw.Flush()

	case "results":
		fs := flag.NewFlagSet("distributors results", flag.ExitOnError)
		orderID := fs.String("order", "", "Optional deployment order ID filter")
		if len(args) > 2 {
			_ = fs.Parse(args[2:])
		}
		results, err := cli.ListDeploymentResults(ctx, *orderID)
		must(err)
		if jsonOutput {
			printJSON(results)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "RESULT_ID\tORDER_ID\tDISTRIBUTOR\tGRANULARITY\tLANDED/TARGET\tREBOOT_WAIT\tFAILED\tROLLBACK\tOBSERVED_AT")
		for _, r := range results {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d/%d\t%d\t%d\t%t\t%s\n",
				r.ResultID,
				r.OrderID,
				r.DistributorID,
				r.EvidenceGranularity,
				r.LandedCount,
				r.TargetedCount,
				r.RebootWaitingCount,
				r.FailedCount,
				r.IsRollback,
				r.ObservedAt.Format(time.RFC3339),
			)
		}
		_ = tw.Flush()

	case "aliases":
		aliases, err := cli.ListAssetAliases(ctx)
		must(err)
		printJSON(aliases)

	case "dispatch":
		if len(args) < 3 {
			fatalf("usage: warrant distributors dispatch <request.json> [--key <active.priv.json>]")
		}
		reqFile := args[2]
		fs := flag.NewFlagSet("distributors dispatch", flag.ExitOnError)
		keyFile := fs.String("key", globalSignerPath, "Active principal .priv.json signing 1-of-2 FEED_MUTATION DSSE")
		if len(args) > 3 {
			_ = fs.Parse(args[3:])
		}
		rawReq, err := os.ReadFile(reqFile)
		must(err)
		var req warrantsdk.DistributorDispatchRequest
		must(json.Unmarshal(rawReq, &req))

		dCli := cli
		if strings.TrimSpace(*keyFile) != "" {
			signer, sErr := loadPrivateSignerFile(*keyFile)
			must(sErr)
			dCli = warrantsdk.NewClient(baseURL, warrantsdk.WithSignerBundle(signer), warrantsdk.WithOperatorToken(opToken), warrantsdk.WithAutomationToken(autoToken))
		}
		out, err := dCli.DispatchDistributorOrder(ctx, req)
		must(err)
		printJSON(out)

	case "rollback":
		if len(args) < 3 {
			fatalf("usage: warrant distributors rollback <order-id> --key <active.priv.json> [--reason <code>]")
		}
		orderID := args[2]
		fs := flag.NewFlagSet("distributors rollback", flag.ExitOnError)
		keyFile := fs.String("key", globalSignerPath, "Active principal .priv.json signing 1-of-2 EMERGENCY_ROLLBACK DSSE")
		reason := fs.String("reason", "OPERATOR_CLI_DISTRIBUTOR_ROLLBACK", "Structured rollback reason code")
		if len(args) > 3 {
			_ = fs.Parse(args[3:])
		}
		rbCli := cli
		if strings.TrimSpace(*keyFile) != "" {
			signer, sErr := loadPrivateSignerFile(*keyFile)
			must(sErr)
			rbCli = warrantsdk.NewClient(baseURL, warrantsdk.WithSignerBundle(signer), warrantsdk.WithOperatorToken(opToken))
		}
		out, err := rbCli.RollbackDistributorOrder(ctx, orderID, *reason)
		must(err)
		if jsonOutput {
			printJSON(out)
			return
		}
		fmt.Printf("Executed Native Distributor Rollback for order %s (%s): rolled_back=%d/%d native_job=%s\n",
			out.OrderID, out.DistributorID, out.RolledBackCount, out.TargetedCount, out.NativeJobRef)

	default:
		printUsage()
		os.Exit(1)
	}
}
