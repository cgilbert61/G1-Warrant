package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/g1163rt-labs/g1-warrant/internal/db"
	"github.com/g1163rt-labs/g1-warrant/internal/server"
)

func main() {
	if err := server.ValidateStartupSecurityGuards(os.Getenv); err != nil {
		log.Printf("%v", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	listenAddr := envOrDefault("WARRANTD_LISTEN_ADDR", ":8080")
	dbURL := envOrDefault("DATABASE_URL", "postgres://warrant:warrant@postgres:5432/warrant?sslmode=disable")
	if dbURLFile := strings.TrimSpace(os.Getenv("DATABASE_URL_FILE")); dbURLFile != "" {
		if b, readErr := os.ReadFile(dbURLFile); readErr == nil && strings.TrimSpace(string(b)) != "" {
			dbURL = strings.TrimSpace(string(b))
		}
	}
	extractorURL := envOrDefault("EXTRACTOR_URL", "http://warrant-extractor:8090")
	fleetURL := envOrDefault("FLEET_SIM_URL", "http://fleet-sim:8095")
	kernelSeed := strings.TrimSpace(os.Getenv("KERNEL_ATTESTATION_SEED"))
	rpID := envOrDefault("WEBAUTHN_RP_ID", "localhost")
	rpOrigin := envOrDefault("WEBAUTHN_RP_ORIGIN", "http://localhost:8080")

	webauthnCfg := crypto.WebAuthnConfig{
		RPID: rpID,
		AllowedOrigins: uniqueStrings([]string{
			rpOrigin,
			"http://localhost:8080",
			"http://127.0.0.1:8080",
		}),
	}

	var store *db.Store
	var err error
	for attempt := 1; attempt <= 30; attempt++ {
		store, err = db.NewStore(ctx, dbURL)
		if err == nil {
			break
		}
		log.Printf("waiting for postgres (%d/30): %v", attempt, err)
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		log.Fatalf("unable to connect to postgres: %v", err)
	}
	defer store.Close()

	if err := store.Migrate(ctx); err != nil {
		log.Fatalf("database migrations failed: %v", err)
	}

	waitHTTPReady(ctx, extractorURL+"/healthz", "warrant-extractor", 25)
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("WARRANT_CLUSTER_DRIVER")), "kubernetes") {
		waitHTTPReady(ctx, fleetURL+"/healthz", "fleet-sim", 25)
	}

	orch, err := server.NewOrchestrator(ctx, store, extractorURL, fleetURL, kernelSeed, webauthnCfg)
	if err != nil {
		log.Fatalf("initialize control-plane orchestrator: %v", err)
	}

	if os.Getenv("WARRANT_ENABLE_TEST_SMARTCARDS") == "true" && os.Getenv("SKIP_SEED") != "true" {
		if err := orch.SeedEnterpriseEstate(ctx); err != nil {
			log.Printf("seed warning: %v", err)
		}
	}

	orch.N1Warrant.StartFreezeListener(ctx)
	orch.N3Verify.StartDriftWatcher(ctx, 2*time.Second)
	orch.Feeds.StartBackgroundPoller(ctx)

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           orch.BuildHTTPHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("G1-Warrant Control Plane (warrantd) listening on %s | RPID=%s RPOrigin=%s", listenAddr, rpID, rpOrigin)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("warrantd HTTP server failed: %v", err)
		}
	}()

	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}

func envOrDefault(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func waitHTTPReady(ctx context.Context, url, name string, maxAttempts int) {
	client := &http.Client{Timeout: 2 * time.Second}
	for i := 1; i <= maxAttempts; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if resp, err := client.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 300 {
				return
			}
		}
		log.Printf("waiting for %s (%d/%d)...", name, i, maxAttempts)
		time.Sleep(500 * time.Millisecond)
	}
}
