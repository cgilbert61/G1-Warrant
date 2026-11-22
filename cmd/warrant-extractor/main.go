package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/extractor"
)

func main() {
	addr := os.Getenv("EXTRACTOR_LISTEN_ADDR")
	if addr == "" {
		addr = ":8090"
	}
	digest := extractor.SelfBinaryDigest()
	srv := &http.Server{
		Addr:              addr,
		Handler:           extractor.NewHTTPHandler(digest),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf(
			"warrant-extractor listening on %s (binary_sha256=%s, profile=ZERO_EGRESS_ISOLATED, require_wire_pop=%t)",
			addr, digest, extractor.ShouldRequireExtractorWireAuthFromEnv(),
		)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("warrant-extractor server failed: %v", err)
		}
	}()

	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}
