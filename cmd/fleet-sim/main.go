package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/fleetsim"
)

func main() {
	addr := os.Getenv("FLEET_SIM_LISTEN_ADDR")
	if addr == "" {
		addr = ":8095"
	}
	sim := fleetsim.NewClusterSimulator()
	srv := &http.Server{
		Addr:              addr,
		Handler:           sim.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("fleet-sim target cluster listening on %s (6 simulated Kubernetes/Cilium workloads)", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("fleet-sim failed: %v", err)
		}
	}()

	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}
