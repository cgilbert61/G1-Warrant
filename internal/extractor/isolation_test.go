package extractor

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunIsolationSelfTestPassesWhenBlocked(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	missingSecret := filepath.Join(t.TempDir(), "nonexistent-kernel.key")
	rep, err := RunIsolationSelfTest(ctx, IsolationSelfTestConfig{
		EgressProbeAddr:      "127.0.0.1:1",
		PostgresProbeAddr:    "127.0.0.1:1",
		ForbiddenSecretPaths: []string{missingSecret},
		ProbeTimeout:         200 * time.Millisecond,
	})
	if err != nil || !rep.Passed || len(rep.Checks) != 3 {
		t.Fatalf("expected isolation self-test pass with 3 checks, got rep=%+v err=%v", rep, err)
	}
}

func TestRunIsolationSelfTestFailsClosedWhenReachableOrReadable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	readableSecret := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(readableSecret, []byte("top-secret"), 0600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rep, runErr := RunIsolationSelfTest(ctx, IsolationSelfTestConfig{
		EgressProbeAddr:      ln.Addr().String(),
		ForbiddenSecretPaths: []string{readableSecret},
		ProbeTimeout:         200 * time.Millisecond,
	})
	if runErr == nil || rep.Passed {
		t.Fatalf("expected isolation self-test to fail closed when egress/secret is exposed, got rep=%+v err=%v", rep, runErr)
	}
}
