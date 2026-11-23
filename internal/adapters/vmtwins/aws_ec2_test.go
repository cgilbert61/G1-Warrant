package vmtwins

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

func TestAWSEC2VMTwinProviderSigV4WarmupRebootAndTeardown(t *testing.T) {
	var sendCalls, pollCalls, terminateCalls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=g1test-aws-key/") {
			http.Error(w, "missing SigV4 auth", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-Amz-Security-Token") != "g1test-sts-token" {
			http.Error(w, "missing STS X-Amz-Security-Token", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)

		if target := r.Header.Get("X-Amz-Target"); target != "" {
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			switch target {
			case "AmazonSSM.SendCommand":
				if sendCalls.Add(1) == 1 {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"__type":  "InvalidInstanceId",
						"message": "SSM agent still warming up after boot",
					})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"Command": map[string]any{"CommandId": "cmd-aws-unit-01"},
				})
			case "AmazonSSM.GetCommandInvocation":
				if pollCalls.Add(1) <= 3 {
					_ = json.NewEncoder(w).Encode(map[string]any{
						"Status":       "Delayed",
						"ResponseCode": 194,
					})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"Status":       "Success",
					"ResponseCode": 0,
					"StandardOutputContent": `G1_CLONE_RESULT={"booted_kernel_or_build":"6.8.0-45.amzn2023.x86_64","reboot_verified":true,"service_up_passed":true,"smoke_test_passed":true,"class_acceptance_passed":true,"observed_latency_ms":11.4,"exit_code":0}`,
				})
			default:
				http.Error(w, "unexpected SSM target "+target, http.StatusBadRequest)
			}
			return
		}

		vals, _ := url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "text/xml")
		switch vals.Get("Action") {
		case "RunInstances":
			if vals.Get("NetworkInterface.1.AssociatePublicIpAddress") != "false" || vals.Get("InstanceInitiatedShutdownBehavior") != "terminate" {
				http.Error(w, "missing isolation/termination flags", http.StatusBadRequest)
				return
			}
			if vals.Get("IamInstanceProfile.Name") != "g1-warrant-twin-enclave-guest-profile-us-east-1" {
				http.Error(w, "missing IamInstanceProfile.Name", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<RunInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <instancesSet>
    <item><instanceId>i-0111</instanceId><privateIpAddress>10.254.1.11</privateIpAddress><placement><availabilityZone>us-east-1a</availabilityZone></placement></item>
    <item><instanceId>i-0222</instanceId><privateIpAddress>10.254.1.12</privateIpAddress><placement><availabilityZone>us-east-1a</availabilityZone></placement></item>
    <item><instanceId>i-0333</instanceId><privateIpAddress>10.254.1.13</privateIpAddress><placement><availabilityZone>us-east-1a</availabilityZone></placement></item>
  </instancesSet>
</RunInstancesResponse>`))
		case "DescribeInstances":
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <reservationSet><item><instancesSet>
    <item><instanceId>i-0111</instanceId><instanceState><name>running</name></instanceState></item>
    <item><instanceId>i-0222</instanceId><instanceState><name>running</name></instanceState></item>
    <item><instanceId>i-0333</instanceId><instanceState><name>running</name></instanceState></item>
  </instancesSet></item></reservationSet>
</DescribeInstancesResponse>`))
		case "TerminateInstances":
			terminateCalls.Add(1)
			_, _ = w.Write([]byte(`<TerminateInstancesResponse/>`))
		default:
			http.Error(w, "unexpected EC2 action "+vals.Get("Action"), http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	prov, err := NewAWSEC2VMTwinProvider(AWSEC2Config{
		Region:              "us-east-1",
		AccessKeyID:         "g1test-aws-key",
		SecretAccessKey:     "g1test-aws-secret",
		SessionToken:        "g1test-sts-token",
		EC2EndpointOverride: srv.URL,
		SSMEndpointOverride: srv.URL,
		QAAMIID:             "ami-0al2023qa",
		SubnetID:            "subnet-isolated01",
		IsolatedSGID:        "sg-isolated01",
		IAMInstanceProfile:  "g1-warrant-twin-enclave-guest-profile-us-east-1",
		PollInterval:        5 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatalf("NewAWSEC2VMTwinProvider: %v", err)
	}

	manifest, err := prov.RunVMTwinProving(context.Background(), adapters.CloneTwinProvingRequest{
		RemediationID:    "rem-aws-unit",
		ServiceID:        "payments-ledger-api",
		WarrantID:        "wrt-aws-01",
		WarrantClass:     "KEV-TIER1-STATELESS",
		CVEID:            "CVE-2026-99001",
		PackageNEVRA:     "kernel-6.8.0-45.amzn2023.x86_64",
		PatchTargetLayer: models.PatchTargetLayerKernel,
		CloneCount:       3,
	})
	if err != nil {
		t.Fatalf("RunVMTwinProving failed: %v", err)
	}
	if !manifest.AllPassed || manifest.AcceptancePassedCount != 3 || !manifest.ZeroProductionEgress {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	if sendCalls.Load() < 2 {
		t.Fatalf("expected SSM InvalidInstanceId warmup retry, got %d SendCommand calls", sendCalls.Load())
	}
	if terminateCalls.Load() != 1 {
		t.Fatalf("expected TerminateInstances teardown call, got %d", terminateCalls.Load())
	}
}
