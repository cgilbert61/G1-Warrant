#!/usr/bin/env python3
"""
G1-Warrant v1.3.0 — Reproducible Disposable Kubernetes Cluster Proof (Closes F3 & Item 1/2)

Spins up a real disposable `rancher/k3s` single-node Kubernetes cluster in Docker,
deploys a real 3-replica HTTP workload (`payments-ledger-api` in namespace `fin-core`),
connects live `warrantd` (`WARRANT_CLUSTER_DRIVER=kubernetes`, `WARRANT_POSTURE=live`)
and zero-egress `warrant-extractor`, and executes end-to-end:

  1. Genesis quorum enrollment (2 SERVICE_OWNER + 2 AUTHORIZING_OFFICIAL principals)
     and 1 `2-of-2` Standing Warrant (`KEV-TIER1-STATELESS`, `clone_twin_count = 3`).
  2. Token-only finding ingest (`POST /api/v1/intake/sarif` with `X-Warrant-Intake-Token` ONLY,
     zero human signatures, zero Four-Eyes exceptions).
  3. Live Kubernetes execution on `k3s`:
     - Stage 2 `networking.k8s.io/v1` `NetworkPolicy` containment bridge in `fin-core`
     - Differential Exploit Replay (`batch/v1` positive + candidate Jobs in `g1-twin-isolated`)
     - **3-Clone Proving Ground** (`3` real clone Pods + `batch/v1` Proving Runner Job in
       zero-egress `g1-twin-proving` verifying `/healthz`, `/smoke`, and `/acceptance`)
     - Rolling update of all `3/3` production `Deployment` pods in `fin-core` to the patched OCI image
     - Live `ValidatingAdmissionPolicy` + `ValidatingAdmissionPolicyBinding` lockout on `k3s`
       (verified by attempting to schedule a Pod with the banned digest and observing live denial!)
     - Containment bridge retirement & DSSE-signed NIST OSCAL 1.1.2 POA&M minting
  4. Live fail-closed Runtime-Follows-Patch check: submitting a `KERNEL` package (`kernel-core-...`)
     against `CONTAINER_TWIN` fails closed with `KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME` and `0` orders.
  5. Air-gapped offline OSCAL 1.1.2 verification against the pinned `kernel.pub` file.
  6. Guaranteed teardown of `g1-f3-k3s` and all ephemeral proof containers/volumes/networks.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "sdk" / "python"))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from g1_warrant import (
    ROLE_AUTHORIZING_OFFICIAL,
    ROLE_SERVICE_OWNER,
    WarrantClient,
    canonicalize_jcs,
    draft_warrant_envelope,
    generate_ed25519_signer_bundle,
    verify_oscal_bundle_offline,
)

NET_NAME = "g1-f3-proof-net"
VOL_PUBKEYS = "g1-f3-pubkeys"
VOL_SHARED = "g1-f3-shared"
K3S_CONTAINER = "g1-f3-k3s"
PG_CONTAINER = "g1-f3-postgres"
EXT_CONTAINER = "g1-f3-extractor"
WARRANTD_CONTAINER = "g1-f3-warrantd"
K3S_IMAGE = os.environ.get("G1_F3_K3S_IMAGE", "rancher/k3s:v1.31.2-k3s1")

TRANSCRIPT_LINES: list[str] = []


def log_line(msg: str) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    TRANSCRIPT_LINES.append(line)


def run_cmd(cmd: list[str], *, input_bytes: bytes | None = None, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess:
    res = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if check and res.returncode != 0:
        out = res.stdout.decode("utf-8", errors="replace")
        err = res.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"Command failed ({res.returncode}): {' '.join(cmd)}\nSTDOUT:\n{out}\nSTDERR:\n{err}")
    return res


def cleanup_resources() -> None:
    for cname in [WARRANTD_CONTAINER, EXT_CONTAINER, PG_CONTAINER, K3S_CONTAINER]:
        subprocess.run(["docker", "rm", "-f", "-v", cname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for vname in [VOL_PUBKEYS, VOL_SHARED]:
        subprocess.run(["docker", "volume", "rm", "-f", vname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["docker", "network", "rm", NET_NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write_file_to_volume(vol_name: str, filename: str, content: bytes, mode: str = "0644") -> None:
    b64 = base64.b64encode(content).decode("ascii")
    sh_cmd = f"printf '%s' '{b64}' | base64 -d > /vol/{filename} && chmod {mode} /vol/{filename}"
    run_cmd(["docker", "run", "--rm", "-v", f"{vol_name}:/vol", "python:3.12-alpine", "sh", "-c", sh_cmd])


def read_file_from_volume(vol_name: str, filename: str) -> bytes:
    res = run_cmd(["docker", "run", "--rm", "-v", f"{vol_name}:/vol:ro", "python:3.12-alpine", "cat", f"/vol/{filename}"])
    return res.stdout


def build_workload_and_probe_images(work_dir: Path) -> None:
    app_py = """import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = os.environ.get("BUILD_VARIANT", "vuln")
PORT = int(os.environ.get("PORT", "8080"))
SRV_REF = None

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stdout.write(f"[workload-{MODE}] " + (fmt % args) + "\\n")
        sys.stdout.flush()

    def _send(self, code, obj):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, {"status": "OK", "service": "payments-ledger-api", "variant": MODE})
        elif self.path == "/smoke":
            self._send(200, {
                "status": "OK",
                "smoke_invariant": "double_entry_balance_zero",
                "shard_nodes": ["shard-a", "shard-b", "shard-c"],
            })
        elif self.path == "/acceptance":
            if MODE == "vuln":
                self._send(200, {"acceptance": "VULNERABLE_BUILD", "cve": "CVE-2026-41001"})
            else:
                self._send(200, {
                    "acceptance": "CLASS_INVARIANTS_SATISFIED",
                    "warrant_class": "KEV-TIER1-STATELESS",
                    "fixed_cve": "CVE-2026-41001",
                    "max_frame_bytes": 16384,
                })
        elif self.path == "/exploit-probe-check":
            if MODE == "vuln":
                self._send(200, {"verdict": "EXPLOIT_SUCCEEDED", "leaked_heap_bytes": 65535})
            else:
                self._send(400, {"verdict": "EXPLOIT_BLOCKED", "error": "ErrOversizedExploitFrame"})
        else:
            self._send(200, {"status": "OK"})

    def do_POST(self):
        if self.path == "/twin-sidecar-complete":
            self._send(200, {"shutting_down": True})
            if SRV_REF is not None:
                threading.Thread(target=SRV_REF.shutdown, daemon=True).start()
        else:
            self._send(404, {"error": "not_found"})

if __name__ == "__main__":
    SRV_REF = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    sys.stdout.write(f"[payments-ledger-api] listening on :{PORT} variant={MODE}\\n")
    sys.stdout.flush()
    SRV_REF.serve_forever()
"""
    probe_py = """import http.client, os, sys, time

role = os.environ.get("TWIN_CONTROL_ROLE", "unknown")
cve = os.environ.get("CVE_ID", "CVE-2026-41001")

status = None
body = ""
for _ in range(40):
    try:
        conn = http.client.HTTPConnection("127.0.0.1", 8080, timeout=1.5)
        conn.request("GET", "/exploit-probe-check")
        resp = conn.getresponse()
        status = resp.status
        body = resp.read().decode("utf-8", errors="replace")
        conn.close()
        break
    except Exception:
        time.sleep(0.25)

try:
    conn = http.client.HTTPConnection("127.0.0.1", 8080, timeout=1.5)
    conn.request("POST", "/twin-sidecar-complete", body=b"{}")
    conn.getresponse().read()
    conn.close()
except Exception:
    pass

if status is None:
    print(f"[probe] failed to reach local twin server for {cve} ({role})", flush=True)
    sys.exit(2)

if "EXPLOIT_SUCCEEDED" in body:
    print(f"[probe] role={role} cve={cve} http={status} payload={body}", flush=True)
    print("G1_TWIN_VERDICT=EXPLOIT_SUCCEEDED", flush=True)
    sys.exit(42)
else:
    print(f"[probe] role={role} cve={cve} http={status} payload={body}", flush=True)
    print("G1_TWIN_VERDICT=EXPLOIT_BLOCKED", flush=True)
    sys.exit(0)
"""
    (work_dir / "app.py").write_text(app_py, encoding="utf-8")
    (work_dir / "probe.py").write_text(probe_py, encoding="utf-8")

    for variant, tag in [("vuln", "payments-ledger-api:v1-vuln"), ("patched", "payments-ledger-api:v2-patched")]:
        df = f"""FROM python:3.12-alpine
WORKDIR /app
COPY app.py /app/app.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 BUILD_VARIANT={variant} PORT=8080
USER 65532:65532
EXPOSE 8080
CMD ["python3", "/app/app.py"]
"""
        df_path = work_dir / f"Dockerfile.{variant}"
        df_path.write_text(df, encoding="utf-8")
        run_cmd(["docker", "build", "-q", "-t", tag, "-f", str(df_path), str(work_dir)])

    df_probe = """FROM python:3.12-alpine
WORKDIR /app
COPY probe.py /app/probe.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
CMD ["python3", "/app/probe.py"]
"""
    df_probe_path = work_dir / "Dockerfile.probe"
    df_probe_path.write_text(df_probe, encoding="utf-8")
    run_cmd(["docker", "build", "-q", "-t", "g1-twin-probe:v1.3.0", "-f", str(df_probe_path), str(work_dir)])


def sign_live_rulepacks() -> tuple[str, bytes]:
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    key_id = "rulepack-authority-ed25519-" + hashlib.sha256(pub_raw).hexdigest()[:12]

    rp = {
        "rulepack_id": "rpk-cwe787-tls-heartbeat-v1",
        "cve_id": "",
        "cwe_id": "CWE-787",
        "exploit_vector": "TLS_HEARTBEAT",
        "blocked_paths": ["/tls-heartbeat-ext"],
        "blocked_headers": [],
        "has_signed_probe": True,
        "publisher_key_id": key_id,
    }
    material = "|".join([
        "G1_RULEPACK_V1",
        rp["rulepack_id"],
        rp["cve_id"].upper(),
        rp["cwe_id"].upper(),
        rp["exploit_vector"],
        ",".join(rp["blocked_paths"]),
        ",".join(rp["blocked_headers"]),
        "true",
    ]).encode("utf-8")
    sig = priv.sign(material)
    rp["signature_b64"] = base64.b64encode(sig).decode("ascii")
    return pub_b64, json.dumps([rp], indent=2).encode("utf-8")


def k3s_kubectl(args: list[str], *, input_bytes: bytes | None = None, check: bool = True) -> str:
    res = run_cmd(["docker", "exec", "-i", K3S_CONTAINER, "kubectl", *args], input_bytes=input_bytes, check=check)
    return res.stdout.decode("utf-8", errors="replace")


def http_json(method: str, url: str, *, headers: dict[str, str] | None = None, body: bytes | None = None) -> tuple[int, dict | list | str]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost"):
        raise ValueError(f"Refusing non-loopback HTTP target: {url}")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=90)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", errors="replace")
        status = resp.status
    finally:
        conn.close()
    try:
        return status, json.loads(raw)
    except Exception:
        return status, raw


def main() -> int:
    work_dir = Path(tempfile.mkdtemp(prefix="g1-f3-k3s-proof-"))
    cleanup_resources()
    try:
        log_line("=== G1-WARRANT v1.3.0 DISPOSABLE KUBERNETES CLUSTER PROOF (CLOSES F3) ===")
        log_line("Step 1: Building local workload (v1-vuln, v2-patched), twin-probe, warrant-extractor, and warrantd images...")
        build_workload_and_probe_images(work_dir)
        run_cmd(["docker", "build", "-q", "-t", "g1-f3-extractor:local", "-f", "Dockerfile.extractor", "."])
        run_cmd(["docker", "build", "-q", "-t", "g1-f3-warrantd:local", "-f", "Dockerfile.warrantd", "."])

        # Docker image config IDs match kubelet's status.containerStatuses[0].imageID after `docker save | ctr import`
        vuln_digest = run_cmd(["docker", "image", "inspect", "payments-ledger-api:v1-vuln", "--format", "{{.Id}}"]).stdout.decode("utf-8").strip()
        patched_digest = run_cmd(["docker", "image", "inspect", "payments-ledger-api:v2-patched", "--format", "{{.Id}}"]).stdout.decode("utf-8").strip()
        if not vuln_digest.startswith("sha256:") or not patched_digest.startswith("sha256:") or vuln_digest == patched_digest:
            raise RuntimeError(f"Invalid image IDs: vuln={vuln_digest} patched={patched_digest}")

        run_cmd(["docker", "network", "create", NET_NAME])
        run_cmd(["docker", "volume", "create", VOL_PUBKEYS])
        run_cmd(["docker", "volume", "create", VOL_SHARED])

        log_line(f"Step 2: Booting disposable Kubernetes cluster ({K3S_IMAGE}) in container {K3S_CONTAINER}...")
        run_cmd([
            "docker", "run", "-d", "--privileged",
            "--name", K3S_CONTAINER,
            "--hostname", K3S_CONTAINER,
            "--network", NET_NAME,
            K3S_IMAGE,
            "server",
            "--disable=traefik",
            "--disable=metrics-server",
            "--disable=servicelb",
            f"--tls-san={K3S_CONTAINER}",
            "--tls-san=127.0.0.1",
        ])

        node_ready = False
        k8s_version = ""
        for _ in range(90):
            res = run_cmd(["docker", "exec", K3S_CONTAINER, "kubectl", "get", "nodes", "-o", "json"], check=False)
            if res.returncode == 0:
                doc = json.loads(res.stdout.decode("utf-8"))
                items = doc.get("items") or []
                if items:
                    k8s_version = items[0].get("status", {}).get("nodeInfo", {}).get("kubeletVersion", "")
                    for cond in items[0].get("status", {}).get("conditions", []):
                        if cond.get("type") == "Ready" and cond.get("status") == "True":
                            node_ready = True
                            break
            if node_ready:
                break
            time.sleep(1.5)
        if not node_ready:
            raise RuntimeError("Disposable k3s node did not reach Ready within timeout")
        log_line(f"  -> Live k3s node READY: kubeletVersion={k8s_version}")

        log_line("Step 3: Importing OCI workload & twin-probe images into k3s containerd...")
        save_proc = run_cmd(["docker", "save", "payments-ledger-api:v1-vuln", "payments-ledger-api:v2-patched", "g1-twin-probe:v1.3.0"])
        imp_res = run_cmd(["docker", "exec", "-i", K3S_CONTAINER, "ctr", "-n", "k8s.io", "images", "import", "-"], input_bytes=save_proc.stdout)
        for ln in imp_res.stdout.decode("utf-8", errors="replace").strip().splitlines():
            log_line(f"  -> ctr import: {ln}")
        log_line(f"  -> Authoritative kubelet imageID digests:\n     v1-vuln    = {vuln_digest}\n     v2-patched = {patched_digest}")

        log_line("Step 4: Deploying 3-replica production workload `Deployment/payments-ledger-api` in namespace `fin-core`...")
        patched_short = patched_digest[7:19]
        k8s_manifests = f"""apiVersion: v1
kind: Namespace
metadata:
  name: fin-core
  labels:
    kubernetes.io/metadata.name: fin-core
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: payments-ledger-cfg
  namespace: fin-core
data:
  LEDGER_REGION: "us-gov-east-1"
  MAX_FRAME_BYTES: "16384"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-ledger-api
  namespace: fin-core
  annotations:
    g1.warrant/image-{patched_short}: "docker.io/library/payments-ledger-api:v2-patched"
spec:
  replicas: 3
  selector:
    matchLabels:
      app.kubernetes.io/name: payments-ledger-api
  template:
    metadata:
      labels:
        app.kubernetes.io/name: payments-ledger-api
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
      containers:
        - name: payments-ledger-api
          image: docker.io/library/payments-ledger-api:v1-vuln
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8080
          envFrom:
            - configMapRef:
                name: payments-ledger-cfg
          readinessProbe:
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 1
            periodSeconds: 2
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
      volumes:
        - name: ledger-cfg-vol
          configMap:
            name: payments-ledger-cfg
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: warrant-controller
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: warrant-controller-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: warrant-controller
    namespace: kube-system
"""
        k3s_kubectl(["apply", "-f", "-"], input_bytes=k8s_manifests.encode("utf-8"))
        k3s_kubectl(["rollout", "status", "deployment/payments-ledger-api", "-n", "fin-core", "--timeout=90s"])

        initial_pods_out = k3s_kubectl(["get", "pods", "-n", "fin-core", "-o", "wide"]).strip()
        log_line("  -> Initial 3-replica production pods in `fin-core`:\n" + "\n".join("     " + ln for ln in initial_pods_out.splitlines()))

        pods_json = json.loads(k3s_kubectl(["get", "pods", "-n", "fin-core", "-o", "json"]))
        live_pod_digests = set()
        for item in pods_json.get("items", []):
            for cs in item.get("status", {}).get("containerStatuses", []):
                img_id = cs.get("imageID", "")
                if "sha256:" in img_id:
                    live_pod_digests.add(img_id[img_id.index("sha256:"):])
        log_line(f"  -> Kubelet-reported initial Pod imageID digest(s): {sorted(live_pod_digests)}")
        assert vuln_digest in live_pod_digests, f"Expected {vuln_digest} in {live_pod_digests}"

        sa_token = k3s_kubectl(["create", "token", "warrant-controller", "-n", "kube-system", "--duration=1h"]).strip()
        ca_pem = run_cmd(["docker", "exec", K3S_CONTAINER, "cat", "/var/lib/rancher/k3s/server/tls/server-ca.crt"]).stdout
        rulepack_pub_b64, rulepacks_json = sign_live_rulepacks()
        write_file_to_volume(VOL_SHARED, "k3s-ca.crt", ca_pem, "0644")
        write_file_to_volume(VOL_SHARED, "rulepacks.json", rulepacks_json, "0644")

        log_line("Step 5: Starting PostgreSQL 16, zero-egress `warrant-extractor`, and live `warrantd` (`WARRANT_CLUSTER_DRIVER=kubernetes`)...")
        pg_pw = secrets.token_hex(24)
        db_dsn = f"postgres://warrant:{pg_pw}@{PG_CONTAINER}:5432/warrant?sslmode=disable"
        run_cmd([
            "docker", "run", "-d",
            "--name", PG_CONTAINER,
            "--network", NET_NAME,
            "-e", "POSTGRES_USER=warrant",
            "-e", f"POSTGRES_PASSWORD={pg_pw}",
            "-e", "POSTGRES_DB=warrant",
            "postgres:16-alpine",
        ])
        for _ in range(30):
            r = run_cmd(["docker", "exec", PG_CONTAINER, "pg_isready", "-U", "warrant", "-d", "warrant"], check=False)
            if r.returncode == 0:
                break
            time.sleep(1.0)

        run_cmd([
            "docker", "run", "-d",
            "--name", EXT_CONTAINER,
            "--network", NET_NAME,
            "--read-only",
            "--cap-drop=ALL",
            "-v", f"{VOL_PUBKEYS}:/var/lib/warrant-pubkeys:ro",
            "-e", "EXTRACTOR_LISTEN_ADDR=:8090",
            "-e", "WARRANT_EXTRACTOR_REQUIRE_TASK_POP=true",
            "-e", "WARRANT_KERNEL_PUBLIC_KEY_FILE=/var/lib/warrant-pubkeys/kernel_public_key.b64",
            "g1-f3-extractor:local",
        ])

        admin_tok = "g1adm_" + secrets.token_hex(20)
        intake_tok = "g1int_" + secrets.token_hex(20)
        pub_seed_hex = secrets.token_hex(32)
        twin_img_map = json.dumps({
            vuln_digest: "docker.io/library/payments-ledger-api:v1-vuln",
            patched_digest: "docker.io/library/payments-ledger-api:v2-patched",
        })

        run_cmd([
            "docker", "run", "-d",
            "--name", WARRANTD_CONTAINER,
            "--network", NET_NAME,
            "-p", "127.0.0.1:0:8080",
            "-v", f"{VOL_PUBKEYS}:/var/lib/warrant-pubkeys",
            "-v", f"{VOL_SHARED}:/var/lib/warrant-shared:ro",
            "-e", "WARRANTD_LISTEN_ADDR=:8080",
            "-e", f"DATABASE_URL={db_dsn}",
            "-e", f"EXTRACTOR_URL=http://{EXT_CONTAINER}:8090",
            "-e", "WARRANT_CLUSTER_DRIVER=kubernetes",
            "-e", "WARRANT_POSTURE=live",
            "-e", "WARRANT_ENABLE_TEST_SMARTCARDS=false",
            "-e", f"WARRANT_KUBE_API_URL=https://{K3S_CONTAINER}:6443",
            "-e", f"WARRANT_KUBE_BEARER_TOKEN={sa_token}",
            "-e", "WARRANT_KUBE_CA_FILE=/var/lib/warrant-shared/k3s-ca.crt",
            "-e", "WARRANT_KUBE_DEFAULT_NAMESPACE=fin-core",
            "-e", "WARRANT_TWIN_PROBE_IMAGE=docker.io/library/g1-twin-probe:v1.3.0",
            "-e", "WARRANT_PROVING_RUNNER_IMAGE=docker.io/library/payments-ledger-api:v2-patched",
            "-e", f"WARRANT_TWIN_IMAGE_MAP_JSON={twin_img_map}",
            "-e", f"WARRANT_BOOTSTRAP_ADMIN_TOKEN={admin_tok}",
            "-e", f"WARRANT_INTAKE_TOKEN={intake_tok}",
            "-e", f"WARRANT_PUBLISHER_SEED_HEX={pub_seed_hex}",
            "-e", f"WARRANT_RULEPACK_PUBLIC_KEY_B64={rulepack_pub_b64}",
            "-e", "WARRANT_RULEPACKS_FILE=/var/lib/warrant-shared/rulepacks.json",
            "-e", "WARRANT_KERNEL_PUBLIC_KEY_EXPORT_PATH=/var/lib/warrant-pubkeys/kernel_public_key.b64",
            "g1-f3-warrantd:local",
        ])

        port_out = run_cmd(["docker", "port", WARRANTD_CONTAINER, "8080/tcp"]).stdout.decode("utf-8").strip().splitlines()[0]
        host_port = port_out.rsplit(":", 1)[-1]
        base_url = f"http://127.0.0.1:{host_port}"

        ready = False
        for _ in range(40):
            try:
                st, _ = http_json("GET", base_url + "/healthz")
                if st == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.5)
        if not ready:
            logs = run_cmd(["docker", "logs", WARRANTD_CONTAINER], check=False).stdout.decode("utf-8", errors="replace")
            ext_err = run_cmd(["docker", "logs", WARRANTD_CONTAINER], check=False).stderr.decode("utf-8", errors="replace")
            raise RuntimeError(f"warrantd failed to become ready:\n{logs}\n{ext_err}")
        log_line(f"  -> Live warrantd healthy at {base_url} (WARRANT_CLUSTER_DRIVER=kubernetes, WARRANT_POSTURE=live)")

        std_syscalls = json.dumps(["accept4", "close", "epoll_ctl", "epoll_wait", "fcntl", "fstat", "futex", "getsockopt", "mmap", "munmap", "nanosleep", "openat", "read", "recvfrom", "rt_sigaction", "rt_sigprocmask", "sendto", "setsockopt", "socket", "write"])
        sql_reg = f"""
INSERT INTO estate_services (
    service_id, display_name, namespace, tier, warrant_class, current_digest, current_purl, sbom_purls,
    replicas, test_coverage_pct, otel_health_probes, readonly_shadow_replica, shadow_db_mode,
    rollback_automation_verified, readonly_root_filesystem, noexec_tmp_mounts, allowed_egress_services,
    allow_kube_apiserver_egress, baseline_syscalls, volatile_json_paths, unordered_array_paths,
    eligible, autonomy_tier, eligibility_checklist, updated_at
) VALUES (
    'payments-ledger-api', 'Payments Ledger API (Live k3s)', 'fin-core', 'TIER_1_MISSION_CRITICAL',
    'KEV-TIER1-STATELESS', '{vuln_digest}', 'pkg:oci/payments-ledger-api@{vuln_digest}',
    '["pkg:pypi/payments-ledger@1.0.0"]'::jsonb, 3, 94.5, TRUE, TRUE, 'EPHEMERAL_COW_BRANCH',
    TRUE, TRUE, TRUE, '["kube-dns.kube-system.svc.cluster.local"]'::jsonb, FALSE,
    '{std_syscalls}'::jsonb, '[]'::jsonb, '["$.shard_nodes"]'::jsonb,
    TRUE, 'TIER_1_FULL_AUTONOMOUS', '[]'::jsonb, NOW()
);
"""
        run_cmd(["docker", "exec", "-i", PG_CONTAINER, "psql", "-U", "warrant", "-d", "warrant", "-v", "ON_ERROR_STOP=1"], input_bytes=sql_reg.encode("utf-8"))

        log_line("Step 6: Enrolling 2 SERVICE_OWNER + 2 AUTHORIZING_OFFICIAL principals and signing 1 Standing Warrant class (`clone_twin_count=3`)...")
        cli = WarrantClient(base_url, timeout=90.0)
        so1 = generate_ed25519_signer_bundle("usr-f3-so-1", "so1@agency.gov", "F3 Service Owner 1", ROLE_SERVICE_OWNER)
        so2 = generate_ed25519_signer_bundle("usr-f3-so-2", "so2@agency.gov", "F3 Service Owner 2", ROLE_SERVICE_OWNER)
        ao1 = generate_ed25519_signer_bundle("usr-f3-ao-1", "ao1@agency.gov", "F3 Authorizing Official 1", ROLE_AUTHORIZING_OFFICIAL)
        ao2 = generate_ed25519_signer_bundle("usr-f3-ao-2", "ao2@agency.gov", "F3 Authorizing Official 2", ROLE_AUTHORIZING_OFFICIAL)
        for b in [so1, so2, ao1, ao2]:
            cli.register_principal(b, admin_token=admin_tok)

        w_env = draft_warrant_envelope(
            scope_services=["payments-ledger-api"],
            scope_assets=["payments-ledger-api"],
            warrant_class="KEV-TIER1-STATELESS",
            max_cvss=10.0,
            kev_eligible=True,
            max_blast_radius_replicas=6,
            sla_bridge_minutes=60,
            max_p99_latency_ms=200.0,
            ttl_days=30,
            warrant_id="wrt-f3-k3s-live-001",
        )
        w_payload = json.loads(base64.b64decode(w_env["payload"]).decode("utf-8"))
        w_payload["clone_twin_count"] = 3
        w_env["payload"] = base64.b64encode(canonicalize_jcs(w_payload)).decode("ascii")
        so1.sign_envelope(1, w_env)
        ao1.sign_envelope(2, w_env)
        w_rec = cli.create_warrant(w_env)
        log_line(f"  -> Standing Warrant ACTIVE: warrant_id={w_rec['warrant_id']} class={w_rec['warrant_class']} clone_twin_count={w_rec.get('clone_twin_count')} live_status={w_rec['live_status']}")

        log_line("Step 7: Submitting scanner finding via `POST /api/v1/intake/sarif` with `X-Warrant-Intake-Token` ONLY (ZERO human signatures)...")
        sarif_doc = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "WizFederalScanner", "semanticVersion": "4.12.0", "rules": [{"id": "CVE-2026-41001"}]}},
                "results": [{
                    "ruleId": "CVE-2026-41001",
                    "message": {"text": "Untrusted scanner text stripped inside zero-egress warrant-extractor"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/frame_parser.py"}}}],
                    "properties": {
                        "cve": "CVE-2026-41001",
                        "cwe": "CWE-787",
                        "cvss": 9.8,
                        "cisa_kev": True,
                        "service_id": "payments-ledger-api",
                        "purl": f"pkg:oci/payments-ledger-api@{vuln_digest}",
                        "vulnerable_digest": vuln_digest,
                        "patched_digest": patched_digest,
                        "vulnerable_symbol": "tls_heartbeat_ext_parse_vuln",
                        "exploit_vector": "TLS_HEARTBEAT",
                        "affected_port": 8080,
                    },
                }],
            }],
        }
        st_in, items = http_json(
            "POST",
            base_url + "/api/v1/intake/sarif",
            headers={"Content-Type": "application/json", "X-Warrant-Intake-Token": intake_tok},
            body=json.dumps(sarif_doc).encode("utf-8"),
        )
        if st_in != 201 or not isinstance(items, list) or len(items) != 1:
            raise RuntimeError(f"Unexpected intake response HTTP {st_in}: {items}")

        rem = items[0]
        proving = rem.get("clone_twin_proving") or {}
        log_line(f"  -> Autonomous Remediation Result: HTTP {st_in}")
        log_line(f"     remediation_id       = {rem['remediation_id']}")
        log_line(f"     stage                = {rem['stage']}")
        log_line(f"     status_health        = {rem['status_health']}")
        log_line(f"     assurance_tier       = {rem.get('assurance_tier')}")
        log_line(f"     class_binding_status = {rem.get('class_binding_status')}")
        log_line(f"     patch_target_layer   = {rem.get('patch_target_layer')}")
        log_line(f"     attestation_id       = {rem.get('attestation_id')}")
        log_line("  -> Executed 3-Clone Proving Manifest (`g1-twin-proving` on live k3s):")
        log_line(f"     proving_run_id       = {proving.get('proving_run_id')}")
        log_line(f"     twin_runtime         = {proving.get('twin_runtime')}")
        log_line(f"     proving_namespace    = {proving.get('proving_namespace')}")
        log_line(f"     clone_count          = {proving.get('clone_count')}")
        log_line(f"     services_up_count    = {proving.get('services_up_count')}")
        log_line(f"     smoke_passed_count   = {proving.get('smoke_passed_count')}")
        log_line(f"     accept_passed_count  = {proving.get('acceptance_passed_count')}")
        log_line(f"     all_passed           = {proving.get('all_passed')}")
        log_line(f"     transcript_sha256    = {proving.get('transcript_sha256')}")
        for inst in proving.get("clones") or []:
            log_line(
                f"       * clone[{inst['clone_index']}] pod={inst['clone_name']} ip={inst.get('pod_ip')} node={inst.get('node_or_host')} "
                f"ready={inst['service_up_passed']} smoke={inst['smoke_test_passed']} accept={inst['class_acceptance_passed']} "
                f"lat_ms={inst['observed_latency_ms']:.2f} evidence_sha256={inst['evidence_sha256'][:16]}..."
            )

        if rem["stage"] != "ATTESTED_CLOSED" or not proving.get("all_passed") or proving.get("clone_count") != 3:
            raise RuntimeError(f"Expected ATTESTED_CLOSED with 3/3 clones proven, got: {json.dumps(rem, indent=2)}")

        _, exceptions = http_json("GET", base_url + "/api/v1/exceptions")
        log_line(f"  -> Four-Eyes Queue rows (`ceiling_exceptions`): {len(exceptions)} (expected 0)")
        if len(exceptions) != 0:
            raise RuntimeError(f"Expected 0 exceptions, got {exceptions}")

        log_line("Step 8: Verifying live k3s cluster state AFTER autonomous promotion & AdmissionLockout...")
        after_pods_out = k3s_kubectl(["get", "pods", "-n", "fin-core", "-o", "wide"]).strip()
        log_line("  -> Post-rollout 3-replica production pods in `fin-core`:\n" + "\n".join("     " + ln for ln in after_pods_out.splitlines()))

        after_pods_json = json.loads(k3s_kubectl(["get", "pods", "-n", "fin-core", "-o", "json"]))
        running_patched = 0
        for item in after_pods_json.get("items", []):
            if item.get("metadata", {}).get("deletionTimestamp"):
                continue
            if item.get("status", {}).get("phase") == "Running":
                for cs in item.get("status", {}).get("containerStatuses", []):
                    if patched_digest in cs.get("imageID", "") or "v2-patched" in cs.get("image", ""):
                        running_patched += 1
        log_line(f"  -> Converged live pods running v2-patched ({patched_digest[:24]}...): {running_patched}/3")
        if running_patched != 3:
            raise RuntimeError(f"Expected 3/3 pods running patched image, got {running_patched}")

        vap_out = k3s_kubectl(["get", "validatingadmissionpolicies,validatingadmissionpolicybindings"]).strip()
        log_line("  -> Live Kubernetes ValidatingAdmissionPolicy objects on k3s:\n" + "\n".join("     " + ln for ln in vap_out.splitlines()))

        rogue_pod_yaml = f"""apiVersion: v1
kind: Pod
metadata:
  name: rogue-regression-pod
  namespace: fin-core
spec:
  containers:
    - name: app
      image: docker.io/library/payments-ledger-api@{vuln_digest}
"""
        denied_msg = ""
        for _ in range(15):
            r_try = run_cmd(["docker", "exec", "-i", K3S_CONTAINER, "kubectl", "apply", "-f", "-"], input_bytes=rogue_pod_yaml.encode("utf-8"), check=False)
            if r_try.returncode != 0 and "ValidatingAdmissionPolicy" in r_try.stderr.decode("utf-8", errors="replace"):
                denied_msg = r_try.stderr.decode("utf-8", errors="replace").strip()
                break
            k3s_kubectl(["delete", "pod", "rogue-regression-pod", "-n", "fin-core", "--ignore-not-found=true"], check=False)
            time.sleep(1.0)
        if not denied_msg:
            raise RuntimeError("Expected ValidatingAdmissionPolicy on k3s to deny rogue vulnerable digest pod!")
        log_line(f"  -> Live kube-apiserver Admission Lockout Enforcement Check: DENIED as expected:\n     {denied_msg}")

        log_line("Step 9: Verifying Runtime-Follows-Patch fail-closed (`KERNEL` patch against `CONTAINER_TWIN` on k3s)...")
        qualys_kernel = {
            "hosts": [{
                "service_id": "payments-ledger-api",
                "asset_key": "payments-ledger-api",
                "detections": [{
                    "qid": 379955,
                    "severity": 5,
                    "cvss3_base": 9.3,
                    "status": "Active",
                    "cisa_kev": True,
                    "cves": ["CVE-2026-99111"],
                }],
            }],
        }
        st_qk, qk_items = http_json(
            "POST",
            base_url + "/api/v1/intake/qualys?patch_profile=UPSTREAM_VENDOR_PENDING",
            headers={"Content-Type": "application/json", "X-Warrant-Intake-Token": intake_tok},
            body=json.dumps(qualys_kernel).encode("utf-8"),
        )
        if st_qk != 201 or not isinstance(qk_items, list) or len(qk_items) != 1:
            raise RuntimeError(f"Expected 201 on Qualys kernel intake, got {st_qk}: {qk_items}")
        so_cli = WarrantClient(base_url, signer_bundle=so1, timeout=90.0)
        kernel_rejected_err = ""
        try:
            so_cli.dispatch_distributor_order(
                {
                    "remediation_id": qk_items[0]["remediation_id"],
                    "distributor_id": "ansible-awx",
                    "fix_identity": {"cve_id": "CVE-2026-99111", "package_nevra": "kernel-core-6.8.0-45.el9.x86_64"},
                    "target_assets": [{"asset_key": "payments-ledger-api", "service_id": "payments-ledger-api"}],
                }
            )
        except Exception as exc:
            kernel_rejected_err = str(exc)
        if "KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME" not in kernel_rejected_err:
            raise RuntimeError(f"Expected KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME, got: {kernel_rejected_err}")
        log_line(f"  -> Kernel patch rejected fail-closed before order creation:\n     {kernel_rejected_err}")

        log_line("Step 10: Air-gapped offline verification of exported DSSE NIST OSCAL 1.1.2 POA&M bundle against pinned `kernel.pub`...")
        kernel_pub_b64 = read_file_from_volume(VOL_PUBKEYS, "kernel_public_key.b64").decode("utf-8").strip()
        st_oscal, oscal_bundle = http_json("GET", f"{base_url}/api/v1/attestations/{rem['attestation_id']}/oscal")
        if st_oscal != 200 or not isinstance(oscal_bundle, dict):
            raise RuntimeError(f"Expected 200 OSCAL bundle, got {st_oscal}: {oscal_bundle}")
        offline_ver = verify_oscal_bundle_offline(json.dumps(oscal_bundle).encode("utf-8"), kernel_pub_b64)
        log_line(
            f"  -> Offline OSCAL Verification PASSED: valid={offline_ver['valid']} "
            f"trust_basis={offline_ver['trust_basis']} cve_id={offline_ver['cve_id']} "
            f"service_id={offline_ver['service_id']} warrant_id={offline_ver['warrant_id']}"
        )

        oscal_titles = [
            obs.get("title")
            for obs in oscal_bundle.get("oscal_poam", {}).get("plan-of-action-and-milestones", {}).get("observations", [])
        ]
        log_line(f"  -> Minted OSCAL 1.1.2 Observation Titles ({len(oscal_titles)}): {oscal_titles}")
        if "N3 Isolated Clone-Twin Proving Ground Verification" not in oscal_titles:
            raise RuntimeError(f"Missing Clone-Twin Proving observation in OSCAL bundle: {oscal_titles}")

        log_line("=== ALL F3 DISPOSABLE KUBERNETES CLUSTER CHECKS PASSED — TEARING DOWN EPHEMERAL CLUSTER ===")
        out_report = REPO_ROOT / "reports" / "f3-disposable-k3s-proof-transcript.txt"
        out_report.parent.mkdir(parents=True, exist_ok=True)
        out_report.write_text("\n".join(TRANSCRIPT_LINES) + "\n", encoding="utf-8")
        return 0
    finally:
        cleanup_resources()
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
