# G1-Warrant — Third-Party Open-Source License Inventory (SPDX)

**Project License:** [Apache License 2.0](LICENSE) · **Attribution Notice:** [NOTICE](NOTICE)  
**Automated Audit Report:** [`reports/license-audit.json`](reports/license-audit.json) · **CycloneDX SBOM:** [`reports/sbom.cdx.json`](reports/sbom.cdx.json) (`48/48` SPDX-annotated)  
**Policy Verdict:** **PASS — 100% Permissive Open Source (0 Copyleft / GPL / AGPL Dependencies)**

---

## 1. License Distribution Summary

| SPDX Identifier | Dependency Count | Category |
| :--- | :--- | :--- |
| `MIT` | 30 | OSI-Approved Permissive |
| `BSD-3-Clause` | 6 | OSI-Approved Permissive |
| `Apache-2.0` | 5 | OSI-Approved Permissive |
| `Apache-2.0 AND MIT` | 2 | OSI-Approved Permissive |
| `ISC` | 2 | OSI-Approved Permissive |
| `Apache-2.0 OR BSD-3-Clause` | 1 | OSI-Approved Permissive |

---

## 2. Go Control-Plane, Extractor & SDK Modules (`go.mod` — 32 Modules)

| Go Module | Version | Scope | Verified SPDX License |
| :--- | :--- | :--- | :--- |
| `github.com/google/uuid` | `v1.6.0` | direct | `BSD-3-Clause` |
| `github.com/jackc/pgx/v5` | `v5.13.0` | direct | `MIT` |
| `github.com/open-policy-agent/opa` | `v1.22.4` | direct | `Apache-2.0` |
| `gopkg.in/yaml.v3` | `v3.0.1` | direct | `Apache-2.0 AND MIT` |
| `github.com/agnivade/levenshtein` | `v1.2.2` | indirect | `MIT` |
| `github.com/cespare/xxhash/v2` | `v2.3.0` | indirect | `MIT` |
| `github.com/decred/dcrd/dcrec/secp256k1/v4` | `v4.4.1` | indirect | `ISC` |
| `github.com/gobwas/glob` | `v1.1.0` | indirect | `MIT` |
| `github.com/goccy/go-json` | `v0.11.2` | indirect | `MIT` |
| `github.com/jackc/pgpassfile` | `v1.0.0` | indirect | `MIT` |
| `github.com/jackc/pgservicefile` | `v0.0.0-20240606120523-5a60cdf6a761` | indirect | `MIT` |
| `github.com/jackc/puddle/v2` | `v2.2.3` | indirect | `MIT` |
| `github.com/lestrrat-go/blackmagic` | `v1.0.4` | indirect | `MIT` |
| `github.com/lestrrat-go/dsig` | `v1.4.0` | indirect | `MIT` |
| `github.com/lestrrat-go/dsig-secp256k1` | `v1.0.0` | indirect | `MIT` |
| `github.com/lestrrat-go/httpcc` | `v1.0.1` | indirect | `MIT` |
| `github.com/lestrrat-go/httprc/v3` | `v3.0.6` | indirect | `MIT` |
| `github.com/lestrrat-go/jwx/v3` | `v3.4.0` | indirect | `MIT` |
| `github.com/lestrrat-go/option/v2` | `v2.0.0` | indirect | `MIT` |
| `github.com/segmentio/asm` | `v1.2.1` | indirect | `MIT` |
| `github.com/sirupsen/logrus` | `v1.10.2` | indirect | `MIT` |
| `github.com/valyala/fastjson` | `v1.6.10` | indirect | `MIT` |
| `github.com/vektah/gqlparser/v2` | `v2.5.64` | indirect | `MIT` |
| `github.com/xeipuuv/gojsonpointer` | `v0.0.0-20190905194746-02993c407bfb` | indirect | `Apache-2.0` |
| `github.com/xeipuuv/gojsonreference` | `v0.0.0-20180127040603-bd5ef7bd5415` | indirect | `Apache-2.0` |
| `github.com/yashtewari/glob-intersection` | `v0.2.0` | indirect | `Apache-2.0` |
| `go.yaml.in/yaml/v3` | `v3.0.6` | indirect | `Apache-2.0 AND MIT` |
| `golang.org/x/net` | `v0.62.0` | indirect | `BSD-3-Clause` |
| `golang.org/x/sync` | `v0.25.0` | indirect | `BSD-3-Clause` |
| `golang.org/x/sys` | `v0.50.0` | indirect | `BSD-3-Clause` |
| `golang.org/x/text` | `v0.44.0` | indirect | `BSD-3-Clause` |
| `google.golang.org/protobuf` | `v1.36.12` | indirect | `BSD-3-Clause` |

---

## 3. Embedded React 19 Console Packages (`web/package.json` — 13 Packages)

| NPM Package | Version | Scope | Verified SPDX License |
| :--- | :--- | :--- | :--- |
| `@noble/ed25519` | `2.3.0` | runtime | `MIT` |
| `@noble/hashes` | `1.8.0` | runtime | `MIT` |
| `lucide-react` | `0.468.0` | runtime | `ISC` |
| `react` | `19.3.1` | runtime | `MIT` |
| `react-dom` | `19.3.1` | runtime | `MIT` |
| `@types/react` | `19.3.0` | build-dev | `MIT` |
| `@types/react-dom` | `19.3.0` | build-dev | `MIT` |
| `@vitejs/plugin-react` | `4.7.0` | build-dev | `MIT` |
| `autoprefixer` | `10.6.2` | build-dev | `MIT` |
| `postcss` | `8.5.33` | build-dev | `MIT` |
| `tailwindcss` | `3.4.19` | build-dev | `MIT` |
| `typescript` | `5.7.3` | build-dev | `Apache-2.0` |
| `vite` | `6.4.6` | build-dev | `MIT` |

---

## 4. Python Client SDK Dependencies (`sdk/python/pyproject.toml`)

| PyPI Package | Version | Scope | Verified SPDX License |
| :--- | :--- | :--- | :--- |
| `cryptography` | `>=42.0.0` | sdk-runtime | `Apache-2.0 OR BSD-3-Clause` |

---

## 5. Container Base Images, Databases & Open Standards

| Component / Standard | Role in G1-Warrant | License |
| :--- | :--- | :--- |
| `gcr.io/distroless/static:nonroot` | Production runtime base image (`warrantd`, `warrant-extractor`, `fleet-sim`) | `Apache-2.0` |
| `postgres:16-alpine` | Immutable trigger-protected WORM state & ledger database | `PostgreSQL` (Permissive) |
| `golang:1.26-alpine` / `node:22-alpine` | Multi-stage compile-only build containers (not shipped in runtime image) | `BSD-3-Clause` / `MIT` |
| `DSSE v1.0` / `in-toto` | Cryptographic signing envelope specification | `Apache-2.0` |
| `RFC 8785 (JCS)` / `W3C WebAuthn` | Deterministic JSON canonicalization & hardware PIV/FIDO2 standard | Open W3C / IETF Standard |
| `NIST OSCAL 1.1.2` / `SARIF 2.1.0` / `CycloneDX 1.5` / `OpenC2` | Compliance, vulnerability intake, SBOM & containment schemas | Public Domain / `Apache-2.0` / OASIS |

---

## 6. Out-of-Process DevSecOps CI Scanners (Clean-Room Process Boundary)

The 9-Gate Federal DevSecOps Harness (`scripts/compliance_harness.py`) invokes external open-source scanners strictly as **isolated out-of-process Docker containers** over HTTP or static report files (`./reports/`). Zero source code or binaries from these tools are linked into or distributed inside G1-Warrant:

| CI Gate Tool | Invocation Boundary | Upstream Tool License |
| :--- | :--- | :--- |
| `Semgrep` (`returntocorp/semgrep`) | Ephemeral CI Docker container -> `reports/semgrep.sarif` | `LGPL-2.1` (External CLI only) |
| `Gitleaks` (`zricethezav/gitleaks`) | Ephemeral CI Docker container -> `reports/gitleaks.sarif` | `MIT` |
| `Checkov` (`bridgecrew/checkov`) | Ephemeral CI Docker container -> `reports/checkov.sarif` | `Apache-2.0` |
| `Syft` (`anchore/syft`) | Ephemeral CI Docker container -> `reports/sbom.cdx.json` | `Apache-2.0` |
| `Trivy` (`aquasec/trivy`) | Ephemeral CI / opt-in `--profile live-feeds` sidecar -> HTTP `SARIF 2.1.0` | `Apache-2.0` |
| `OWASP ZAP` (`zaproxy/zap-stable`) | Ephemeral CI Docker container -> HTTP scan against `:8080` | `Apache-2.0` |
| `Grafana k6` (`grafana/k6`) | Ephemeral CI Docker container -> HTTP load test against `:8080` | `AGPL-3.0` (External load generator only) |
| `GovReady-Q` (`govready/govready-q`) | Separate external GRC container (`:8008`) -> OSCAL JSON export | `GPL-3.0` (External GRC platform only) |
