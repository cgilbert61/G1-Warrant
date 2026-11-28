# G1-Warrant Empirical Go Fuzz Testing Report

- **Generated:** `2026-11-28T00:01:11Z`
- **Environment:** Native Go `go1.26.2 windows/amd64` (`go test -fuzz=... -fuzztime=6s`, 6 workers)
- **Repository:** `D:\G1-Warrant` (`cgilbert61/G1-Warrant`)

## Native Go Fuzzing Results (`8/8 PASS`, `1,225,752` Total Executions)

| Package | Fuzz Target | Executions | Interesting Corpus | Status | Security Invariant Verified |
| :--- | :--- | ---: | ---: | :--- | :--- |
| `internal/crypto` | `FuzzCanonicalizeJSON` | 141,394 | 160 | `PASS` | RFC 8785 JCS never panics and is strictly idempotent |
| `internal/crypto` | `FuzzDSSEVerifyDualHuman` | 335,932 | 115 | `PASS` | Forged/malformed DSSE envelopes never pass dual-human verification or panic |
| `internal/crypto` | `FuzzSecretBoxOpenColumn` | 56,107 | 83 | `PASS` | AES-GCM column AAD seal/open round-trip holds; arbitrary tampered ciphertext never panics |
| `internal/extractor` | `FuzzParseUntrustedSARIF` | 277,499 | 122 | `PASS` | Untrusted SARIF 2.1.0 payloads never panic zero-prose extractor |
| `internal/extractor` | `FuzzParseUntrustedDiff` | 82,153 | 95 | `PASS` | Untrusted unified diffs never panic DDL/ORM/syscall analyzer |
| `internal/extractor` | `FuzzParseUntrustedSecretFindings` | 134,412 | 153 | `PASS` | Untrusted secret-scanner JSON never panics extractor |
| `internal/adapters/siem` | `FuzzParseCredentialRef` | 196,125 | 101 | `PASS` | Raw tokens, headers, PEMs, whitespace/NULs, and `..` path traversals never pass `credential_ref` validation |
| `internal/adapters/siem` | `FuzzSIEMFormattersNoInjection` | 2,130 | 6 | `PASS` | CEF:0, LEEF:2.0, RFC 5424 JSON, HEC, Elastic `_bulk`, Sentinel DCE, Chronicle UDM & NDJSON never emit raw CR/LF frame injection or malformed JSON |

## Running Locally

```powershell
go test ./internal/crypto -run=NONE -fuzz='^FuzzCanonicalizeJSON$' -fuzztime=10s
go test ./internal/crypto -run=NONE -fuzz='^FuzzDSSEVerifyDualHuman$' -fuzztime=10s
go test ./internal/crypto -run=NONE -fuzz='^FuzzSecretBoxOpenColumn$' -fuzztime=10s
go test ./internal/extractor -run=NONE -fuzz='^FuzzParseUntrustedSARIF$' -fuzztime=10s
go test ./internal/extractor -run=NONE -fuzz='^FuzzParseUntrustedDiff$' -fuzztime=10s
go test ./internal/extractor -run=NONE -fuzz='^FuzzParseUntrustedSecretFindings$' -fuzztime=10s
go test ./internal/adapters/siem -run=NONE -fuzz='^FuzzParseCredentialRef$' -fuzztime=10s
go test ./internal/adapters/siem -run=NONE -fuzz='^FuzzSIEMFormattersNoInjection$' -fuzztime=10s
```
