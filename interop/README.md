# Cross-implementation interop harness

Proves that state written by the Python reference (this repo) is honored by
the Go and PHP ports over ONE shared Redis, and vice versa. The Redis schema
(specs/08) is the wire contract; specs/07 (rate limiting) and specs/09 (IP
bans) own the semantics. Code wins over prose: every check below was
verified against `guard_core/` and the ports before being encoded here.

## Participants

| Participant | Repo | Runner | Mode |
|---|---|---|---|
| Python reference | this repo | `interop/py_participant.py` | `uv run`, real `RedisManager` / `IPBanManager` / `check_rate_limit_by_ip` / `RedisCloudIpStore` / `CloudManager` |
| Go port | `../guard-core-go` | `guardcore/interop_runner_test.go` (`//go:build interop`, in-package, env-driven) | `go test -tags interop -v -run '^TestInteropRunner$' ./guardcore` |
| PHP port | `../guard-core-php` | `bin/interop.php` | `php bin/interop.php` (env-driven phase) |

All three bind `127.0.0.1:6379` from the host and
`host.docker.internal:6379` from containers, share the single key prefix
`guard_core_interop:` on DB 0, and only ever touch keys under that prefix.
The orchestrator deletes exactly `{guard_core_interop:*}` before and after
every run, so runs are idempotent and a host Redis is left clean.

## Run

```bash
python3 interop/run.py
```

Requirements: host Redis on 6379, Docker (golang:1.25-alpine, php:8.3-cli
images), uv on PATH. Exits 0 with every check green; writes
`interop/last_run.json` and per-phase JSON reports to `interop/reports/`.

Each phase is one participant subprocess; the orchestrator asserts exit 0
and reads its JSON report (file, not stdout, so `go test` wrapper noise
does not matter). Artifacts (raw float strings, payload bytes) flow forward
so each reader phase byte-compares what the writer phase wrote.

## Phases and ledger

1. `py_write`: bans `203.0.113.7` and network `198.51.100.0/24`, seeds a
   LEGACY ban key in mapped form `{prefix}banned_ips:::ffff:203.0.113.9`,
   records 3 hits on bucket A (`{prefix}rate_limit:rate:192.0.2.10`),
   writes `cloud_ip_v2:AWS` (entries `203.0.113.0/25|us-east-1` and
   `203.0.113.128/25`) through `RedisCloudIpStore`.
2. `go_read_then_write`: migration runs inside the Go ban manager init;
   Go reads Python's bans, the migrated legacy key (value byte-exact, TTL
   preserved), the shared bucket A count (3 -> 4 through
   `RateLimitManager.CheckRateLimit`, then a blocked hit at limit 1 pins
   count 5), the AWS payload (decode + byte-exact re-encode) and the
   carve-out. Writes ban `192.0.2.66`, 2 hits on bucket B, `cloud_ip_v2:GCP`.
3. `php_read_then_write`: verifies everything from phases 1-2 (both
   writers' bans, migration state, bucket A=6 and B=3 continuity via
   blocked `checkRateLimit` hits, AWS+GCP caches + byte round-trip).
   Writes ban `192.0.2.77`, 2 hits on bucket C, `cloud_ip_v2:Azure`.
4. `py_verify`: Python honors the Go/PHP bans (raw expiry strings
   byte-equal), the migrated ban, bucket counts A=7 B=4 C=3, and all three
   cloud caches including carve-outs and byte round-trips.

Bucket ledger: A = 3(py) + 1(go obs) + 1(go crossing) + 1(php) + 1(py obs)
+ 1(py crossing) = 8; B = 2(go) + 1(php) + 1(py obs) = 4; C = 2(php) +
1(py obs) = 3. Every observation is itself a hit and is asserted against
this exact arithmetic inside the observing participant.

The float-string rule (spec 08) is exercised everywhere: every ban expiry
written by any implementation is read back byte-exactly and float-parsed by
the others, and all values carry non-integer fractions (microseconds).

## Known contract boundaries (documented by checks, not bugs)

- `banned_networks:*` has NO reader in any implementation, including the
  Python reference (specs/09 discrepancy 3). Cross-impl network-ban checks
  are wire-level via each port's own storage handler plus its own
  canonical-network parser; the manager-level negative is asserted too.
- Rate-limit zset members are opaque; scores are the observable floats.
  PHP `(string)` casts quantize to 14 significant digits (noted in the PHP
  repo's local KNOWN_GAPS.md; no parse divergence, no observable effect).
- `cloud_ip_v2` payloads are byte-exact across all three writers since the
  PHP port adopted Python's `", "` list separators (same category as the
  earlier JSON_UNESCAPED_SLASHES fix).

## Rust binary-body vectors

`interop/rust_binary_vectors.py` proves rust == python 4.0.3 on
binary-decoded request bodies without Redis: the Python reference and the
guard-core-rs engine (built from branch fix/binary-noise-gate-4.0.3)
scan the same payloads in-process and their verdicts are compared. See
the script docstring for the binding build steps and the surrogateescape
mapping note. The runner exits 0 when every vector is green and writes
`interop/reports/rust_binary_vectors.json`.

## Go/PHP binary-body detect vectors

`go_php_binary_vectors.py` proves that the Go and PHP engines (branch
`fix/binary-noise-gate-4.0.3`) and the Python reference produce identical
detect verdicts on binary-decoded request bodies: random noise, a zip
upload, attacks in plain and padded forms, and plain/accented/non-Latin
text controls. Payloads mirror the honesty suite classes from
`tests/test_sus_patterns/test_pattern_binary_noise_gate.py`. No Redis: the
detect stage is pure; the Go and PHP participants run inside their official
docker images against the ports' checkouts (paths default to the sibling
checkouts, override with `GUARD_CORE_GO_ROOT` / `GUARD_CORE_PHP_ROOT`).

```bash
GUARD_CORE_GO_ROOT=../guard-core-go GUARD_CORE_PHP_ROOT=../guard-core-php \
    uv run python interop/go_php_binary_vectors.py
```
