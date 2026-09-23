#!/usr/bin/env python3
"""Go == PHP == Python 4.0.3 binary-body detect vectors.

Proves that the guard-core-go and guard-core-php engines (branch
fix/binary-noise-gate-4.0.3) and the Python reference (guard-core 4.0.3, the
binary-body noise gate from commit 436d6f72) produce identical detect
verdicts on binary-decoded request bodies: random noise, a zip upload,
attacks in plain and padded forms, and plain/accented/non-Latin text
controls.

The payloads are the same classes (and, for the noise seeds, the same
bytes) as guard-core's tests/test_sus_patterns/
test_pattern_binary_noise_gate.py honesty suite.

Run from the guard-core checkout (no Redis needed; the detect stage is
pure). The Go and PHP participants run inside their official docker images
against the ports' checkouts:

    GUARD_CORE_GO_ROOT=/Users/you/guard-core-go \
        GUARD_CORE_PHP_ROOT=/Users/you/guard-core-php \
        uv run python interop/go_php_binary_vectors.py

Both roots default to the sibling checkouts of this repository. Exits 0 with
every vector green; writes a JSON report to
interop/reports/go_php_binary_vectors.json.

Representation note: the Python reference decodes request bytes with
surrogateescape (undecodable bytes surface as U+DC80..U+DCFF surrogates).
The Go and PHP engines scan UTF-8 text and represent undecodable bytes as
U+FFFD (an artifact class in every engine), so surrogate-bearing payloads
are lossily re-decoded before reaching those participants; verdicts compare
is_threat, threat_score and the (category, pattern) threat multiset, which
the 4.0.3 spec-4.0.3 conformance corpus pins as representation-invariant.
Code-point lengths are only compared when the payload crossed the boundary
unchanged (per-byte surrogates vs collapsed U+FFFD runs legitimately shift
the count).
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

GUARD_CORE_ROOT = Path(__file__).resolve().parent.parent
GO_ROOT = Path(
    os.environ.get("GUARD_CORE_GO_ROOT", GUARD_CORE_ROOT.parent / "guard-core-go")
)
PHP_ROOT = Path(
    os.environ.get("GUARD_CORE_PHP_ROOT", GUARD_CORE_ROOT.parent / "guard-core-php")
)
_MULTIPART_FIELD_CONTEXT = "request_body:multipart_field"
_NOISE_SIZE = 262144
# Same seeds and decode views as the upstream honesty suite.
_NOISE_SEEDS = (1, 3)
_DECODED_VIEWS = ("latin-1", "utf-8-surrogateescape")

_ATTACK_PAYLOADS = (
    "`rm -rf /`",
    "$(cat /etc/passwd)",
    "c'a't config.ini",
    "'; DROP TABLE users;--",
    "../../../etc/passwd",
)

_PLAIN_TEXT_SAMPLES = (
    "Café résumé naïve décor sélection",
    "日本語のテキストです。中国語與繁體字。한국어 텍스트",
    "кириллица и русский текст",
)

_BURIED_FRAGMENTS = (
    "\x85" * 200 + ".." + "\x9f\x9e\x9d\x9c" + "/" + "\x87" * 200,
    "\x85" * 200 + "$(cat /etc/passwd)" + "\x87" * 200,
)

_CONTROL_ONLY = (
    "\x00" * 500,
    "".join(chr(i) for i in range(1, 32)) * 40,
    "\x7f" * 300,
)


def _noise_bytes(seed: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(_NOISE_SIZE))


def _decoded_noise(seed: int, decoding: str) -> str:
    raw = _noise_bytes(seed)
    if decoding == "latin-1":
        return raw.decode("latin-1")
    return raw.decode("utf-8", errors="surrogateescape")


def _zip_bytes(seed: int) -> bytes:
    import io

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("attachment.bin", _noise_bytes(seed)[:50000])
    return buffer.getvalue()


def _vectors() -> list[tuple[str, str]]:
    """(label, payload) pairs covering the honesty-suite classes."""
    vectors: list[tuple[str, str]] = []
    for seed in _NOISE_SEEDS:
        for decoding in _DECODED_VIEWS:
            vectors.append((f"noise_{seed}_{decoding}", _decoded_noise(seed, decoding)))
    vectors.append(
        (
            "zip_upload",
            _zip_bytes(seed=11).decode("utf-8", errors="surrogateescape"),
        )
    )
    for i, payload in enumerate(_ATTACK_PAYLOADS):
        vectors.append((f"attack_{i}", payload))
    for i, sample in enumerate(_PLAIN_TEXT_SAMPLES):
        vectors.append((f"text_{i}", sample))
        vectors.append((f"text_backtick_{i}", f"{sample}; `rm -rf /`"))
    vectors.append(("near_start", "../../../etc/passwd and more prose here"))
    vectors.append(("near_end", "prose " * 30 + "../../../etc/passwd"))
    vectors.append(("short_margin", "café '; DELETE FROM users;--"))
    for i, control_only in enumerate(_CONTROL_ONLY):
        vectors.append((f"control_only_{i}", control_only))
    for i, payload in enumerate(_BURIED_FRAGMENTS):
        vectors.append((f"buried_{i}", payload))
    return vectors


def _engine_payload(payload: str) -> tuple[str, bool]:
    """Map a Python surrogateescape string into the Go/PHP engines' world.

    Both engines scan UTF-8 text and represent undecodable bytes as U+FFFD
    (an artifact class in every engine). Re-encode to the original bytes and
    lossily decode. The boolean reports whether the payload crossed the
    boundary unchanged (no surrogates), which gates the length comparison.
    """
    try:
        payload.encode("utf-8")
        return payload, True
    except UnicodeEncodeError:
        return payload.encode("utf-8", "surrogatepass").decode(
            "utf-8", "replace"
        ), False


def _canonical_threats(verdict: dict[str, Any]) -> list[tuple[str, str]]:
    return sorted(
        (str(t.get("category", "")), str(t.get("pattern", "")))
        for t in verdict.get("threats", [])
    )


def _compare(
    py_verdict: dict[str, Any],
    engine_verdict: dict[str, Any],
    engine: str,
    payload_is_unmapped: bool,
) -> list[str]:
    diffs: list[str] = []
    if bool(py_verdict["is_threat"]) != bool(engine_verdict["is_threat"]):
        diffs.append(
            f"is_threat {py_verdict['is_threat']} != {engine_verdict['is_threat']}"
        )
    py_score = round(py_verdict["threat_score"], 6)
    engine_score = round(engine_verdict["threat_score"], 6)
    if py_score != engine_score:
        diffs.append(f"threat_score {py_score:.6f} != {engine_score:.6f}")
    if (
        payload_is_unmapped
        and py_verdict["original_length"] != engine_verdict["original_length"]
    ):
        diffs.append("original_length")
    py_threats = _canonical_threats(py_verdict)
    engine_threats = _canonical_threats(engine_verdict)
    if py_threats != engine_threats:
        diffs.append(f"threats {py_threats} != {engine_threats}")
    if diffs:
        return [f"{engine}: {diff}" for diff in diffs]
    return []


def _run_go_probe(vectors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    input_path = GUARD_CORE_ROOT / "interop" / "reports" / "go_probe_input.json"
    output_path = GUARD_CORE_ROOT / "interop" / "reports" / "go_probe_output.json"
    input_path.write_text(json.dumps(vectors, indent=2))
    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{GO_ROOT}:/app",
        "-v",
        f"{GUARD_CORE_ROOT / 'interop'}:/interop",
        "-w",
        "/app",
        "-e",
        "INTEROP_VECTORS_INPUT=/interop/reports/go_probe_input.json",
        "-e",
        "INTEROP_VECTORS_OUTPUT=/interop/reports/go_probe_output.json",
        "-e",
        "GOCACHE=/tmp/gocache",
        "golang:1.25-alpine",
        "go",
        "test",
        "-tags",
        "interop",
        "-v",
        "-run",
        "^TestBinaryVectorProbe$",
        "-count=1",
        "./guardcore",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
    if result.returncode != 0:
        raise SystemExit(
            f"go probe exited {result.returncode}: "
            f"{(result.stdout + result.stderr)[-2000:]}"
        )
    verdicts: list[dict[str, Any]] = json.loads(output_path.read_text())
    return verdicts


def _run_php_probe(vectors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    input_path = GUARD_CORE_ROOT / "interop" / "reports" / "php_probe_input.json"
    output_path = GUARD_CORE_ROOT / "interop" / "reports" / "php_probe_output.json"
    input_path.write_text(json.dumps(vectors, indent=2))
    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{PHP_ROOT}:/app",
        "-v",
        f"{GUARD_CORE_ROOT / 'interop'}:/interop",
        "-w",
        "/app",
        "-e",
        "INTEROP_VECTORS_INPUT=/interop/reports/php_probe_input.json",
        "-e",
        "INTEROP_VECTORS_OUTPUT=/interop/reports/php_probe_output.json",
        "php:8.3-cli",
        "php",
        "bin/binary_vector_probe.php",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
    if result.returncode != 0:
        raise SystemExit(
            f"php probe exited {result.returncode}: "
            f"{(result.stdout + result.stderr)[-2000:]}"
        )
    verdicts: list[dict[str, Any]] = json.loads(output_path.read_text())
    return verdicts


async def _py_verdicts() -> dict[str, dict[str, Any]]:
    from guard_core.handlers.suspatterns_handler import SusPatternsManager
    from guard_core.models import SecurityConfig

    config = SecurityConfig(
        detection_compiler_timeout=2.0,
        detection_max_content_length=10000,
        detection_preserve_attack_patterns=True,
        detection_semantic_threshold=0.7,
        detection_anomaly_threshold=3.0,
        detection_slow_pattern_threshold=0.1,
        detection_monitor_history_size=1000,
        detection_max_tracked_patterns=1000,
    )
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    manager = SusPatternsManager(config)

    async def _detect(payload: str) -> dict[str, Any]:
        return await manager.detect(
            payload, "127.0.0.1", context=_MULTIPART_FIELD_CONTEXT
        )

    verdicts: dict[str, dict[str, Any]] = {}
    for label, payload in _vectors():
        verdicts[label] = await _detect(payload)
    return verdicts


def main() -> int:
    started = time.monotonic()
    vectors = []
    unmapped: dict[str, bool] = {}
    for label, payload in _vectors():
        engine_payload, unchanged = _engine_payload(payload)
        unmapped[label] = unchanged
        vectors.append(
            {
                "label": label,
                "payload_b64": base64.b64encode(
                    engine_payload.encode("utf-8", "surrogatepass")
                ).decode("ascii"),
            }
        )

    print(f"running {len(vectors)} vectors through go and php probes...")
    py_verdicts = asyncio.run(_py_verdicts())
    go_verdicts = _run_go_probe(vectors)
    php_verdicts = _run_php_probe(vectors)

    report: dict[str, Any] = {"vectors": [], "green": 0, "red": 0}
    for entry in vectors:
        label = entry["label"]
        py_verdict = py_verdicts[label]
        diffs: list[str] = []
        for engine, engine_verdicts in (
            ("go", go_verdicts),
            ("php", php_verdicts),
        ):
            match = next((v for v in engine_verdicts if v["label"] == label), None)
            if match is None:
                diffs.append(f"{engine}: no verdict returned")
                continue
            diffs.extend(_compare(py_verdict, match, engine, unmapped[label]))
        entry_report = {
            "label": label,
            "payload_b64_bytes": len(entry["payload_b64"]),
            "py_is_threat": bool(py_verdict["is_threat"]),
            "diffs": diffs,
        }
        report["vectors"].append(entry_report)
        if diffs:
            report["red"] += 1
            print(f"RED   {label}: {diffs}")
        else:
            report["green"] += 1
            print(f"green {label} (is_threat={entry_report['py_is_threat']})")

    report["elapsed_s"] = round(time.monotonic() - started, 2)
    reports = Path(__file__).parent / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "go_php_binary_vectors.json").write_text(json.dumps(report, indent=2))
    total = report["green"] + report["red"]
    print(f"\ntotal: {report['green']}/{total} vectors green in {report['elapsed_s']}s")
    print("RESULT:", "GREEN" if report["red"] == 0 else "RED")
    return 0 if report["red"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
