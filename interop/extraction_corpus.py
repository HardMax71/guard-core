#!/usr/bin/env python3
"""Body-extraction differential corpus.

Generates the (body bytes, content-type) pairs the extraction differential
runner (extraction_differential.py) feeds to every family's extractor:
roughly 60 crafted bodies covering form fields, multipart text and binary
file parts, nested multipart containers, JSON walks (mongo operator keys,
embedded JSON leaves, depth-cap boundaries, number renderings, malformed
bodies) and mixed/malformed edge cases, plus roughly 150 seeded random
mutations of the same classes.

The corpus is deliberately clean-first: the extraction multiset comparison
has no first-hit truncation ambiguity on bodies without threats, and the
attack-carrying bodies are there to pin that the attack lands in the SAME
extracted value everywhere (the detect-level verdicts are the body detect
vector runner's job, body_detect_vectors.py).
"""

from __future__ import annotations

import io
import json
import random
import zipfile
from typing import Any

FORM_CT = "application/x-www-form-urlencoded"
JSON_CT = "application/json"
TEXT_CT = "text/plain"
BOUNDARY = "guardinterop7d1a"
MPART_CT = f"multipart/form-data; boundary={BOUNDARY}"

ATTACKS = (
    "`rm -rf /`",
    "$(cat /etc/passwd)",
    "1' UNION SELECT username,password FROM users--",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "/default.asp",
    "\\README.md",
)

NOISE_BYTES = bytes(range(0, 256)) * 4


def _multipart(parts: list[bytes], boundary: str = BOUNDARY) -> bytes:
    body = b""
    for part in parts:
        body += b"--" + boundary.encode() + b"\r\n" + part + b"\r\n"
    body += b"--" + boundary.encode() + b"--\r\n"
    return body


def _field(name: str, value: str, extra_headers: str = "") -> bytes:
    header = (
        f'Content-Disposition: form-data; name="{name}"'.encode()
        + extra_headers.encode()
        + b"\r\n\r\n"
    )
    return header + value.encode("utf-8", "surrogatepass")


def _file(name: str, filename: str, payload: bytes, ctype: str = "") -> bytes:
    header = (
        f'Content-Disposition: form-data; name="{name}"; filename="{filename}"'.encode()
    )
    if ctype:
        header += f"\r\nContent-Type: {ctype}".encode()
    return header + b"\r\n\r\n" + payload


def _zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("attachment.bin", NOISE_BYTES[:50000])
    return buffer.getvalue()


def _deep_json(depth: int, leaf: str = "clean") -> str:
    return '{"a":' * depth + f'"{leaf}"' + "}" * depth


def _crafted() -> list[tuple[str, bytes, str]]:
    cases: list[tuple[str, bytes, str]] = []

    # --- urlencoded form bodies ------------------------------------------
    cases.append(("form_simple", b"user=bob&role=admin", FORM_CT))
    cases.append(("form_blank_value", b"user=&role=", FORM_CT))
    cases.append(("form_no_equals", b"flagme&user=bob", FORM_CT))
    cases.append(("form_double_equals", b"expr=a=b=c", FORM_CT))
    cases.append(("form_plus_spaces", b"note=hello+world+again", FORM_CT))
    cases.append(("form_pct_valid", b"name=Caf%C3%A9&city=Se%C3%BAl", FORM_CT))
    cases.append(("form_pct_invalid", b"name=%ZZ&raw=%2", FORM_CT))
    cases.append(("form_pct_binary", b"blob=%85%9f%9e", FORM_CT))
    cases.append(("form_empty", b"", FORM_CT))
    cases.append(("form_only_amp", b"&&&", FORM_CT))
    cases.append(("form_sqli_value", b"q=1%27%20UNION%20SELECT%20name", FORM_CT))
    cases.append(("form_bare_sap", b"system=SAP", FORM_CT))
    cases.append(("form_bare_default", b"page=default", FORM_CT))
    cases.append(("form_backslash_probe", b"next=%5Cdefault.asp", FORM_CT))
    cases.append(("form_ldap_probe", b"next=%5C2fdefault.asp", FORM_CT))
    cases.append(
        ("form_embedded_json", b'payload={"user":"bob","roles":["a","b"]}', FORM_CT)
    )
    cases.append(("form_embedded_json_mongo", b'q={"$where":"x","$ne":1}', FORM_CT))
    cases.append(
        ("form_embedded_json_attack", b'q={"path":"../../../etc/passwd"}', FORM_CT)
    )
    cases.append(
        ("form_embedded_json_string_leaf", b'q={"a":"{\\"b\\":\\"c\\"}"}', FORM_CT)
    )
    cases.append(("form_attack_name", b"etc%2Fpasswd=bob", FORM_CT))

    # --- multipart bodies -------------------------------------------------
    cases.append(
        (
            "mp_text_field",
            _multipart([_field("name", "bob"), _field("note", "hello world")]),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_text_file",
            _multipart([_file("doc", "report.txt", b"quarterly numbers look fine")]),
            MPART_CT,
        )
    )
    binary_payload = (
        bytes([0x85]) * 40
        + b"cat /etc/passwd"
        + bytes([0x87]) * 40
        + b"../../etc/passwd"
        + bytes([0x86]) * 40
    )
    cases.append(
        (
            "mp_binary_file_islands",
            _multipart(
                [_file("blob", "blob.bin", binary_payload, "application/octet-stream")]
            ),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_binary_file_clean_islands",
            _multipart(
                [
                    _file(
                        "blob",
                        "blob.bin",
                        NOISE_BYTES[:4000],
                        "application/octet-stream",
                    )
                ]
            ),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_zip_upload",
            _multipart(
                [_file("attachment", "backup.zip", _zip_bytes(), "application/zip")]
            ),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_binary_field_no_filename",
            _multipart(
                [
                    _field(
                        "blob",
                        (
                            bytes([0x85]) * 40
                            + b"$(cat /etc/passwd)"
                            + bytes([0x87]) * 40
                        ).decode("latin-1"),
                    )
                ]
            ),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_mixed",
            _multipart(
                [
                    _field("name", "bob"),
                    _file("doc", "report.txt", b"clean text payload"),
                    _file(
                        "blob", "blob.bin", binary_payload, "application/octet-stream"
                    ),
                ]
            ),
            MPART_CT,
        )
    )
    nested_inner = _multipart(
        [_file("inner", "inner.txt", b"inner clean payload")], "innerbound42"
    )
    outer_part = (
        b'Content-Disposition: form-data; name="nested"; filename="nested.bin"\r\n'
        b"Content-Type: multipart/mixed; boundary=innerbound42\r\n\r\n" + nested_inner
    )
    cases.append(("mp_nested", _multipart([outer_part]), MPART_CT))
    cases.append(
        (
            "mp_no_close_boundary",
            (
                b"--"
                + BOUNDARY.encode()
                + b"\r\nContent-Disposition: form-data; "
                + b'name="a"\r\n\r\nvalue runs to end'
            ),
            MPART_CT,
        )
    )
    cases.append(("mp_no_boundary_param", b"--x\r\nwhatever", "multipart/form-data"))
    cases.append(
        (
            "mp_boundary_mismatch",
            _multipart([_field("a", "b")], "otherbound"),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_preamble_epilogue",
            (
                b"preamble garbage here\r\n--"
                + BOUNDARY.encode()
                + b'\r\nContent-Disposition: form-data; name="a"\r\n\r\nvalue\r\n--'
                + BOUNDARY.encode()
                + b"--\r\nepilogue junk"
            ),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_folded_header",
            (
                b"--"
                + BOUNDARY.encode()
                + b"\r\nContent-Disposition: form-data;\r\n "
                + b'name="folded"\r\n\r\nfolded value'
                + b"\r\n--"
                + BOUNDARY.encode()
                + b"--\r\n"
            ),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_colonless_header_line",
            (
                b"--"
                + BOUNDARY.encode()
                + b"\r\nnot a header line just text"
                + b"\r\nmore payload $(cat /etc/passwd)\r\n--"
                + BOUNDARY.encode()
                + b"--\r\n"
            ),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_quoted_filename_escapes",
            _multipart([_file("doc", 'weird\\"name.txt', b"clean payload")]),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_rfc2231_filename",
            (
                b"--"
                + BOUNDARY.encode()
                + b'\r\nContent-Disposition: form-data; name="doc"; '
                + b"filename*=utf-8''r%C3%A9sum%C3%A9.txt\r\n\r\nclean rfc2231 payload"
                + b"\r\n--"
                + BOUNDARY.encode()
                + b"--\r\n"
            ),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_empty_payload_part",
            _multipart([_field("empty", "")]),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_attack_filename",
            _multipart([_file("doc", "../../../etc/passwd", b"clean payload")]),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_embedded_json_field",
            _multipart([_field("data", '{"server":{"path":"default"}}')]),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_mongo_key_field",
            _multipart([_field("q", '{"$exists":true,"$where":"x"}')]),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_bare_sap",
            _multipart([_field("system", "SAP")]),
            MPART_CT,
        )
    )
    cases.append(
        (
            "mp_backslash_probe_field",
            _multipart([_field("next", "\\default.asp")]),
            MPART_CT,
        )
    )

    # --- JSON content types -----------------------------------------------
    cases.append(("json_object", b'{"user":"bob","role":"admin"}', JSON_CT))
    cases.append(("json_array", b'[1,"two",3]', JSON_CT))
    cases.append(("json_mongo_keys", b'{"$ne":1,"filter":{"$where":"x"}}', JSON_CT))
    cases.append(
        ("json_attack_leaf", b'{"path":"../../../etc/passwd","q":"1 OR 1=1"}', JSON_CT)
    )
    cases.append(("json_bare_sap_leaf", b'{"system":"SAP"}', JSON_CT))
    cases.append(("json_bare_default_leaf", b'{"page":"default"}', JSON_CT))
    cases.append(("json_backslash_leaf", b'{"next":"\\\\default.asp"}', JSON_CT))
    cases.append(("json_empty_object", b"{}", JSON_CT))
    cases.append(("json_malformed", b'{"a": nope}', JSON_CT))
    cases.append(("json_scalar_root", b'"just a string"', JSON_CT))
    cases.append(("json_trailing_data", b'{"a":1} trailing', JSON_CT))
    cases.append(
        (
            "json_numbers",
            b'{"a":1e2,"b":100.0,"c":-0,"d":123456789012345678901234567890,"e":0.1}',
            JSON_CT,
        )
    )
    cases.append(("json_special_floats", b"[NaN, Infinity, -Infinity]", JSON_CT))
    cases.append(("json_dup_keys", b'{"a":1,"a":2}', JSON_CT))
    cases.append(("json_bools_nulls", b'{"t":true,"f":false,"n":null}', JSON_CT))
    cases.append(
        (
            "json_unicode_escapes",
            b'{"emoji":"\\ud83d\\ude00","cyr":"\\u0434\\u0430"}',
            JSON_CT,
        )
    )
    cases.append(("json_depth_31", _deep_json(31).encode(), JSON_CT))
    cases.append(("json_depth_32", _deep_json(32).encode(), JSON_CT))
    cases.append(("json_depth_33", _deep_json(33).encode(), JSON_CT))
    cases.append(
        (
            "json_key_is_attack",
            b'{"../../../etc/passwd":"value","`rm -rf /`":2}',
            JSON_CT,
        )
    )
    cases.append(
        (
            "json_generic_ct",
            b'{"user":"bob"}',
            "text/json; charset=utf-8",
        )
    )
    cases.append(
        (
            "json_embedded_in_string_leaf",
            b'{"outer":"{\\"inner\\":\\"/default.asp\\"}"}',
            "application/vnd.api+json",
        )
    )

    # --- blob / unknown content types --------------------------------------
    cases.append(("blob_plain_text", b"just some plain prose text", TEXT_CT))
    cases.append(
        ("blob_sql_injection", b"1' UNION SELECT password FROM users--", TEXT_CT)
    )
    cases.append(("blob_binary_noise", NOISE_BYTES[:2000], "application/octet-stream"))
    cases.append(("blob_empty_body", b"", TEXT_CT))
    cases.append(
        (
            "blob_multipart_ct_body_not_multipart",
            b"random prose, no boundaries",
            MPART_CT,
        )
    )
    cases.append(("blob_form_ct_not_form", b"this is not urlencoded at all", FORM_CT))

    return cases


_TEMPLATES = ("form", "mpart", "json", "blob")
_FRAGMENTS = (
    "user=bob",
    "q=default",
    "system=SAP",
    'payload={"a":{"$ne":1}}',
    'payload={"k":"/default.asp"}',
    "\\README.md",
    "\\2fdefault.asp",
    "next=%5Cdefault",
    "1' OR '1'='1",
    "$(cat /etc/passwd)",
    "../../../etc/passwd",
    "<script>alert(1)</script>",
    "caf%C3%A9",
    "%85%9f",
    "clean prose value",
    "README.md",
    '{"$where":"1==1"}',
    '{"leaf":"actuator"}',
)


def _random_body(rng: random.Random) -> tuple[bytes, str]:
    template = rng.choice(_TEMPLATES)
    if template == "form":
        pair_count = rng.randrange(1, 5)
        chunks = []
        for _ in range(pair_count):
            name = rng.choice(_FRAGMENTS).split("=")[0]
            value = rng.choice(_FRAGMENTS).split("=", 1)[-1]
            if rng.random() < 0.3:
                value = value.replace("%", "%%2F", 1)
            sep = "=" if rng.random() < 0.9 else ""
            chunks.append(f"{name}{sep}{value}")
        body = "&".join(chunks)
        return body.encode("utf-8", "surrogatepass"), FORM_CT
    if template == "mpart":
        parts: list[bytes] = []
        for i in range(rng.randrange(1, 4)):
            kind = rng.random()
            name = f"f{i}"
            if kind < 0.4:
                parts.append(_field(name, rng.choice(_FRAGMENTS)))
            elif kind < 0.7:
                parts.append(
                    _file(
                        name,
                        rng.choice(("a.txt", "b.bin")),
                        rng.choice(_FRAGMENTS).encode(),
                    )
                )
            else:
                pad = bytes(
                    rng.randrange(0x80, 0x100) for _ in range(rng.randrange(0, 120))
                )
                payload = pad + rng.choice(_FRAGMENTS).encode() + pad
                parts.append(
                    _file(name, "blob.bin", payload, "application/octet-stream")
                )
        closing = rng.random()
        mp_body = b""
        for part in parts:
            mp_body += b"--" + BOUNDARY.encode() + b"\r\n" + part + b"\r\n"
        if closing < 0.85:
            mp_body += b"--" + BOUNDARY.encode() + b"--\r\n"
        if rng.random() < 0.15:
            mp_body = b"preamble\r\n" + mp_body
        return mp_body, MPART_CT
    if template == "json":
        depth = rng.randrange(1, 5)
        inner: Any = rng.choice(_FRAGMENTS)
        for _ in range(depth):
            if rng.random() < 0.5:
                inner = {f"k{rng.randrange(9)}": inner}
            else:
                inner = [inner, rng.choice(_FRAGMENTS)]
        text = json.dumps(inner)
        if rng.random() < 0.15:
            text = text[:-1]
        return text.encode(), JSON_CT
    fragments = rng.sample(_FRAGMENTS, rng.randrange(1, 4))
    return " ".join(fragments).encode(), rng.choice(
        (TEXT_CT, "application/octet-stream", "")
    )


def corpus() -> list[tuple[str, bytes, str]]:
    """(label, body bytes, content type) triples for the differential run."""
    cases = _crafted()
    rng = random.Random(20260926)
    for i in range(150):
        body, ctype = _random_body(rng)
        cases.append((f"rand_{i:03d}", body, ctype))
    return cases


if __name__ == "__main__":
    entries = corpus()
    print(f"{len(entries)} corpus entries")
    for label, body, ctype in entries[:5]:
        print(f"  {label}: {ctype} {body[:60]!r}")
