#!/usr/bin/env python3
"""Regenerate the checked-in Project Wycheproof signature vectors from pinned sources."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import sys
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

WYCHEPROOF_COMMIT = "65ca494727a52944c204441c860b039e6786b99b"
CRATE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Source:
    name: str
    file: str
    sha256: str

    @property
    def url(self) -> str:
        return (
            "https://raw.githubusercontent.com/C2SP/wycheproof/"
            f"{WYCHEPROOF_COMMIT}/testvectors_v1/{self.file}"
        )


ED25519 = Source(
    name="Project Wycheproof Ed25519 test vectors",
    file="ed25519_test.json",
    sha256="ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3",
)
ECDSA_SECP256R1_SHA256_P1363 = Source(
    name="Project Wycheproof ECDSA secp256r1 SHA-256 P1363 test vectors",
    file="ecdsa_secp256r1_sha256_p1363_test.json",
    sha256="c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986",
)
BLS_SIG_G2_BASIC = Source(
    name="Project Wycheproof BLS12-381 G2 basic signature test vectors",
    file="bls_sig_g2_basic_verify_test.json",
    sha256="f2792254b83b5563f56f4886d71fa416643a1ff07d52e131a324dceb6b0f36ea",
)
BLS_SIG_G2_POP = Source(
    name="Project Wycheproof BLS12-381 G2 proof-of-possession signature test vectors",
    file="bls_sig_g2_pop_verify_test.json",
    sha256="2dfa383d22f22f2d5009cf6626fd9558998592ed3b72b9a4f4b08f64b505b44d",
)

BLS_SIG_G2_BASIC_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
BLS_SIG_G2_POP_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

RESULTS = {"valid": "Valid", "acceptable": "Acceptable", "invalid": "Invalid"}
HEX_CHUNK = 64


@dataclass(frozen=True)
class Vector:
    tc_id: int
    result: str
    flags: list[str]
    public_key: str
    message: str
    signature: str


@dataclass(frozen=True)
class Output:
    path: Path
    sources: list[Source]
    tables: list[tuple[str, list[Vector]]]
    constants: list[tuple[str, str]]


def fetch(source: Source) -> dict:
    request = urllib.request.Request(
        source.url,
        headers={"User-Agent": "commonware-cryptography-test-vector-generator"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != source.sha256:
        raise ValueError(
            f"{source.name} digest changed: expected {source.sha256}, got {digest}"
        )
    return json.loads(data)


def check_header(
    data: dict, source: Source, algorithm: str, schema: str, count: int
) -> None:
    if data["algorithm"] != algorithm or data["schema"] != schema:
        raise ValueError(f"unexpected {source.name} metadata")
    if data["numberOfTests"] != count:
        raise ValueError(f"expected {count} {source.name}, got {data['numberOfTests']}")


def check_vectors(
    vectors: list[Vector], source: Source, results: dict[str, int]
) -> list[Vector]:
    if [vector.tc_id for vector in vectors] != list(range(1, len(vectors) + 1)):
        raise ValueError(f"{source.name} test IDs are not contiguous")
    counts = Counter(vector.result for vector in vectors)
    if counts != Counter(results):
        raise ValueError(f"unexpected {source.name} result counts: {dict(counts)}")
    for vector in vectors:
        for value in (vector.public_key, vector.message, vector.signature):
            bytes.fromhex(value)
    return vectors


def to_vector(test: dict, public_key: str) -> Vector:
    return Vector(
        tc_id=test["tcId"],
        result=test["result"],
        flags=test["flags"],
        public_key=public_key,
        message=test["msg"],
        signature=test["sig"],
    )


def parse_ed25519(data: dict) -> list[Vector]:
    check_header(data, ED25519, "EDDSA", "eddsa_verify_schema_v1.json", 210)
    vectors = []
    for group in data["testGroups"]:
        public_key = group["publicKey"]
        if (
            group["type"] != "EddsaVerify"
            or public_key["type"] != "EDDSAPublicKey"
            or public_key["curve"] != "edwards25519"
            or len(public_key["pk"]) != 64
        ):
            raise ValueError("unexpected Wycheproof Ed25519 test group")
        vectors.extend(to_vector(test, public_key["pk"]) for test in group["tests"])
    return check_vectors(
        vectors, ED25519, {"valid": 117, "acceptable": 29, "invalid": 64}
    )


def parse_ecdsa_secp256r1_sha256_p1363(data: dict) -> list[Vector]:
    source = ECDSA_SECP256R1_SHA256_P1363
    check_header(data, source, "ECDSA", "ecdsa_p1363_verify_schema_v1.json", 262)
    vectors = []
    for group in data["testGroups"]:
        public_key = group["publicKey"]
        if (
            group["type"] != "EcdsaP1363Verify"
            or group["sha"] != "SHA-256"
            or public_key["type"] != "EcPublicKey"
            or public_key["curve"] != "secp256r1"
        ):
            raise ValueError("unexpected Wycheproof ECDSA secp256r1 test group")
        x = int(public_key["wx"], 16).to_bytes(32, "big").hex()
        y = int(public_key["wy"], 16).to_bytes(32, "big").hex()
        uncompressed = public_key["uncompressed"]
        if uncompressed != "04" + x + y:
            raise ValueError("Wycheproof ECDSA secp256r1 public key is inconsistent")
        vectors.extend(to_vector(test, uncompressed) for test in group["tests"])
    return check_vectors(vectors, source, {"valid": 173, "invalid": 89})


def parse_bls(
    data: dict, source: Source, dst: str, count: int, results: dict[str, int]
) -> list[Vector]:
    check_header(data, source, "BLS", "bls_sig_verify_schema.json", count)
    vectors = []
    for group in data["testGroups"]:
        public_key = group["publicKey"]
        if (
            group["type"] != "BlsSigVerify"
            or group["ciphersuite"] != dst
            or public_key["group"] != "G1"
        ):
            raise ValueError(f"unexpected {source.name} test group")
        vectors.extend(to_vector(test, public_key["pk"]) for test in group["tests"])
    return check_vectors(vectors, source, results)


def hex_expr(value: str, indent: str) -> str:
    if not value:
        return "commonware_formatting::hex!()"
    if len(value) <= HEX_CHUNK:
        return f'commonware_formatting::hex!("0x{value}")'
    chunks = [value[i : i + HEX_CHUNK] for i in range(0, len(value), HEX_CHUNK)]
    lines = ["commonware_formatting::hex!("]
    for index, chunk in enumerate(chunks):
        prefix = "0x" if index == 0 else ""
        lines.append(f'{indent}    "{prefix}{chunk}"')
    lines.append(f"{indent})")
    return "\n".join(lines)


def render(output: Output) -> str:
    lines = [
        "// Generated by cryptography/generate_wycheproof_vectors.py.",
        "// Do not edit manually.",
        "//",
        "// Project Wycheproof (https://github.com/C2SP/wycheproof) is licensed under Apache-2.0.",
    ]
    lines.extend(f"// {source.name}: {source.url}" for source in output.sources)
    variants = sorted(
        {vector.result for _, vectors in output.tables for vector in vectors},
        key=list(RESULTS).index,
    )
    lines.extend(
        [
            "",
            "#[derive(Debug, PartialEq, Eq)]",
            "pub(super) enum Outcome {",
            *(f"    {RESULTS[variant]}," for variant in variants),
            "}",
            "",
            "pub(super) struct Vector {",
            "    pub(super) tc_id: u16,",
            "    pub(super) result: Outcome,",
            "    pub(super) flags: &'static [&'static str],",
            "    pub(super) public_key: &'static [u8],",
            "    pub(super) message: &'static [u8],",
            "    pub(super) signature: &'static [u8],",
            "}",
        ]
    )
    for name, value in output.constants:
        lines.extend(["", f'pub(super) const {name}: &[u8] = b"{value}";'])
    indent = "        "
    for name, vectors in output.tables:
        lines.extend(["", "#[rustfmt::skip]", f"pub(super) const {name}: &[Vector] = &["])
        for vector in vectors:
            flags = ", ".join(f'"{flag}"' for flag in vector.flags)
            lines.extend(
                [
                    "    Vector {",
                    f"        tc_id: {vector.tc_id},",
                    f"        result: Outcome::{RESULTS[vector.result]},",
                    f"        flags: &[{flags}],",
                    f"        public_key: &{hex_expr(vector.public_key, indent)},",
                    f"        message: &{hex_expr(vector.message, indent)},",
                    f"        signature: &{hex_expr(vector.signature, indent)},",
                    "    },",
                ]
            )
        lines.append("];")
    lines.append("")
    return "\n".join(lines)


def generate() -> list[tuple[Path, str]]:
    outputs = [
        Output(
            path=CRATE / "src" / "ed25519" / "wycheproof.rs",
            sources=[ED25519],
            tables=[("ED25519", parse_ed25519(fetch(ED25519)))],
            constants=[],
        ),
        Output(
            path=CRATE / "src" / "secp256r1" / "wycheproof.rs",
            sources=[ECDSA_SECP256R1_SHA256_P1363],
            tables=[
                (
                    "ECDSA_SECP256R1_SHA256_P1363",
                    parse_ecdsa_secp256r1_sha256_p1363(
                        fetch(ECDSA_SECP256R1_SHA256_P1363)
                    ),
                )
            ],
            constants=[],
        ),
        Output(
            path=CRATE / "src" / "bls12381" / "primitives" / "ops" / "wycheproof.rs",
            sources=[BLS_SIG_G2_BASIC, BLS_SIG_G2_POP],
            tables=[
                (
                    "BLS_SIG_G2_BASIC",
                    parse_bls(
                        fetch(BLS_SIG_G2_BASIC),
                        BLS_SIG_G2_BASIC,
                        BLS_SIG_G2_BASIC_DST,
                        88,
                        {"valid": 29, "invalid": 59},
                    ),
                ),
                (
                    "BLS_SIG_G2_POP",
                    parse_bls(
                        fetch(BLS_SIG_G2_POP),
                        BLS_SIG_G2_POP,
                        BLS_SIG_G2_POP_DST,
                        26,
                        {"valid": 13, "invalid": 13},
                    ),
                ),
            ],
            constants=[
                ("BLS_SIG_G2_BASIC_DST", BLS_SIG_G2_BASIC_DST),
                ("BLS_SIG_G2_POP_DST", BLS_SIG_G2_POP_DST),
            ],
        ),
    ]
    return [(output.path, render(output)) for output in outputs]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the checked-in vectors differ from regenerated output",
    )
    args = parser.parse_args()
    generated = generate()

    if args.check:
        stale = False
        for path, text in generated:
            checked_in = path.read_text(encoding="ascii") if path.exists() else ""
            if checked_in != text:
                stale = True
                sys.stdout.writelines(
                    difflib.unified_diff(
                        checked_in.splitlines(keepends=True),
                        text.splitlines(keepends=True),
                        fromfile=str(path),
                        tofile="regenerated",
                    )
                )
        return 1 if stale else 0

    for path, text in generated:
        with path.open("w", encoding="ascii", newline="\n") as output:
            output.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
