from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_evidence.cli import main
from technocore_evidence.core import (
    EvidenceError,
    normalize_message,
    public_key_from_did,
    verify_record,
)

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"  # pragma: allowlist secret


def base58_encode(value: bytes) -> str:
    number = int.from_bytes(value, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = ALPHABET[remainder] + encoded
    return "1" * (len(value) - len(value.lstrip(b"\0"))) + (encoded or "")


def signed_record(text: str = "reproducible signed evidence") -> dict[str, str]:
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    room = "technocore"
    nonce = "1724610000000"
    normalized = normalize_message(text)
    signature = key.sign(f"{room}|{nonce}|{normalized}".encode())
    return {
        "room": room,
        "from": "did:key:z" + base58_encode(b"\xed\x01" + public),
        "nonce": nonce,
        "text": normalized,
        "sig": base64.urlsafe_b64encode(signature).decode().rstrip("="),
    }


def test_valid_record_round_trips() -> None:
    record = signed_record()
    result = verify_record(record)
    assert result.valid is True
    assert result.as_dict()["did"] == record["from"]


def test_normalization_is_single_line_and_idempotent() -> None:
    assert normalize_message("a\nb\u200dc") == "a b c"
    assert normalize_message(normalize_message("a\nb")) == "a b"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("room", "Bad Room", "name grammar"),
        ("nonce", "-1", "ASCII digits"),
        ("nonce", "1" * 20, "ASCII digits"),
        ("from", "did:key:z0", "base58"),
        ("sig", "!" * 86, "base64url"),
    ],
)
def test_malformed_fields_fail_closed(field: str, value: str, message: str) -> None:
    record = signed_record()
    record[field] = value
    with pytest.raises(EvidenceError, match=message):
        verify_record(record)


def test_modified_message_fails_signature() -> None:
    record = signed_record()
    record["text"] += " altered"
    with pytest.raises(EvidenceError, match="signature verification failed"):
        verify_record(record)


def test_wrong_did_codec_fails() -> None:
    record = signed_record()
    record["from"] = "did:key:z" + base58_encode(b"\x00\x01" + bytes(32))
    with pytest.raises(EvidenceError, match="32-byte Ed25519"):
        verify_record(record)


def test_empty_did_material_and_non_string_did_fail() -> None:
    record = signed_record()
    record["from"] = "did:key:z"
    with pytest.raises(EvidenceError, match="base58 value is empty"):
        verify_record(record)
    record["from"] = 1  # type: ignore[assignment]
    with pytest.raises(EvidenceError, match="from must be a string"):
        verify_record(record)
    with pytest.raises(EvidenceError, match="must be an Ed25519"):
        public_key_from_did(1)  # type: ignore[arg-type]


def test_noncanonical_and_modified_signatures_fail() -> None:
    record = signed_record()
    record["sig"] = record["sig"][:-1] + ("A" if record["sig"][-1] != "A" else "B")
    with pytest.raises(EvidenceError, match="canonical|verification failed"):
        verify_record(record)


def test_unicode_digits_do_not_count_as_nonce() -> None:
    record = signed_record()
    record["nonce"] = "\uff11\uff12"
    with pytest.raises(EvidenceError, match="ASCII digits"):
        verify_record(record)


def test_oversized_text_fails() -> None:
    with pytest.raises(EvidenceError, match="4096"):
        normalize_message("x" * 4097)


def test_non_string_and_missing_fields_fail() -> None:
    with pytest.raises(EvidenceError, match="text must be a string"):
        normalize_message(1)  # type: ignore[arg-type]
    with pytest.raises(EvidenceError, match="sig must be a string"):
        verify_record({"room": "lobby", "from": "x", "nonce": "1", "text": "x"})


def test_cli_success_and_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = tmp_path / "good.json"
    bad = tmp_path / "bad.json"
    good.write_text(json.dumps(signed_record()), encoding="utf-8")
    bad.write_text("[]", encoding="utf-8")
    assert main([str(good)]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert main([str(bad)]) == 1
    assert json.loads(capsys.readouterr().out)["valid"] is False


def test_cli_rejects_invalid_json_and_missing_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    assert main([str(invalid)]) == 1
    assert json.loads(capsys.readouterr().out)["valid"] is False
    assert main([str(tmp_path / "missing.json")]) == 1
    assert json.loads(capsys.readouterr().out)["valid"] is False
