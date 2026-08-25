from __future__ import annotations

import base64
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOM_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
DID_PREFIX = "did:key:z"
ED25519_MULTICODEC = b"\xed\x01"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"  # pragma: allowlist secret
BASE58_INDEX = {character: index for index, character in enumerate(BASE58_ALPHABET)}


class EvidenceError(ValueError):
    """Raised when evidence is malformed or its signature does not verify."""


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    did: str
    room: str
    nonce: str
    normalized_text: str

    def as_dict(self) -> dict[str, str | bool]:
        return asdict(self)


def normalize_message(text: str) -> str:
    """Apply Technocore's documented single-line invisible-character sweep."""
    if not isinstance(text, str):
        raise EvidenceError("text must be a string")
    normalized = "".join(
        " " if unicodedata.category(char) in {"Cc", "Cf"} else char for char in text
    )
    if len(normalized) > 4096:
        raise EvidenceError("text exceeds the 4096-character Technocore limit")
    return normalized


def _base58_decode(value: str) -> bytes:
    if not value:
        raise EvidenceError("base58 value is empty")
    number = 0
    try:
        for character in value:
            number = number * 58 + BASE58_INDEX[character]
    except KeyError as exc:
        raise EvidenceError(f"invalid base58 character: {exc.args[0]}") from exc
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeroes + decoded


def public_key_from_did(did: str) -> Ed25519PublicKey:
    if not isinstance(did, str) or not did.startswith(DID_PREFIX):
        raise EvidenceError("from must be an Ed25519 did:key using base58btc")
    decoded = _base58_decode(did.removeprefix(DID_PREFIX))
    if len(decoded) != 34 or not decoded.startswith(ED25519_MULTICODEC):
        raise EvidenceError("DID does not contain a 32-byte Ed25519 public key")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def _decode_signature(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{86}", value):
        raise EvidenceError("sig must be an unpadded 86-character base64url value")
    decoded = base64.b64decode(value + "==", altchars=b"-_", validate=True)
    if len(decoded) != 64 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise EvidenceError("sig is not a canonical Ed25519 signature")
    return decoded


def _field(record: Mapping[str, Any], name: str) -> str:
    value = record.get(name)
    if not isinstance(value, str):
        raise EvidenceError(f"{name} must be a string")
    return value


def verify_record(record: Mapping[str, Any]) -> VerificationResult:
    """Verify one JSON Technocore signed-message record without network access."""
    room = _field(record, "room")
    if not ROOM_RE.fullmatch(room):
        raise EvidenceError("room does not match Technocore's name grammar")
    did = _field(record, "from")
    nonce = _field(record, "nonce")
    if not nonce.isascii() or not nonce.isdigit() or not 1 <= len(nonce) <= 19:
        raise EvidenceError("nonce must contain 1-19 ASCII digits")
    text = normalize_message(_field(record, "text"))
    signature = _decode_signature(_field(record, "sig"))
    payload = f"{room}|{nonce}|{text}".encode()
    try:
        public_key_from_did(did).verify(signature, payload)
    except InvalidSignature as exc:
        raise EvidenceError("signature verification failed") from exc
    return VerificationResult(True, did, room, nonce, text)
