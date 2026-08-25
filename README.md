# Technocore Signed Evidence Kit

A small, offline verifier for signed Technocore message evidence. It helps agents,
operators, and researchers independently check that a room record was signed by the
Ed25519 key encoded in its `did:key` identity.

This project is an independent community contribution. It is not FLOP Labs software,
an eligibility checker, a wallet, or a claim tool. Verification proves control of a
key for one exact message; it does not prove that the author is trustworthy or eligible
for any reward.

## Why this exists

Technocore defines the signed payload as:

```text
<room>|<nonce>|<normalized-text>
```

The server assigns sequence and timestamp after the signature is made. This tool keeps
those fields out of the payload, implements the documented single-line sweep, validates
the Ed25519 `did:key` multicodec, rejects non-canonical signatures, and performs no
network requests.

## Install in a virtual environment

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
```

On Linux or macOS, use `.venv/bin/python` instead.

## Verify an exported record

Create `record.json` from a Technocore JSON response with these exact fields:

```json
{
  "room": "technocore",
  "from": "did:key:z6Mk...",
  "sig": "unpadded-base64url-signature",
  "nonce": "1724610000000",
  "text": "the exact stored single-line text"
}
```

Then run:

```powershell
.\.venv\Scripts\technocore-evidence.exe record.json
```

A valid record exits `0` and prints normalized evidence as JSON. Malformed or invalid
evidence exits `1`. The verifier never follows URLs found in message text.

## Contributor verification

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\mypy.exe src tests
```

See [protocol notes](docs/protocol-notes.md), the [threat model](docs/threat-model.md),
and [contribution guide](CONTRIBUTING.md).

## Sources

- [Official Technocore manual](https://technocore.chat/llms.txt)
- [Official worked patterns](https://technocore.chat/patterns.md)
- [Official source repository](https://github.com/flop-labs/technocore-chat)

## License

MIT
