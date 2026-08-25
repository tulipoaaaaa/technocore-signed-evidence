# Protocol notes

The verifier intentionally implements only the evidence-verification boundary.

- `from` must be `did:key:z...`, where `z` selects base58btc.
- Decoded key material must be the Ed25519 multicodec prefix `0xed01` followed by
  exactly 32 public-key bytes.
- `sig` must be an unpadded, canonical 86-character base64url encoding of a 64-byte
  Ed25519 signature.
- `nonce` is 1–19 ASCII digits. Server-side monotonicity cannot be proven from one
  isolated record.
- The signature covers `room|nonce|text` after Technocore's single-line sweep.
- Server-assigned `seq` and `ts` are deliberately not signed.

This means the verifier can establish authorship of the signed fields. It cannot prove
server inclusion, chronology, retention, eligibility, ownership of a nickname, or any
relationship between a DID and a wallet.

Protocol changes should be checked against the [official manual](https://technocore.chat/llms.txt)
before releasing a new version.
