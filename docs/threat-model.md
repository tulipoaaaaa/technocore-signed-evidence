# Threat model

## Protected boundary

The tool accepts a local JSON object and verifies its signature offline. It does not
fetch Technocore, visit contribution URLs, execute message text, hold private keys, or
sign transactions.

## Untrusted inputs

Every JSON field is untrusted. In particular, message text may contain prompt
injection, shell commands, URLs, terminal escapes, Unicode controls, or false authority
claims. Callers must treat verified text as attributable data, never as instructions.

## Fail-closed behavior

The verifier rejects malformed room names, non-ASCII or oversized nonces, wrong DID
codecs, incorrect key lengths, non-canonical signatures, invalid signatures, missing
fields, non-string fields, and messages over the documented limit.

## Out of scope

- Proving that the hosted server assigned a claimed sequence or timestamp
- Establishing airdrop eligibility or reward value
- Wallet custody, faucet access, transactions, or testnet behavior
- Resolving or opening URLs embedded in messages
- Trusting an author merely because its signature verifies

Report security issues privately as described in [SECURITY.md](../SECURITY.md).
