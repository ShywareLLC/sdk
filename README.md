# @shyware/sdk

Structurally anonymous distributed-ledger protocol SDK.

Non-linkability by write architecture — not policy. One invariant, thirteen embodiments.

## What it does

Every submission atomically writes two permanently disjoint records:

- **List 1** — anonymous payload record: direction-free identifier, sealed content. No participant identity.
- **List 2** — participant registry record: identity hash. No payload, no submission identifier.

No join key between List 1 and List 2 is ever written to canonical state. The rejection predicate refuses any state transition that would create one. Identity-to-payload linkage is non-representable by write architecture — not hidden, not encrypted, not gated.

## Embodiments

| Client | Contract | Domain |
|---|---|---|
| `@shyware/sdk/clients/voting` | `shyvoting-v1` | Elections and referenda |
| `@shyware/sdk/clients/wire` | `shywire-v1` | Private value transfer |
| `@shyware/sdk/clients/custody` | `shycustody-v1` | Commodity custody |
| `@shyware/sdk/clients/contracts` | `shycontracts-v1` | Revenue financing |
| `@shyware/sdk/clients/shares` | `shyshares-v1` | DAO governance |
| `@shyware/sdk/clients/chat` | `shychat-v1` | Private messaging |
| `@shyware/sdk/clients/store` | `shystore-v1` | Credential vault / EHR |
| `@shyware/sdk/clients/browser` | `shybrowser-v1` | Anonymous analytics |
| `@shyware/sdk/clients/rest` | `shyrest-v1` | Anonymous submissions |
| `@shyware/sdk/clients/bets` | `shybets-v1` | Anonymous betting |
| `@shyware/sdk/clients/lots` | `shylots-v1` | Sealed-bid auction |
| `@shyware/sdk/clients/stream` | `shystream-v1` | Private streaming |
| `@shyware/sdk/clients/financing` | `shycontracts-v1` | Financing composite |

## Installation

```bash
npm install @shyware/sdk
```

Requires a Commercial License Agreement for production deployment.
See [shyware.fyi/legal](https://shyware.fyi/legal/) for terms.

## Publishing

This package is published from the npm account `shyware`, which uses `auth-and-writes` two-factor auth with npm web/passkey authentication on the user's MacBook.

Release flow:

```bash
npm version minor # or npm version patch
npm pack --dry-run
npm publish --access public
npm view @shyware/sdk version dist-tags --json
git push origin main --follow-tags
```

Run `npm publish --access public` in an interactive TTY. When npm asks to press Enter to authenticate in the browser, press Enter and have the user approve the passkey prompt on the MacBook. Do not ask for a numeric OTP unless npm explicitly asks for one after web/passkey auth fails.

## Quick start

```js
import { createVotingClient } from '@shyware/sdk/clients/voting';

const client = createVotingClient({ /* shyconfig */ });

// Pass the SAME persisted per-poll keypair on every call for a given poll --
// see "Per-poll key persistence" below for why this matters beyond avoiding
// redundant work.
const envelope = await client.voteSubmission({ scopingId, payload: 'yes', diditSessionId, keypair });

// Change your mind, or rescind entirely -- oldSubmissionId comes from the
// original cast's envelope.submissionId; keypair must be the SAME one used
// to cast, since the chain re-derives identity_hash from voter_pub_key.
await client.replaceVote({ scopingId, oldSubmissionId, newPayload: 'no', diditSessionId, keypair });
await client.rescindVote({ scopingId, oldSubmissionId, diditSessionId, keypair });
```

### Per-poll key persistence

`buildVote`/`voteSubmission` accept an optional `keypair` (a WebCrypto
`CryptoKeyPair`) instead of always generating one fresh. Generating a new
keypair on every call means every retry after a transient failure looks like
a *different* voter to the IDV attestation enclave's one-time-use-per-poll
replay guard, permanently orphaning that poll for the underlying Didit
session on the very first failed attempt — regardless of whether a ballot
ever actually reached canonical state. Persist one keypair per `(user, poll)`
(e.g. in `IndexedDB` or `localStorage`, non-extractable where possible) and
pass it on every call for that poll, including retries and updates.

### Didit identity provider

`@shyware/sdk/providers/didit` exports `createDiditSession`,
`getDiditSessionStatus`, and `extractDiditIdentity` — the real HTTP calls
against your own backend's `/api/didit/create-session` and
`/api/didit/status/:sessionId` routes (you implement those server-side;
these just call them). Use these directly rather than going through
`identityResolver`, which is deliberately provider-agnostic (shared across
wallet/identus/didit) and has no HTTP knowledge of any specific provider.

Full documentation: [docs.shyware.fyi](https://docs.shyware.fyi)

## License

Evaluation use only. Production deployment requires a Commercial License.
See [LICENSE](./LICENSE) and [shyware.fyi/legal](https://shyware.fyi/legal/).

Patent Pending, U.S. App. No. 64/074,348.
Copyright © 2026 Nicholas Carducci / Shyware LLC.
