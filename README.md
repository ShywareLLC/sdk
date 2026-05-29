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

## Quick start

```js
import { createVotingClient } from '@shyware/sdk/clients/voting';

const client = createVotingClient({ /* shyconfig */ });
```

Full documentation: [docs.shyware.fyi](https://docs.shyware.fyi)

## License

Evaluation use only. Production deployment requires a Commercial License.
See [LICENSE](./LICENSE) and [shyware.fyi/legal](https://shyware.fyi/legal/).

Patent Pending, U.S. App. No. 64/074,348.
Copyright © 2026 Nicholas Carducci / Shyware LLC.
