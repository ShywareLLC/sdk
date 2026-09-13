# Shyware Two-List Invariant — CorDapp

Chain-enforced implementation of the two-list invariant (rejection predicate, sybil
resistance, replay protection, count-match, one-time-only period-close) for R3 Corda.
See `../../corda.js` for the JS adapter that talks to this CorDapp over the `webserver`
module's REST bridge.

## Layout

- `contracts/` — `L1State`, `L2State`, `ScopingRegistryState`, `PeriodCloseState`, and
  `TwoListContract` (the on-chain rules; verified by every node that resolves a
  transaction, not just the party that built it).
- `workflows/` — `SubmitTwoListWriteFlow`, `GetCountFlow`, `RescindTwoListWriteFlow`,
  `ReplaceTwoListWriteFlow`, `CommitPeriodCloseFlow`, and the `driver`-based integration
  test (`workflows/src/test/kotlin/.../TwoListFlowTests.kt`) that exercises all five
  against a real (in-process) node network + notary.
- `webserver/` — a small Spring Boot service holding the `CordaRPCClient` connection and
  exposing plain HTTP+JSON endpoints, because there is no first-party (or mature
  community) Corda RPC client for Node.js.

## Why a registry state, not just L1/L2 states

Corda's notary enforces uniqueness of *consumed* states, not of arbitrary field values on
freshly created ones. To get real notary-enforced uniqueness for `(scopingId,
submissionId)` and `(scopingId, identityHash)` — not just an app-level check with a race
window — every write for a given `scopingId` consumes and reissues a single
`ScopingRegistryState` that carries the used-id sets and the running counts. The notary
will only let one transaction consume a given version of that state, which serializes
writers and makes the contract's duplicate checks race-free. See the doc comment at the
top of `contracts/.../states/States.kt` for the full rationale, including the one
documented gap: the very first submission for a `scopingId` has no registry to consume
yet, so notary enforcement engages from the second write onward for that scopingId.

## Building and running this for real

This module needs a JDK **8** (Corda 4.x does not run on JDK 11+) and Gradle **6.x**
(the `net.corda.plugins` toolchain pinned in `gradle.properties` does not support modern
Gradle). Once on that toolchain, with network access to Maven Central and
`https://software.r3.com/artifactory/corda`:

```sh
./gradlew test              # driver-based integration test (contracts/flows, real notary)
./gradlew deployNodes       # materializes build/nodes/{Notary,ShywareOperator}
build/nodes/runnodes        # starts both node processes
./gradlew :webserver:bootRun \
  -Dconfig.rpc.host=localhost -Dconfig.rpc.port=10006 \
  -Dconfig.rpc.username=shyware -Dconfig.rpc.password=changeme
```

The JS adapter then talks to `http://localhost:8081` (the webserver's default port).

**Sandbox note:** the environment this CorDapp was authored in had JDK 22 (no JDK 8),
Gradle 9.6 (incompatible with the Corda 4.x gradle plugins), and no authenticated access
to R3's Artifactory, so the Gradle build above could not actually be executed there. See
the task report for what was verified instead (a manual review pass over the Kotlin
sources, and a full JS-side unit-test run against a mocked REST bridge).
