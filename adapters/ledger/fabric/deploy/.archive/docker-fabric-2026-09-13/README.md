# Docker-based Fabric bootstrap (archived 2026-09-13)

Superseded by `../setup-native.sh` (native systemd peer/orderer/chaincode,
no Docker daemon required). The three-stack A/B experiment documented in
`Consumers/SHYWARE_FYI/docs/three-stack-experiment.md` already concluded
this: "native Fabric (no Docker) preserves all two-list invariant
assertions" (H4) — Stack 3 (this Docker path) and Stack 4 (native) were
run side by side, and Stack 4 won with zero regressions.

Kept here for reference, not for reuse. If you need Docker Fabric for some
reason not covered by `setup-native.sh`, start here rather than from
scratch — but confirm `setup-native.sh` genuinely doesn't fit first.
