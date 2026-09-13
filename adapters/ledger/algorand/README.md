# Algorand adapter — native local verification (no Docker)

`AlgorandLedgerInterface` was verified end-to-end against a real, natively-built
`algod` node — the same non-Docker approach this project uses for Fabric
(`../fabric/deploy/setup-native.sh`). AlgoKit LocalNet/the classic sandbox both
wrap this same `algod` binary in Docker Compose purely for convenience; running
it natively works identically and needs no Docker daemon.

## 1. Build `algod`, `goal`, and `kmd` from source

```bash
git clone --depth 1 https://github.com/algorand/go-algorand
cd go-algorand

# Native build deps for the vendored libsodium fork (macOS):
brew install libtool automake autoconf
export PATH="/usr/local/opt/libtool/libexec/gnubin:$PATH"
make libsodium

mkdir -p /tmp/algobin
go build -o /tmp/algobin/algod ./cmd/algod/...
go build -o /tmp/algobin/goal  ./cmd/goal/...
go build -o /tmp/algobin/kmd   ./cmd/kmd      # note: no /... here, kmd has a
                                               # sibling `codes` package that
                                               # trips up `go build -o` with a
                                               # wildcard target
```

## 2. Create and start a single-node DevMode network

DevMode gives instant finality (blocks only advance on real activity) — ideal
for scripted tests. Use `docker/files/run/devmode_template.json` from the
cloned repo as your template, but **replace its `NUM_ROUNDS` placeholder with
a small number** (e.g. `10000`) — the default multi-million-round value in
some sample configs makes participation-key generation take effectively
forever for local testing.

```bash
export PATH="/tmp/algobin:$PATH"
sed 's/NUM_ROUNDS/10000/' docker/files/run/devmode_template.json > /tmp/template.json
goal network create -n devmodenet -r /tmp/algo-privnet -t /tmp/template.json
goal network start -r /tmp/algo-privnet
```

Enable the developer API (needed for `/teal/compile`, which the verification
script uses to compile the checked-in TEAL source to bytecode) by writing
`{"EnableDeveloperAPI": true}` to `/tmp/algo-privnet/data/config.json` before
starting, or `goal network restart -r /tmp/algo-privnet` after adding it.

Get a funded account and its algod token:

```bash
goal account list -d /tmp/algo-privnet/data
goal account export -a <ADDRESS> -d /tmp/algo-privnet/data
cat /tmp/algo-privnet/data/algod.token
```

## 3. Run the verification script

```bash
npm install algosdk --no-save   # from ShywareLLC/sdk root, if not already installed
node adapters/ledger/algorand/scripts/verify-localnet.mjs \
  --node-port 8080 \
  --token-file /tmp/algo-privnet/data/algod.token \
  --mnemonic "<25-word mnemonic from `goal account export`>"
```

Deploys the compiled contract fresh, funds its app account, and drives the
real `AlgorandLedgerInterface` through submit / get-count / replay-rejection /
sybil-rejection / rescind / resubmit-after-rescind — all against real AVM
execution, not a mock.
