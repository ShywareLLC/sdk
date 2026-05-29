#!/usr/bin/env bash
# setup-native.sh — Bootstrap Hyperledger Fabric 2.4 peer + orderer as
# native systemd services on EC2. No Docker required: chaincode runs via
# ccaas (external builder). Eliminates Docker daemon RAM overhead, Docker
# socket attack surface, and storage-driver I/O latency.
#
# Prerequisites: peer, orderer, cryptogen, configtxgen in ~/bin
# Run once after cloning. Safe to re-run: checks for existing artifacts.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
FABRIC_BIN=/home/ubuntu/bin
FABRIC_CFG=/home/ubuntu/config          # core.yaml + orderer.yaml live here
DATA_DIR=/home/ubuntu/fabric-native      # ledger storage, not crypto material
CHANNEL=shyware
CHAINCODE_NAME=shyware
CHAINCODE_VERSION=2.0
CHAINCODE_SEQUENCE=3
CHAINCODE_DIR="$(cd "${DIR}/../../../../../../domain/state/fabric" && pwd)"

export PATH="${FABRIC_BIN}:${PATH}"
export FABRIC_CFG_PATH="${DIR}"         # for cryptogen/configtxgen (needs configtx.yaml)

# ── 1. Crypto material ───────────────────────────────────────────────────────
if [ ! -d "${DIR}/crypto-config" ]; then
  echo "▶ Generating crypto material..."
  cryptogen generate --config="${DIR}/crypto-config.yaml" --output="${DIR}/crypto-config"
fi

# ── 2. Channel artifacts ─────────────────────────────────────────────────────
mkdir -p "${DIR}/channel-artifacts"

if [ ! -f "${DIR}/channel-artifacts/genesis.block" ]; then
  echo "▶ Generating genesis block..."
  configtxgen -profile ShywareGenesis -channelID system-channel \
    -outputBlock "${DIR}/channel-artifacts/genesis.block"
fi

if [ ! -f "${DIR}/channel-artifacts/${CHANNEL}.tx" ]; then
  echo "▶ Generating channel transaction..."
  configtxgen -profile ShywareChannel \
    -outputCreateChannelTx "${DIR}/channel-artifacts/${CHANNEL}.tx" \
    -channelID "${CHANNEL}"
fi

# ── 3. Data directories ──────────────────────────────────────────────────────
mkdir -p "${DATA_DIR}/orderer" "${DATA_DIR}/peer" "${DATA_DIR}/chaincode-pkgs"

# Path vars referenced in systemd units and chaincode packaging steps
ADMIN_MSP="${DIR}/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
PEER_TLS="${DIR}/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls"
ORDERER_TLS="${DIR}/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/tls/ca.crt"

# ── 4. Write orderer.yaml ────────────────────────────────────────────────────
ORDERER_CFG="${DIR}/orderer.yaml"
if [ ! -f "${ORDERER_CFG}" ]; then
  echo "▶ Writing orderer.yaml..."
  cat > "${ORDERER_CFG}" << EOF
General:
  ListenAddress: 127.0.0.1
  ListenPort: 7050
  TLS:
    Enabled: true
    PrivateKey: ${DIR}/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.key
    Certificate: ${DIR}/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt
    RootCAs:
      - ${DIR}/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/tls/ca.crt
  GenesisMethod: file
  GenesisFile: ${DIR}/channel-artifacts/genesis.block
  LocalMSPDir: ${DIR}/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/msp
  LocalMSPID: OrdererMSP
  BCCSP:
    Default: SW
    SW:
      Hash: SHA2
      Security: 256
  Authentication:
    TimeWindow: 15m

FileLedger:
  Location: ${DATA_DIR}/orderer

Cluster:
  SendBufferSize: 10

Operations:
  ListenAddress: 127.0.0.1:8443
  TLS:
    Enabled: false

Metrics:
  Provider: disabled
EOF
fi

# ── 5. Patch core.yaml for native paths ──────────────────────────────────────
# core.yaml already exists at ${FABRIC_CFG}/core.yaml from when we set up
# the peer CLI. We need to ensure vm.endpoint is unset/disabled and the
# external builder (ccaas) is configured.
# Rather than patch the shared core.yaml, write a peer-specific one.
PEER_CORE="${DIR}/core.yaml"
if [ ! -f "${PEER_CORE}" ]; then
  echo "▶ Writing peer core.yaml..."
  cat > "${PEER_CORE}" << EOF
peer:
  id: peer0.org1.example.com
  networkId: shyware
  listenAddress: 0.0.0.0:7051
  chaincodeListenAddress: 0.0.0.0:7052
  address: peer0.org1.example.com:7051
  addressAutoDetect: false
  gateway:
    enabled: true
    endorsementTimeout: 30s
    dialTimeout: 2m
  keepalive:
    interval: 7200s
    timeout: 20s
    client:
      interval: 60s
      timeout: 20s
    deliveryClient:
      interval: 60s
      timeout: 20s
  gossip:
    bootstrap: peer0.org1.example.com:7051
    useLeaderElection: true
    orgLeader: false
    endpoint:
    maxBlockCountToStore: 100
    maxPropagationBurstLatency: 10ms
    maxPropagationBurstSize: 10
    propagateIterations: 1
    propagatePeerNum: 3
    pullInterval: 4s
    pullPeerNum: 3
    requestStateInfoInterval: 4s
    publishStateInfoInterval: 4s
    stateInfoRetentionInterval:
    publishCertPeriod: 10s
    skipBlockVerification: false
    dialTimeout: 3s
    connTimeout: 2s
    recvBuffSize: 20
    sendBuffSize: 200
    digestWaitTime: 1s
    requestWaitTime: 1500ms
    responseWaitTime: 2s
    aliveTimeInterval: 5s
    aliveExpirationTimeout: 25s
    reconnectInterval: 25s
    externalEndpoint: peer0.org1.example.com:7051
    election:
      startupGracePeriod: 15s
      membershipSampleInterval: 1s
      leaderAliveThreshold: 10s
      leaderElectionDuration: 5s
    pvtData:
      pullRetryThreshold: 60s
      transientstoreMaxBlockRetention: 1000
      pushAckTimeout: 3s
      btlPullMargin: 10
      reconcileBatchSize: 10
      reconcileSleepInterval: 1m
      reconciliationEnabled: true
      skipPullingInvalidTransactionsDuringCommit: false
  tls:
    enabled: true
    cert:
      file: ${DIR}/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.crt
    key:
      file: ${DIR}/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.key
    rootcert:
      file: ${DIR}/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
    clientAuthRequired: false
  authentication:
    timewindow: 15m
  fileSystemPath: ${DATA_DIR}/peer
  BCCSP:
    Default: SW
    SW:
      Hash: SHA2
      Security: 256
  mspConfigPath: ${DIR}/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp
  localMspId: Org1MSP
  client:
    connTimeout: 3s
  deliveryclient:
    reconnectTotalTimeThreshold: 3600s
    connTimeout: 3s
    reConnectBackoffThreshold: 3600s
  localMspType: bccsp
  profile:
    enabled: false
  adminService:
    listenAddress: 0.0.0.0:7055
  handlers:
    authFilters:
      - name: DefaultAuth
      - name: ExpirationCheck
    decorators:
      - name: DefaultDecorator
    endorsers:
      escc:
        name: DefaultEndorsement
        library:
    validators:
      vscc:
        name: DefaultValidation
        library:
  validatorPoolSize:
  discovery:
    enabled: true
    authCacheEnabled: true
    authCacheMaxSize: 1000
    authCachePurgeRetentionRatio: 0.75
    orgMembersAllowedAccess: false
  limits:
    concurrency:
      endorserService: 2500
      deliverService: 2500
      gatewayService: 500

vm:
  endpoint:
  docker:
    tls:
      enabled: false

chaincode:
  externalBuilders:
    - name: ccaas_builder
      path: /home/ubuntu/ccaas-builder
      propagateEnvironment:
        - CHAINCODE_SERVER_ADDRESS
        - CHAINCODE_ID
  installTimeout: 300s
  startuptimeout: 300s
  executetimeout: 30s
  mode: net
  keepalive: 0
  system:
    _lifecycle: enable
    cscc: enable
    lscc: enable
    qscc: enable
  logging:
    level: info
    shim: warning
    format: '%{color}%{time:2006-01-02 15:04:05.000 MST} [%{module}] %{shortfunc} -> %{level:.4s} %{id:03x}%{color:reset} %{message}'

ledger:
  blockchain:
  state:
    stateDatabase: goleveldb
    totalQueryLimit: 100000
  history:
    enableHistoryDatabase: true
  pvtdataStore:
    collElgProcMaxDbBatchSize: 5000
    collElgProcDbBatchesInterval: 1000
    purgeInterval: 100
    deprioritizedDataReconcilerInterval: 60m

operations:
  listenAddress: 127.0.0.1:9444
  tls:
    enabled: false

metrics:
  provider: disabled

EOF
fi

# ── 6. Write ccaas external builder scripts ───────────────────────────────────
# The ccaas_builder detect/build/release scripts tell the peer how to handle
# ccaas-type chaincode packages (connection.json instead of code.tar.gz).
mkdir -p /home/ubuntu/ccaas-builder/bin

# detect: $1=source_dir (extracted code.tar.gz), $2=metadata_dir (has metadata.json)
cat > /home/ubuntu/ccaas-builder/bin/detect << 'DETECT'
#!/bin/bash
METADATA_DIR=$2
if [ "$(cat ${METADATA_DIR}/metadata.json | python3 -c "import sys,json; print(json.load(sys.stdin).get('type',''))")" = "ccaas" ]; then
  exit 0
fi
echo "type is not ccaas" >&2
exit 1
DETECT
chmod +x /home/ubuntu/ccaas-builder/bin/detect

# build: source_dir already contains extracted code.tar.gz contents (connection.json)
cat > /home/ubuntu/ccaas-builder/bin/build << 'BUILD'
#!/bin/bash
SOURCE=$1; META=$2; OUTPUT=$3
mkdir -p ${OUTPUT}
cp ${SOURCE}/connection.json ${OUTPUT}/
BUILD
chmod +x /home/ubuntu/ccaas-builder/bin/build

cat > /home/ubuntu/ccaas-builder/bin/release << 'RELEASE'
#!/bin/bash
SOURCE=$1; OUTPUT=$2
cp ${SOURCE}/connection.json ${OUTPUT}/
RELEASE
chmod +x /home/ubuntu/ccaas-builder/bin/release

# run: required binary for external builders; ccaas chaincode runs externally so this is a no-op stub
cat > /home/ubuntu/ccaas-builder/bin/run << 'RUN'
#!/bin/bash
exec tail -f /dev/null
RUN
chmod +x /home/ubuntu/ccaas-builder/bin/run

# ── 7. Systemd unit files ─────────────────────────────────────────────────────
echo "▶ Writing systemd unit files..."

sudo tee /etc/systemd/system/fabric-orderer.service > /dev/null << UNIT
[Unit]
Description=Hyperledger Fabric Orderer 2.4
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
User=ubuntu
Environment=FABRIC_CFG_PATH=${DIR}
WorkingDirectory=${DATA_DIR}/orderer
ExecStart=${FABRIC_BIN}/orderer
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fabric-orderer

[Install]
WantedBy=multi-user.target
UNIT

sudo tee /etc/systemd/system/fabric-peer.service > /dev/null << UNIT
[Unit]
Description=Hyperledger Fabric Peer 2.4
After=fabric-orderer.service
Requires=fabric-orderer.service
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
User=ubuntu
Environment=FABRIC_CFG_PATH=${DIR}
WorkingDirectory=${DATA_DIR}/peer
ExecStart=${FABRIC_BIN}/peer node start
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fabric-peer

[Install]
WantedBy=multi-user.target
UNIT

sudo tee /etc/systemd/system/fabric-chaincode.service > /dev/null << UNIT
[Unit]
Description=Shyware Chaincode (ccaas)
After=fabric-peer.service
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=ubuntu
Environment=CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999
Environment=CHAINCODE_ID=${CHAINCODE_NAME}_${CHAINCODE_VERSION}:PLACEHOLDER
Environment=CHAINCODE_TLS_CERT=${PEER_TLS}/server.crt
Environment=CHAINCODE_TLS_KEY=${PEER_TLS}/server.key
ExecStart=/home/ubuntu/shyware-cc
Restart=on-failure
RestartSec=3
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fabric-chaincode

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload

# ── 8. Stop Docker containers (if running) ───────────────────────────────────
if docker ps 2>/dev/null | grep -qE 'deploy-peer|deploy-orderer'; then
  echo "▶ Stopping Docker Fabric containers..."
  docker compose -f "${DIR}/docker-compose.yml" down -v 2>/dev/null || true
fi

# ── 9. Start orderer and peer ────────────────────────────────────────────────
echo "▶ Starting orderer..."
sudo systemctl enable fabric-orderer
sudo systemctl restart fabric-orderer
sleep 4

echo "▶ Starting peer..."
sudo systemctl enable fabric-peer
sudo systemctl restart fabric-peer
sleep 4

# ── 10. Create channel and join peer ─────────────────────────────────────────
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_MSPCONFIGPATH="${ADMIN_MSP}"
export CORE_PEER_ADDRESS=peer0.org1.example.com:7051
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_TLS_ROOTCERT_FILE="${PEER_TLS}/ca.crt"

if ! peer channel list | grep -q "^${CHANNEL}$"; then
  echo "▶ Creating channel ${CHANNEL}..."
  peer channel create \
    -o orderer.example.com:7050 -c "${CHANNEL}" \
    -f "${DIR}/channel-artifacts/${CHANNEL}.tx" \
    --tls --cafile "${ORDERER_TLS}" \
    --outputBlock "${DIR}/channel-artifacts/${CHANNEL}.block"
  peer channel join -b "${DIR}/channel-artifacts/${CHANNEL}.block"
fi

# ── 11. Package, install, approve, commit ccaas chaincode ────────────────────
CC_PKG="${DATA_DIR}/chaincode-pkgs/${CHAINCODE_NAME}_v${CHAINCODE_VERSION}_seq${CHAINCODE_SEQUENCE}.tar.gz"

echo "▶ Packaging ccaas chaincode (seq ${CHAINCODE_SEQUENCE})..."
# Embed peer's TLS CA cert so the peer can verify the chaincode server's TLS cert.
# The chaincode binary uses CHAINCODE_TLS_CERT/KEY (the peer's server.crt/server.key)
# so the peer CA cert already trusts it.
ROOT_CERT_B64=$(cat "${PEER_TLS}/ca.crt" | base64 -w 0)
mkdir -p /tmp/ccaas-pkg
printf '{"address":"127.0.0.1:9999","dial_timeout":"30s","tls_required":true,"client_auth_required":false,"root_cert":"%s"}' \
  "${ROOT_CERT_B64}" > /tmp/ccaas-pkg/connection.json
cd /tmp/ccaas-pkg && tar czf /tmp/ccaas-code.tar.gz connection.json
mkdir -p /tmp/ccaas-final
printf '{"type":"ccaas","label":"%s_%s"}' "${CHAINCODE_NAME}" "${CHAINCODE_VERSION}" \
  > /tmp/ccaas-final/metadata.json
cp /tmp/ccaas-code.tar.gz /tmp/ccaas-final/code.tar.gz
cd /tmp/ccaas-final && tar czf "${CC_PKG}" metadata.json code.tar.gz

echo "▶ Installing chaincode..."
INSTALL_OUT=$(peer lifecycle chaincode install "${CC_PKG}" 2>&1)
echo "${INSTALL_OUT}"
# Extract package ID from install output; falls back to queryinstalled (last match) if needed
PKG_ID=$(echo "${INSTALL_OUT}" | grep -oE 'Chaincode code package identifier: [^ ]+' | awk '{print $NF}' || true)
if [ -z "${PKG_ID}" ]; then
  PKG_ID=$(peer lifecycle chaincode queryinstalled 2>&1 \
    | grep "${CHAINCODE_NAME}_${CHAINCODE_VERSION}" \
    | tail -1 \
    | awk -F'Package ID: ' '{print $2}' | awk -F', Label' '{print $1}')
fi
echo "  Package ID: ${PKG_ID}"

# Update systemd unit with real package ID
sudo sed -i "s|CHAINCODE_ID=.*|CHAINCODE_ID=${PKG_ID}|" \
  /etc/systemd/system/fabric-chaincode.service
sudo systemctl daemon-reload

echo "▶ Approving chaincode..."
peer lifecycle chaincode approveformyorg \
  -o orderer.example.com:7050 --tls --cafile "${ORDERER_TLS}" \
  --channelID "${CHANNEL}" --name "${CHAINCODE_NAME}" \
  --version "${CHAINCODE_VERSION}" --package-id "${PKG_ID}" \
  --sequence "${CHAINCODE_SEQUENCE}"

echo "▶ Committing chaincode..."
peer lifecycle chaincode commit \
  -o orderer.example.com:7050 --tls --cafile "${ORDERER_TLS}" \
  --channelID "${CHANNEL}" --name "${CHAINCODE_NAME}" \
  --version "${CHAINCODE_VERSION}" --sequence "${CHAINCODE_SEQUENCE}" \
  --peerAddresses peer0.org1.example.com:7051 \
  --tlsRootCertFiles "${PEER_TLS}/ca.crt"

echo "▶ Starting chaincode service..."
sudo systemctl enable fabric-chaincode
sudo systemctl restart fabric-chaincode
sleep 2

echo "▶ Verifying..."
peer chaincode invoke \
  -o orderer.example.com:7050 --tls --cafile "${ORDERER_TLS}" \
  -C "${CHANNEL}" -n "${CHAINCODE_NAME}" \
  --peerAddresses peer0.org1.example.com:7051 \
  --tlsRootCertFiles "${PEER_TLS}/ca.crt" \
  -c '{"Args":["submitTwoListWrite","native-test","{\"submissionId\":\"n1\",\"payloadCommitment\":\"abc\"}","{\"identityHash\":\"def\"}"]}'

echo ""
echo "✓ Native Fabric stack ready — no Docker required."
echo "  sudo systemctl status fabric-orderer fabric-peer fabric-chaincode"
echo ""
echo "Set these in .env (Stack 4 — native Fabric):"
echo "  FABRIC_MODE=local"
echo "  FABRIC_PEER_ENDPOINT=peer0.org1.example.com:7051"
echo "  FABRIC_TLS_CERT=${PEER_TLS}/ca.crt"
echo "  FABRIC_ORDERER_TLS_CERT=${ORDERER_TLS}"
echo "  FABRIC_ADMIN_CERT=${ADMIN_MSP}/signcerts/Admin@org1.example.com-cert.pem"
echo "  FABRIC_ADMIN_KEY=${ADMIN_MSP}/keystore/"
echo "  FABRIC_MSP_ID=Org1MSP"
