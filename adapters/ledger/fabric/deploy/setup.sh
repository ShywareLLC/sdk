#!/usr/bin/env bash
# setup.sh — bootstrap a self-hosted Hyperledger Fabric 2.4 network on EC2.
# Run once after cloning. Safe to re-run: checks for existing artifacts.
set -euo pipefail

FABRIC_VERSION=2.4.9
FABRIC_CA_VERSION=1.5.7
CHANNEL=shyware
CHAINCODE_NAME=shyware
CHAINCODE_VERSION=1.0
CHAINCODE_SEQUENCE=1
DIR="$(cd "$(dirname "$0")" && pwd)"
CHAINCODE_DIR="$(cd "${DIR}/../../../../../../domain/state/fabric" && pwd)"

# ── 1. Install Fabric binaries if missing ────────────────────────────────────
if ! command -v peer &>/dev/null; then
  echo "▶ Installing Fabric ${FABRIC_VERSION} binaries…"
  curl -sSL https://bit.ly/2ysbOFE | bash -s -- "${FABRIC_VERSION}" "${FABRIC_CA_VERSION}" -d -s
  export PATH="${DIR}/bin:$PATH"
fi

export PATH="/home/ubuntu/bin:/usr/local/bin:/usr/local/go/bin:${DIR}/bin:$PATH"
export GOPATH=/home/ubuntu/go
export GOWORK=off
# configtxgen needs FABRIC_CFG_PATH pointing to this dir for configtx.yaml.
# peer CLI needs it pointing to /home/ubuntu/config for core.yaml.
# Switch after artifact generation.
export FABRIC_CFG_PATH="${DIR}"

# ── 2. Generate crypto material ──────────────────────────────────────────────
if [ ! -d "${DIR}/crypto-config" ]; then
  echo "▶ Generating crypto material…"
  cryptogen generate --config="${DIR}/crypto-config.yaml" --output="${DIR}/crypto-config"
fi

# ── 3. Generate channel artifacts ────────────────────────────────────────────
mkdir -p "${DIR}/channel-artifacts"

if [ ! -f "${DIR}/channel-artifacts/genesis.block" ]; then
  echo "▶ Generating genesis block…"
  configtxgen -profile ShywareGenesis -channelID system-channel -outputBlock "${DIR}/channel-artifacts/genesis.block"
fi

if [ ! -f "${DIR}/channel-artifacts/${CHANNEL}.tx" ]; then
  echo "▶ Generating channel transaction…"
  configtxgen -profile ShywareChannel -outputCreateChannelTx "${DIR}/channel-artifacts/${CHANNEL}.tx" -channelID "${CHANNEL}"
fi

# ── 4. Start network ─────────────────────────────────────────────────────────
echo "▶ Starting Fabric containers…"
docker compose -f "${DIR}/docker-compose.yml" up -d

echo "▶ Waiting for peers to start…"
sleep 6

# ── 5. Create channel and join peer ─────────────────────────────────────────
# Switch FABRIC_CFG_PATH to core.yaml location for peer CLI commands.
export FABRIC_CFG_PATH=/home/ubuntu/config

ADMIN_MSP="${DIR}/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
PEER_TLS="${DIR}/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls"
ORDERER_TLS="${DIR}/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/tls/ca.crt"

export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_MSPCONFIGPATH="${ADMIN_MSP}"
# Use hostnames so TLS SAN validation passes (mapped to 127.0.0.1 in /etc/hosts).
export CORE_PEER_ADDRESS=peer0.org1.example.com:7051
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_TLS_ROOTCERT_FILE="${PEER_TLS}/ca.crt"

if ! peer channel list | grep -q "^${CHANNEL}$"; then
  echo "▶ Creating channel ${CHANNEL}…"
  peer channel create \
    -o orderer.example.com:7050 \
    -c "${CHANNEL}" \
    -f "${DIR}/channel-artifacts/${CHANNEL}.tx" \
    --tls --cafile "${ORDERER_TLS}" \
    --outputBlock "${DIR}/channel-artifacts/${CHANNEL}.block"

  echo "▶ Joining peer to channel…"
  peer channel join -b "${DIR}/channel-artifacts/${CHANNEL}.block"
fi

# ── 6. Package and install chaincode ────────────────────────────────────────
CC_PKG="${DIR}/channel-artifacts/${CHAINCODE_NAME}.tar.gz"

if [ ! -f "${CC_PKG}" ]; then
  echo "▶ Packaging chaincode…"
  # Fetch dependencies into vendor/
  pushd "${CHAINCODE_DIR}" >/dev/null
  go mod vendor
  popd >/dev/null

  peer lifecycle chaincode package "${CC_PKG}" \
    --path "${CHAINCODE_DIR}" \
    --lang golang \
    --label "${CHAINCODE_NAME}_${CHAINCODE_VERSION}"
fi

echo "▶ Installing chaincode on peer…"
peer lifecycle chaincode install "${CC_PKG}"

# Get package ID
PKG_ID=$(peer lifecycle chaincode queryinstalled 2>&1 | grep "${CHAINCODE_NAME}_${CHAINCODE_VERSION}" | awk -F'Package ID: ' '{print $2}' | awk -F', Label' '{print $1}')
echo "  Package ID: ${PKG_ID}"

echo "▶ Approving chaincode for Org1…"
peer lifecycle chaincode approveformyorg \
  -o orderer.example.com:7050 --tls --cafile "${ORDERER_TLS}" \
  --channelID "${CHANNEL}" \
  --name "${CHAINCODE_NAME}" \
  --version "${CHAINCODE_VERSION}" \
  --package-id "${PKG_ID}" \
  --sequence "${CHAINCODE_SEQUENCE}"

echo "▶ Committing chaincode to channel…"
peer lifecycle chaincode commit \
  -o orderer.example.com:7050 --tls --cafile "${ORDERER_TLS}" \
  --channelID "${CHANNEL}" \
  --name "${CHAINCODE_NAME}" \
  --version "${CHAINCODE_VERSION}" \
  --sequence "${CHAINCODE_SEQUENCE}" \
  --peerAddresses peer0.org1.example.com:7051 \
  --tlsRootCertFiles "${PEER_TLS}/ca.crt"

echo ""
echo "✓ Shyware Fabric network ready."
echo "  Channel:   ${CHANNEL}"
echo "  Chaincode: ${CHAINCODE_NAME} v${CHAINCODE_VERSION}"
echo ""
echo "Set these env vars in your backend .env:"
echo "  FABRIC_MODE=local"
echo "  FABRIC_PEER_ENDPOINT=localhost:7051"
echo "  FABRIC_CHANNEL=${CHANNEL}"
echo "  FABRIC_CHAINCODE=${CHAINCODE_NAME}"
echo "  FABRIC_TLS_CERT=${DIR}/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
echo "  FABRIC_ADMIN_CERT=${DIR}/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/Admin@org1.example.com-cert.pem"
echo "  FABRIC_ADMIN_KEY=${DIR}/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/"
