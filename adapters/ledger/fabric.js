import { createRequire } from 'module';
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import { LedgerInterface } from './interface.js';

// fabric-network is CJS — load via createRequire
const require = createRequire(import.meta.url);
const { Gateway, Wallets } = require('fabric-network');

export class FabricLedgerInterface extends LedgerInterface {
  constructor({
    mode           = process.env.FABRIC_MODE,
    peerId         = process.env.FABRIC_PEER_ID       || 'peer0.org1.example.com',
    caId           = process.env.FABRIC_CA_ID         || 'ca.org1.example.com',
    mspId          = 'Org1MSP',
    peerEndpoint   = (process.env.FABRIC_MODE === 'local'
                      ? process.env.FABRIC_PEER_ENDPOINT
                      : (process.env.AMB_NODE_ENDPOINT || process.env.FABRIC_PEER_ENDPOINT))
                     || 'localhost:7051',
    caEndpoint     = process.env.FABRIC_CA_ENDPOINT   || 'localhost:7054',
    networkId      = process.env.AMB_NETWORK_ID,
    memberId       = process.env.AMB_MEMBER_ID,
    ambCaEndpoint  = process.env.AMB_CA_ENDPOINT,
    channel        = 'shyware',
    chaincode      = 'shyware',
    // For amb mode, AMB_TLS_CERT_PATH (managedblockchain-tls-chain.pem) takes precedence;
    // FABRIC_TLS_CERT is local-Fabric-only and must not be used for AMB orderer/peer TLS.
    tlsCertPath    = (process.env.FABRIC_MODE === 'amb'
                      ? (process.env.AMB_TLS_CERT_PATH || process.env.FABRIC_TLS_CERT)
                      : (process.env.FABRIC_TLS_CERT   || process.env.AMB_TLS_CERT_PATH)),
    adminCertPath  = (process.env.FABRIC_MODE === 'amb'
                      ? (process.env.AMB_ADMIN_CERT_PATH || process.env.FABRIC_ADMIN_CERT)
                      : (process.env.FABRIC_ADMIN_CERT   || process.env.AMB_ADMIN_CERT_PATH)),
    adminKeyPath   = (process.env.FABRIC_MODE === 'amb'
                      ? (process.env.AMB_ADMIN_KEY_PATH || process.env.FABRIC_ADMIN_KEY)
                      : (process.env.FABRIC_ADMIN_KEY   || process.env.AMB_ADMIN_KEY_PATH)),
    tracer = null,
  } = {}) {
    if (!mode) throw new Error('FABRIC_MODE is required (amb | local)');
    super();
    const resolvedPeerId  = mode === 'amb' ? `peer-node.${memberId}.${networkId}` : peerId;
    const resolvedCaId    = mode === 'amb' ? `ca.${memberId}.${networkId}`        : caId;
    const resolvedMspId   = mode === 'amb' ? memberId                              : mspId;
    const resolvedCaEp    = mode === 'amb' ? ambCaEndpoint                         : caEndpoint;
    this._cfg = { mode, peerId: resolvedPeerId, caId: resolvedCaId, mspId: resolvedMspId,
                  peerEndpoint, caEndpoint: resolvedCaEp, networkId, channel, chaincode, tlsCertPath, adminCertPath, adminKeyPath };
    this._tracer = tracer;
    this._gateway = null;
    this._contract = null;
  }

  get name() { return `fabric-${this._cfg.mode}`; }

  _buildConnectionProfile() {
    const { peerId, caId, mspId, peerEndpoint, caEndpoint, tlsCertPath, mode, networkId } = this._cfg;
    // FABRIC_PEER_TLS_DISABLED=true: use plaintext gRPC (for Docker peer with TLS disabled)
    const peerTlsOff = process.env.FABRIC_PEER_TLS_DISABLED === 'true' || !tlsCertPath;
    const tlsPem = peerTlsOff ? null : readFileSync(tlsCertPath, 'utf8');
    // AMB orderer endpoint follows a known pattern derived from the network ID.
    const ordererId = mode === 'amb'
      ? `orderer.${networkId.toLowerCase()}.managedblockchain.us-east-1.amazonaws.com`
      : 'orderer.example.com';
    const ordererUrl = mode === 'amb'
      ? `grpcs://${ordererId}:30001`
      : peerTlsOff ? 'grpc://localhost:7050' : 'grpcs://localhost:7050';
    // For local Fabric, orderer has its own TLS CA cert separate from the peer's.
    const ordererTlsCertPath = mode === 'local'
      ? (process.env.FABRIC_ORDERER_TLS_CERT || tlsCertPath)
      : tlsCertPath;
    const ordererTlsPem = peerTlsOff ? null : readFileSync(ordererTlsCertPath, 'utf8');
    return {
      name: 'shyware-network', version: '1.0.0',
      client: { organization: mspId, connection: { timeout: { peer: { endorser: '300' }, orderer: '300' } } },
      organizations: { [mspId]: { mspid: mspId, peers: [peerId], certificateAuthorities: [caId] } },
      peers: {
        [peerId]: {
          url: peerTlsOff ? `grpc://${peerEndpoint}` : `grpcs://${peerEndpoint}`,
          ...(peerTlsOff ? {} : { tlsCACerts: { pem: tlsPem } }),
          grpcOptions: {
            ...(mode === 'local' && !peerTlsOff ? { 'ssl-target-name-override': peerEndpoint.split(':')[0] } : {}),
            'grpc-wait-for-ready-timeout': 10000,
          },
        },
      },
      orderers: {
        [ordererId]: {
          url: ordererUrl,
          ...(peerTlsOff ? {} : { tlsCACerts: { pem: ordererTlsPem } }),
          grpcOptions: { ...(mode === 'local' && !peerTlsOff ? { 'ssl-target-name-override': ordererId } : {}) },
        },
      },
      channels: {
        [this._cfg.channel]: {
          orderers: [ordererId],
          peers: { [peerId]: { endorsingPeer: true, chaincodeQuery: true, ledgerQuery: true, eventSource: true } },
        },
      },
      certificateAuthorities: { [caId]: { url: `https://${caEndpoint}`, caName: mspId, tlsCACerts: { pem: [tlsPem] } } },
    };
  }

  async _getContract() {
    if (this._contract) return this._contract;
    const { mspId, adminCertPath, adminKeyPath, channel, chaincode, mode } = this._cfg;
    const wallet = await Wallets.newInMemoryWallet();
    const certPem = readFileSync(adminCertPath, 'utf8');
    const keyFiles = readdirSync(adminKeyPath);
    const keyPem = readFileSync(join(adminKeyPath, keyFiles[0]), 'utf8');
    await wallet.put('admin', { credentials: { certificate: certPem, privateKey: keyPem }, mspId, type: 'X.509' });
    this._gateway = new Gateway();
    await this._gateway.connect(this._buildConnectionProfile(), {
      wallet, identity: 'admin',
      // Discovery disabled for all modes. For ccaas (local) the peer advertises
      // the Docker gateway address which the SDK can't resolve from the host.
      // For AMB the discovery ACL rejects the admin identity. Both use the static
      // connection profile which has all peer and orderer info.
      discovery: { enabled: false },
    });
    this._contract = (await this._gateway.getNetwork(channel)).getContract(chaincode);
    return this._contract;
  }

  async _traced(name, annotations, fn) {
    // Use telemetryInterface.trace() so XRay, OTel, and Noop all emit spans correctly.
    // The old resolveSegment()/addNewSubsegment() path only worked for XRayTelemetryInterface.
    if (this._tracer) {
      return this._tracer.trace(name, annotations, fn);
    }
    return fn();
  }

  async submitTwoListWrite(scopingId, list1, list2) {
    return this._traced('fabric.peer.submit', { scopingId }, async () => {
      const c = await this._getContract();
      return JSON.parse((await c.submitTransaction('submitTwoListWrite', scopingId, JSON.stringify(list1), JSON.stringify(list2))).toString());
    });
  }

  async getCount(scopingId) {
    return this._traced('fabric.peer.query', { scopingId }, async () => {
      const c = await this._getContract();
      return JSON.parse((await c.evaluateTransaction('getCount', scopingId)).toString());
    });
  }

  async rescindTwoListWrite(scopingId, submissionId, identityHash) {
    return this._traced('fabric.peer.rescind', { scopingId }, async () => {
      const c = await this._getContract();
      return JSON.parse((await c.submitTransaction('rescindTwoListWrite', scopingId, submissionId, identityHash)).toString());
    });
  }

  async replaceTwoListWrite(scopingId, oldSubmissionId, newList1, identityHash) {
    return this._traced('fabric.peer.replace', { scopingId }, async () => {
      const c = await this._getContract();
      return JSON.parse((await c.submitTransaction('replaceTwoListWrite', scopingId, oldSubmissionId, JSON.stringify(newList1), identityHash)).toString());
    });
  }

  async commitPeriodClose(scopingId, l1MerkleRoot, l2MerkleRoot, attestation) {
    return this._traced('fabric.peer.period-close', { scopingId }, async () => {
      const c = await this._getContract();
      return JSON.parse((await c.submitTransaction('commitPeriodClose', scopingId, l1MerkleRoot, l2MerkleRoot, attestation)).toString());
    });
  }

  async disconnect() {
    if (this._gateway) { this._gateway.disconnect(); this._gateway = null; this._contract = null; }
  }
}
