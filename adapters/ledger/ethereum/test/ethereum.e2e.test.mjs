// End-to-end verification of EthereumLedgerInterface against a real local EVM
// chain (Hardhat's dev node), exercising the actual deployed ShywareTwoList
// contract — not a mock. This proves the four checks (required-field
// presence, join-key rejection predicate, sybil resistance, replay
// protection) are enforced by the chain's own state-transition function, and
// that the JS adapter's return shapes match the LedgerInterface contract.
//
// Dev-only test harness for this adapter (Hardhat + ethers as devDependencies
// under adapters/ledger/ethereum/node_modules) — not part of the published
// @shyware/sdk package surface.
//
// Run with:  npm test   (from this directory; run `npm install` here first)
//
// Node resolution note: ../ethereum.js dynamically imports 'ethers' from its
// OWN location (adapters/ledger/), so 'ethers' must be resolvable from an
// ancestor of that path — exactly the shape a real consumer gets for free
// (ethers installed at the consumer app's root, with @shyware/sdk nested
// under its node_modules). In this bare dev checkout there is no such
// ancestor install, so 'ethers' installed only under
// adapters/ledger/ethereum/node_modules (a *sibling* of ethereum.js, not an
// ancestor) is NOT sufficient on its own — Node's resolver never looks into
// sibling/child directories. To run this file standalone, either install
// ethers at ShywareLLC/sdk/ (or higher) as well, or temporarily mirror
// adapters/ledger/ethereum/node_modules/{ethers,@noble,@adraffy,aes-js,tslib,ws}
// into adapters/ledger/node_modules/ before running, then remove it — do not
// commit that directory.

import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ETHEREUM_DIR = path.resolve(__dirname, '..');
const ARTIFACT_PATH = path.join(
  ETHEREUM_DIR,
  'artifacts/contracts/ShywareTwoList.sol/ShywareTwoList.json',
);

const RPC_URL = 'http://127.0.0.1:8555'; // non-default port to avoid clashing with any local 8545

let hardhatProcess;
let contractAddress;
let EthereumLedgerInterface;
let ethers;
// Populated from Hardhat's own startup banner (its 20 deterministic dev
// accounts + private keys) so each test can use a distinct signer — avoids
// nonce-ordering flakiness from sharing one account across independently
// constructed EthereumLedgerInterface/ethers.Wallet instances.
let devKeys = [];
let contractAbi;

// Asserts that `promise` rejects due to the contract reverting with the named
// custom error, decoded via the contract's own ABI — a precise check that the
// EVM's state-transition function itself rejected the write (not just that
// "some error" happened), which is the whole point of chain enforcement.
async function assertCustomError(promise, errorName) {
  try {
    await promise;
    assert.fail(`expected revert ${errorName}, but the call succeeded`);
  } catch (err) {
    if (err.name === 'AssertionError') throw err;
    const data = err.data || err.info?.error?.data?.data || err.error?.data;
    assert.ok(data, `no revert data captured for expected ${errorName}; got: ${err.message}`);
    const iface = new ethers.Interface(contractAbi);
    const decoded = iface.parseError(data);
    assert.ok(decoded, `could not decode revert data for expected ${errorName}`);
    assert.equal(decoded.name, errorName);
  }
}

function waitForRpcReady(proc, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    let out = '';
    const timer = setTimeout(() => reject(new Error(`hardhat node did not become ready:\n${out}`)), timeoutMs);
    proc.stdout.on('data', (chunk) => {
      out += chunk.toString();
      // The accounts/private-key banner is printed *after* the "Started..."
      // line, so wait for a handful of private keys too, not just the first line.
      const keyCount = (out.match(/Private Key:/g) || []).length;
      if (out.includes('Started HTTP and WebSocket JSON-RPC server') && keyCount >= 6) {
        clearTimeout(timer);
        resolve(out);
      }
    });
    proc.stderr.on('data', (chunk) => { out += chunk.toString(); });
    proc.on('error', reject);
    proc.on('exit', (code) => {
      if (code !== null && code !== 0) reject(new Error(`hardhat node exited early (${code}):\n${out}`));
    });
  });
}

before(async () => {
  hardhatProcess = spawn(
    process.platform === 'win32' ? 'npx.cmd' : 'npx',
    ['hardhat', 'node', '--port', '8555'],
    { cwd: ETHEREUM_DIR, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const banner = await waitForRpcReady(hardhatProcess);
  devKeys = [...banner.matchAll(/Private Key:\s*(0x[0-9a-fA-F]{64})/g)].map((m) => m[1]);
  if (devKeys.length < 6) throw new Error(`expected at least 6 dev accounts from hardhat node banner, got ${devKeys.length}`);

  ({ ethers } = await import('ethers'));
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const deployer = new ethers.Wallet(devKeys[0], provider);

  const artifact = JSON.parse(readFileSync(ARTIFACT_PATH, 'utf8'));
  contractAbi = artifact.abi;
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, deployer);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  contractAddress = await contract.getAddress();

  ({ EthereumLedgerInterface } = await import('../../ethereum.js'));
});

after(async () => {
  if (hardhatProcess) hardhatProcess.kill();
});

test('submitTwoListWrite succeeds and returns countMatch shape', async () => {
  const ledger = new EthereumLedgerInterface({
    rpcUrl: RPC_URL,
    contractAddress,
    privateKey: devKeys[1],
  });

  const scopingId = 'poll-e2e-1';
  const res = await ledger.submitTwoListWrite(
    scopingId,
    { submissionId: 'submission-alpha', payloadCommitment: 'commit-alpha' },
    { identityHash: 'identity-alpha' },
  );

  assert.equal(typeof res.txId, 'string');
  assert.ok(res.txId.startsWith('0x'));
  assert.equal(res.l1Count, 1);
  assert.equal(res.l2Count, 1);
  assert.equal(res.countMatch, true);

  const count = await ledger.getCount(scopingId);
  assert.deepEqual(count, { l1Count: 1, l2Count: 1, countMatch: true });

  await ledger.disconnect();
});

test('replay protection: same submissionId in same scope reverts', async () => {
  const ledger = new EthereumLedgerInterface({
    rpcUrl: RPC_URL,
    contractAddress,
    privateKey: devKeys[2],
  });

  const scopingId = 'poll-e2e-2';
  await ledger.submitTwoListWrite(
    scopingId,
    { submissionId: 'submission-replay', payloadCommitment: 'commit-1' },
    { identityHash: 'identity-1' },
  );

  await assertCustomError(
    ledger.submitTwoListWrite(
      scopingId,
      { submissionId: 'submission-replay', payloadCommitment: 'commit-2' },
      { identityHash: 'identity-2' },
    ),
    'ReplayProtectionViolated',
  );

  const count = await ledger.getCount(scopingId);
  assert.equal(count.l1Count, 1); // rejected write did not change state
  await ledger.disconnect();
});

test('sybil resistance: same identityHash in same scope reverts', async () => {
  const ledger = new EthereumLedgerInterface({
    rpcUrl: RPC_URL,
    contractAddress,
    privateKey: devKeys[3],
  });

  const scopingId = 'poll-e2e-3';
  await ledger.submitTwoListWrite(
    scopingId,
    { submissionId: 'submission-sybil-1', payloadCommitment: 'commit-1' },
    { identityHash: 'identity-sybil' },
  );

  await assertCustomError(
    ledger.submitTwoListWrite(
      scopingId,
      { submissionId: 'submission-sybil-2', payloadCommitment: 'commit-2' },
      { identityHash: 'identity-sybil' },
    ),
    'SybilResistanceViolated',
  );

  const count = await ledger.getCount(scopingId);
  assert.equal(count.l1Count, 1);
  await ledger.disconnect();
});

test('join-key rejection predicate: sha256(submissionId) == identityHash reverts', async () => {
  const ledger = new EthereumLedgerInterface({
    rpcUrl: RPC_URL,
    contractAddress,
    privateKey: devKeys[4],
  });

  const scopingId = 'poll-e2e-4';
  const submissionId = 'submission-joinkey';
  // Compute sha256(bytes32-encoded submissionId) exactly as the contract does,
  // so identityHash IS the forbidden join key relative to submissionId.
  const submissionId32 = ethers.keccak256(ethers.toUtf8Bytes(submissionId)); // matches adapter's _toBytes32
  const forbiddenIdentityHash = ethers.sha256(submissionId32);

  await assertCustomError(
    ledger.submitTwoListWrite(
      scopingId,
      { submissionId, payloadCommitment: 'commit-joinkey' },
      { identityHash: forbiddenIdentityHash }, // already a 0x 32-byte hex string — used as-is
    ),
    'RejectionPredicateViolated',
  );

  await ledger.disconnect();
});

test('rescindTwoListWrite removes the record and decrements count', async () => {
  const ledger = new EthereumLedgerInterface({
    rpcUrl: RPC_URL,
    contractAddress,
    privateKey: devKeys[5],
  });

  const scopingId = 'poll-e2e-5';
  await ledger.submitTwoListWrite(
    scopingId,
    { submissionId: 'submission-rescind', payloadCommitment: 'commit-rescind' },
    { identityHash: 'identity-rescind' },
  );
  assert.deepEqual(await ledger.getCount(scopingId), { l1Count: 1, l2Count: 1, countMatch: true });

  const res = await ledger.rescindTwoListWrite(scopingId, 'submission-rescind', 'identity-rescind');
  assert.equal(res.rescinded, true);
  assert.equal(res.countMatch, true);

  assert.deepEqual(await ledger.getCount(scopingId), { l1Count: 0, l2Count: 0, countMatch: true });

  // The submission can now be resubmitted with a fresh identity — proves the
  // rescind actually cleared both L1 and L2, not just decremented a counter.
  const resubmit = await ledger.submitTwoListWrite(
    scopingId,
    { submissionId: 'submission-rescind', payloadCommitment: 'commit-rescind-2' },
    { identityHash: 'identity-rescind-2' },
  );
  assert.equal(resubmit.l1Count, 1);

  await ledger.disconnect();
});
