// Real, end-to-end verification of AlgorandLedgerInterface against a live
// Algorand node — no mocks, no Docker.
//
// Usage:
//   node adapters/ledger/algorand/scripts/verify-localnet.mjs \
//     --node-url http://localhost --node-port 8080 \
//     --token-file /path/to/algod.token --mnemonic "25 words..."
//
// Deploys the compiled contract fresh, funds the app account, then drives
// the real adapter through all five operations plus the two rejection
// paths (replay protection, sybil resistance) and a rescind-then-resubmit
// to prove rescind is a real delete, not just a counter decrement.
//
// See ../../README.md for how to stand up a native (non-Docker) local
// Algorand node to run this against.

import algosdk from 'algosdk';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { AlgorandLedgerInterface } from '../../algorand.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONTRACTS_DIR = join(__dirname, '..', 'contracts');

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
}

const nodeUrl = arg('node-url', 'http://localhost');
const nodePort = Number(arg('node-port', '8080'));
const tokenFile = arg('token-file');
const tokenArg = arg('token');
const mnemonic = arg('mnemonic');

if (!mnemonic) {
  console.error('Usage: --mnemonic "25 word mnemonic" [--node-url URL] [--node-port PORT] [--token-file PATH | --token TOKEN]');
  process.exit(1);
}

const token = tokenArg ?? (tokenFile ? readFileSync(tokenFile, 'utf8').trim() : '');
const algod = new algosdk.Algodv2(token, nodeUrl, nodePort);
const account = algosdk.mnemonicToSecretKey(mnemonic);

console.log('Account:', account.addr.toString());
const info = await algod.accountInformation(account.addr).do();
console.log('Balance (microAlgos):', info.amount);

async function compileTeal(src) {
  const res = await algod.compile(src).do();
  return new Uint8Array(Buffer.from(res.result, 'base64'));
}

const approvalProgram = await compileTeal(readFileSync(join(CONTRACTS_DIR, 'shyware_two_list_approval.teal'), 'utf8'));
const clearProgram = await compileTeal(readFileSync(join(CONTRACTS_DIR, 'shyware_two_list_clear.teal'), 'utf8'));

const sp = await algod.getTransactionParams().do();
const createTxn = algosdk.makeApplicationCreateTxnFromObject({
  sender: account.addr,
  suggestedParams: sp,
  onComplete: algosdk.OnApplicationComplete.NoOpOC,
  approvalProgram,
  clearProgram,
  numLocalInts: 0,
  numLocalByteSlices: 0,
  numGlobalInts: 0,
  numGlobalByteSlices: 0,
});
const { txid: createTxId } = await algod.sendRawTransaction(createTxn.signTxn(account.sk)).do();
const created = await algosdk.waitForConfirmation(algod, createTxId, 10);
const appId = Number(created.applicationIndex);
console.log('Deployed appId:', appId);

const appAddress = algosdk.getApplicationAddress(appId);
const fundTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
  sender: account.addr,
  receiver: appAddress,
  amount: 10_000_000,
  suggestedParams: await algod.getTransactionParams().do(),
});
const { txid: fundTxId } = await algod.sendRawTransaction(fundTxn.signTxn(account.sk)).do();
await algosdk.waitForConfirmation(algod, fundTxId, 10);
console.log('Funded app account:', appAddress.toString());

const ledger = new AlgorandLedgerInterface({ algodClient: algod, account: { addr: account.addr, sk: account.sk }, appId });

const scopingId = 'verify-localnet-' + Date.now();
const submissionId = 'sub-' + Date.now();
const identityHash = 'a'.repeat(64);

let failures = 0;
function check(label, cond) {
  console.log(`${cond ? 'PASS' : 'FAIL'} — ${label}`);
  if (!cond) failures++;
}

const r1 = await ledger.submitTwoListWrite(scopingId, { submissionId, payloadCommitment: 'commitmentabc' }, { identityHash });
check('submitTwoListWrite succeeds', r1.countMatch && r1.l1Count === 1 && r1.l2Count === 1);

const c1 = await ledger.getCount(scopingId);
check('getCount reflects the write', c1.l1Count === 1 && c1.l2Count === 1);

let replayRejected = false;
try {
  await ledger.submitTwoListWrite(scopingId, { submissionId, payloadCommitment: 'other' }, { identityHash: 'b'.repeat(64) });
} catch { replayRejected = true; }
check('replay protection rejects on-chain', replayRejected);

let sybilRejected = false;
try {
  await ledger.submitTwoListWrite(scopingId, { submissionId: 'sub2-' + Date.now(), payloadCommitment: 'other' }, { identityHash });
} catch { sybilRejected = true; }
check('sybil resistance rejects on-chain', sybilRejected);

const r2 = await ledger.rescindTwoListWrite(scopingId, submissionId, identityHash);
check('rescindTwoListWrite succeeds', r2.rescinded);

const c2 = await ledger.getCount(scopingId);
check('count is zero after rescind', c2.l1Count === 0 && c2.l2Count === 0);

const r3 = await ledger.submitTwoListWrite(scopingId, { submissionId, payloadCommitment: 'commitmentabc-v2' }, { identityHash });
check('resubmit after rescind succeeds (proves real delete, not just a decrement)', r3.countMatch && r3.l1Count === 1);

console.log(failures === 0 ? '\nALL SCENARIOS PASSED' : `\n${failures} SCENARIO(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
