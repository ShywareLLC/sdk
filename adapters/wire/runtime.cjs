'use strict';

const crypto = require('crypto');
const { trimString } = require('../server/utils.cjs');

function parsePositiveNumber(value, fieldName) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`${fieldName} must be a positive number`);
  return n;
}

function getCircleBaseUrl(mode) {
  return mode === 'live' ? 'https://api.circle.com' : 'https://api-sandbox.circle.com';
}

function getCircleChain(network) {
  const map = { ethereum: 'ETH', base: 'BASE', solana: 'SOL' };
  if (!map[network]) throw new Error(`Unsupported Circle network: ${network}`);
  return map[network];
}

function getCircleMoneyCurrency(asset) {
  if (asset === 'USDC') return 'USD';
  if (asset === 'EURC') return 'EUR';
  return asset;
}

function getCircleAssetDecimals(asset) {
  return asset === 'USDC' || asset === 'EURC' ? 6 : 2;
}

function toCircleAmountString(amount, asset) {
  return (Number(amount) / 10 ** getCircleAssetDecimals(asset)).toFixed(2);
}

function parseJsonEnv(name) {
  if (!process.env[name]) return null;
  try { return JSON.parse(process.env[name]); } catch { return null; }
}

async function circleRequest(pathname, { method = 'GET', body = null, providerMode = 'sandbox', requestId = null } = {}) {
  if (!process.env.CIRCLE_API_KEY) throw new Error('CIRCLE_API_KEY is required for Circle provider dispatch');
  const res = await fetch(`${getCircleBaseUrl(providerMode)}${pathname}`, {
    method,
    headers: { Accept: 'application/json', Authorization: `Bearer ${process.env.CIRCLE_API_KEY}`, 'Content-Type': 'application/json', 'X-Request-Id': requestId || crypto.randomUUID() },
    body: body ? JSON.stringify(body) : undefined,
  });
  const raw = await res.text();
  let parsed; try { parsed = raw ? JSON.parse(raw) : null; } catch { parsed = { raw }; }
  if (!res.ok) { const e = new Error(`Circle API ${res.status}`); e.circle = parsed; e.status = res.status; throw e; }
  return parsed;
}

async function dispatchCircleBlockchainPayout(intent, { address, network }) {
  if (!process.env.CIRCLE_SOURCE_WALLET_ID) throw new Error('CIRCLE_SOURCE_WALLET_ID is required');
  const chain = getCircleChain(network);
  const currency = getCircleMoneyCurrency(intent.settlementAsset);
  const amount = toCircleAmountString(intent.amount, intent.backingAsset);
  const source = { type: 'wallet', id: process.env.CIRCLE_SOURCE_WALLET_ID };
  const identities = parseJsonEnv('CIRCLE_SOURCE_IDENTITIES_JSON');
  if (Array.isArray(identities) && identities.length) source.identities = identities;

  const recipient = await circleRequest('/v1/addressBook/recipients', { method: 'POST', providerMode: intent.providerMode, requestId: crypto.randomUUID(), body: { idempotencyKey: crypto.randomUUID(), chain, address, metadata: { nickname: intent.externalReference || `${intent.kind}-${intent.intentId.slice(0, 12)}` } } });
  const recipientId = recipient?.data?.id;
  if (!recipientId) throw new Error('Circle recipient creation did not return an id');

  const payout = await circleRequest('/v1/payouts', { method: 'POST', providerMode: intent.providerMode, requestId: crypto.randomUUID(), body: { idempotencyKey: crypto.randomUUID(), destination: { type: 'address_book', id: recipientId }, amount: { amount, currency }, toAmount: { amount, currency }, source } });
  return { forwarded: true, status: 'submitted_to_provider', providerStatus: payout?.data?.status || 'submitted', providerResponse: { recipient, payout } };
}

async function dispatchCircleProviderIntent(intent) {
  if (intent.kind === 'issue') return dispatchCircleBlockchainPayout(intent, { address: intent.destinationAddress, network: intent.destinationNetwork });
  if (intent.payoutRail === 'blockchain') return dispatchCircleBlockchainPayout(intent, { address: intent.payoutDestination, network: intent.payoutNetwork });
  return { forwarded: false, status: 'pending_manual_provider_review', providerStatus: `manual_${intent.payoutRail}_review_required`, providerResponse: { message: `Circle ${intent.payoutRail} payout not implemented` } };
}

async function dispatchWireProviderIntent(intent) {
  if (intent.provider === 'circle_usdc') {
    try { return await dispatchCircleProviderIntent(intent); }
    catch (e) { return { forwarded: false, status: 'provider_error', providerStatus: e.status ? `http_${e.status}` : 'circle_error', providerResponse: e.circle ?? { message: e.message } }; }
  }
  const url = intent.kind === 'issue' ? process.env.WIRE_ISSUE_PROVIDER_URL : process.env.WIRE_REDEEM_PROVIDER_URL;
  if (!url) return { forwarded: false, status: intent.requiresOperatorReview ? 'pending_operator_review' : 'pending_provider_dispatch', providerStatus: 'provider_not_configured', providerResponse: null };

  const headers = { 'Content-Type': 'application/json', 'X-Shywire-Intent-Id': intent.intentId };
  if (intent.provider === 'circle_usdc' && process.env.CIRCLE_API_KEY) headers.Authorization = `Bearer ${process.env.CIRCLE_API_KEY}`;
  let res;
  try { res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(intent.payload) }); }
  catch (e) { return { forwarded: false, status: 'provider_error', providerStatus: 'network_error', providerResponse: { message: e.message } }; }
  const raw = await res.text();
  let parsed; try { parsed = raw ? JSON.parse(raw) : null; } catch { parsed = { raw }; }
  return { forwarded: res.ok, status: res.ok ? 'submitted_to_provider' : 'provider_error', providerStatus: res.ok ? 'submitted' : `http_${res.status}`, providerResponse: parsed };
}

function buildWireIntentRecord(kind, body) {
  const intentId = trimString(body.intent_id);
  const provider = trimString(body.provider);
  const providerMode = trimString(body.provider_mode) || 'sandbox';
  const issuerName = trimString(body.issuer_name);
  const amount = parsePositiveNumber(body.amount, 'amount');
  const backingAsset = trimString(body.backing_asset);
  const settlementAsset = trimString(body.settlement_asset || backingAsset);
  const externalReference = trimString(body.external_reference);
  const requiresOperatorReview = body.requires_operator_review !== false;
  const supportedRails = Array.isArray(body.supported_rails) ? body.supported_rails.map(trimString).filter(Boolean) : [];

  if (!intentId) throw new Error('intent_id is required');
  if (!provider) throw new Error('provider is required');
  if (!issuerName) throw new Error('issuer_name is required');
  if (!backingAsset) throw new Error('backing_asset is required');

  const base = { intentId, kind, provider, providerMode, issuerName, amount, backingAsset, settlementAsset, externalReference, requiresOperatorReview, supportedRails, status: requiresOperatorReview ? 'pending_operator_review' : 'pending_provider_dispatch', payload: body, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };

  if (kind === 'issue') {
    const destinationNetwork = trimString(body.destination_network);
    const destinationAddress = trimString(body.destination_address);
    if (!destinationNetwork) throw new Error('destination_network is required for issue intents');
    if (!destinationAddress) throw new Error('destination_address is required for issue intents');
    return { ...base, destinationNetwork, destinationAddress };
  }

  const accountCommitment = trimString(body.account_commitment);
  const payoutRail = trimString(body.payout_rail);
  const payoutDestination = trimString(body.payout_destination);
  const payoutNetwork = trimString(body.payout_network);
  if (!accountCommitment) throw new Error('account_commitment is required for redeem intents');
  if (!payoutRail) throw new Error('payout_rail is required for redeem intents');
  if (!payoutDestination) throw new Error('payout_destination is required for redeem intents');
  return { ...base, accountCommitment, payoutRail, payoutNetwork: payoutRail === 'blockchain' ? payoutNetwork : '', payoutDestination };
}

module.exports = { buildWireIntentRecord, dispatchWireProviderIntent };
