// @shyware/sdk — main barrel
// Import specific subpaths for tree-shaking; this barrel is for convenience.

export * from './clients/embodiments/chatClient.js';
export * from './clients/embodiments/votingClient.js';
export * from './clients/embodiments/wireClient.js';
export * from './clients/embodiments/sharesClient.js';
export * from './clients/embodiments/custodyClient.js';
export * from './clients/embodiments/contractsClient.js';
export * from './clients/embodiments/storeClient.js';
export * from './clients/embodiments/browserClient.js';
export * from './clients/composites/financingClient.js';
export * from './clients/composites/restClient.js';
export * from './clients/composites/betsClient.js';
export * from './clients/composites/lotsClient.js';
export * from './clients/utilities/utilityClient.js';
export * from './clients/utilities/streamClient.js';
export * from './clients/utilities/IoTClient.js';
export * from './clients/utilities/camClient.js';
export * from './clients/utilities/hopClient.js';
export * from './protocol/sealer.js';
export * from './protocol/anonLayer.js';
export * from './protocol/walletProof.js';
export * from './protocol/identity/identityClient.js';
export * from './protocol/zkp/zkpClient.js';
export * from './utils/hostRouting.js';
export * from './adapters/index.js';
