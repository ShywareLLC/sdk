// Sealer stub: This embodiment does not currently require PII/high-risk payload sealing.
// To enable, gate all PII/high-risk payloads with manifest.sealer and use shared sealer logic from shywareSealer.js.
/**
 * App-facing web SDK for the shywire transfer-rail embodiment.
 *
 * Apps should treat this client as the only entrypoint into wrapper flows:
 * account registration, issuance, anonymous transfer, redemption, and lookup.
 */

import { createIdentityResolver } from "../../protocol/identity/identityClient.js";
import { createWalletProofBase64 } from "../../protocol/walletProof.js";

export const WIRE_MANIFEST_CONTRACT_VERSION = "shywire-v1";

function requiredWebCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is required by the shywire client.");
  }
  return globalThis.crypto;
}

function normalizeBase(base) {
  if (base == null || base === "") return "";
  return String(base).endsWith("/") ? String(base).slice(0, -1) : String(base);
}

function joinBaseAndPath(base, path) {
  return `${normalizeBase(base)}${path}`;
}

function nowUnix() {
  return Math.floor(Date.now() / 1000);
}

function randomHex(bytes = 32) {
  const arr = requiredWebCrypto().getRandomValues(new Uint8Array(bytes));
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256hex(value) {
  const payload = typeof value === "string" ? value : JSON.stringify(value);
  const bytes = new TextEncoder().encode(payload);
  const digest = await requiredWebCrypto().subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function buildEnvelope(type, data) {
  const tx = {
    type,
    signature: "AQ==",
    data
  };

  return {
    txJson: JSON.stringify(tx),
    type,
    data
  };
}

function assertOperatorMode(operatorMode, action) {
  if (!operatorMode) {
    throw new Error(`${action} requires operator authority.`);
  }
}

function buildProviderProfile(manifest) {
  const wire = manifest?.wire ?? {};
  const providerConfig = wire.provider_config ?? {};
  return {
    provider: wire.provider ?? null,
    mode: providerConfig.mode ?? "sandbox",
    intentPath: providerConfig.intent_path ?? null,
    settlementAsset:
      providerConfig.settlement_asset ?? wire.backing_asset ?? null,
    supportedRails: providerConfig.supported_rails ?? ["blockchain"],
    requiresOperatorReview: providerConfig.requires_operator_review ?? true,
    supportedNetworks: wire.supported_networks ?? [],
    backingAsset: wire.backing_asset ?? null,
    issuerName: wire.issuer_name ?? null
  };
}

function assertSupportedNetwork(profile, network, action) {
  if (!network) return;
  if (!profile.supportedNetworks.includes(network)) {
    throw new Error(
      `${action} is not available on unsupported network: ${network}`
    );
  }
}

function assertSupportedRail(profile, rail, action) {
  if (!profile.supportedRails.includes(rail)) {
    throw new Error(
      `${action} is not available on unsupported payout rail: ${rail}`
    );
  }
}

export function assertWireManifest(shyconfig) {
  if (shyconfig?.contract_version !== WIRE_MANIFEST_CONTRACT_VERSION) {
    throw new Error(
      `shyconfig must declare contract_version=${WIRE_MANIFEST_CONTRACT_VERSION} for shywire apps.`
    );
  }

  if (shyconfig?.app?.product_type !== "shywire") {
    throw new Error("shyconfig product_type must be shywire for shywire apps.");
  }

  if (!shyconfig?.anon_layer?.black_box_required) {
    throw new Error(
      "shyconfig must require the anonymous layer as a black box."
    );
  }

  const requiredFlows = new Set(shyconfig.anon_layer.required_flows ?? []);
  for (const flow of ["wire_issue", "wire_transfer", "wire_redeem"]) {
    if (!requiredFlows.has(flow)) {
      throw new Error(`shyconfig is missing required shywire flow: ${flow}`);
    }
  }

  if (!shyconfig.signing?.required || shyconfig.signing.backend === "none") {
    throw new Error(
      "shyconfig must require protocol signing for shywire apps."
    );
  }

  if (!shyconfig.wire) {
    throw new Error("shyconfig must declare wire settings for shywire apps.");
  }
}

export function createWireClient({
  defaultBase = "/api",
  defaultSubmitBase = null,
  storageKey = "shyware_wire_api_base",
  fetchImpl = globalThis.fetch?.bind(globalThis),
  getAuthHeaders = null,
  manifest = null,
  operatorMode = false
} = {}) {
  if (!fetchImpl) {
    throw new Error("fetch is required by the shywire client.");
  }

  const identityResolver = createIdentityResolver(manifest);
  const providerProfile = buildProviderProfile(manifest);

  function getBase() {
    if (typeof localStorage === "undefined") return defaultBase;
    return localStorage.getItem(storageKey) || defaultBase;
  }

  function setBase(url) {
    if (typeof localStorage === "undefined") return;
    if (!url) {
      localStorage.removeItem(storageKey);
      return;
    }
    localStorage.setItem(storageKey, url);
  }

  function getSubmitBase() {
    return defaultSubmitBase == null ? getBase() : defaultSubmitBase;
  }

  async function resolveHeaders(extraHeaders = {}) {
    if (!getAuthHeaders) return extraHeaders;
    const authHeaders = await getAuthHeaders();
    return {
      ...authHeaders,
      ...extraHeaders
    };
  }

  async function get(path) {
    let res;
    try {
      res = await fetchImpl(joinBaseAndPath(getBase(), path), {
        headers: await resolveHeaders()
      });
    } catch {
      throw new Error(
        "API not reachable - check Settings or your network connection."
      );
    }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error ?? `HTTP ${res.status}`);
    }
    return res.json();
  }

  async function post(path, body) {
    let res;
    try {
      res = await fetchImpl(joinBaseAndPath(getSubmitBase(), path), {
        method: "POST",
        headers: await resolveHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(body)
      });
    } catch {
      throw new Error(
        "API not reachable - check Settings or your network connection."
      );
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error ?? `HTTP ${res.status}`);
    }
    return res.json();
  }

  return {
    initialize() {
      return {
        contractVersion: manifest?.contract_version ?? null,
        appId: manifest?.app?.id ?? null,
        chainId: manifest?.app?.chain_id ?? null,
        apiBase: getBase(),
        submitBase: getSubmitBase(),
        identity: manifest?.identity ?? null,
        identityProfile: identityResolver.profile,
        signing: manifest?.signing ?? null,
        deployment: manifest?.deployment ?? null,
        wire: manifest?.wire ?? null,
        providerProfile,
        operatorAuthority: {
          operatorMode,
          operatorMintBurn: manifest?.wire?.operator_mint_burn ?? false
        },
        requiredFlows: manifest?.anon_layer?.required_flows ?? []
      };
    },
    getBase,
    setBase,
    getSubmitBase,
    getManifest: () => manifest,
    createWalletProof(args) {
      return createWalletProofBase64(args);
    },
    isOperatorMode: () => operatorMode,
    createIdentityCommitment(input, options = {}) {
      return identityResolver.createCommitment(input, options);
    },
    createIdentityProofHash(input, options = {}) {
      return identityResolver.createProofHash(input, options);
    },
    getProviderProfile: () => providerProfile,
    listSupportedNetworks: () => providerProfile.supportedNetworks.slice(),
    listSupportedRails: () => providerProfile.supportedRails.slice(),
    getAsset: (assetId) => get(`/assets/${assetId}`),
    getSupply: (assetId) => get(`/supply/${assetId}`),
    getBalance: (assetId, accountCommitment) =>
      get(`/balance/${assetId}/${accountCommitment}`),
    async buildRegisterAsset({ assetId, name, decimals = 2 }) {
      return buildEnvelope(1, {
        asset_id: assetId,
        name,
        decimals: Number(decimals)
      });
    },
    submitRegisterAsset: (txJson) => post("/assets", { tx: txJson }),
    async registerAsset(args) {
      assertOperatorMode(operatorMode, "registerAsset");
      const envelope = await this.buildRegisterAsset(args);
      await this.submitRegisterAsset(envelope.txJson);
      return envelope;
    },
    async buildRegisterAccount({
      walletAddress = "",
      identityInput = null,
      accountCommitment = null,
      walletProofBase64 = "",
      enrollmentToken = "",
      enrollmentProofBase64 = ""
    }) {
      const resolvedWalletAddress =
        walletAddress ||
        (typeof identityInput === "string" ? identityInput.trim() : "");
      const commitment =
        accountCommitment ??
        (await identityResolver.createCommitment(
          identityInput ?? resolvedWalletAddress,
          {
            namespace: "account"
          }
        ));
      const resolvedWalletProofBase64 =
        walletProofBase64 ||
        (resolvedWalletAddress
          ? await createWalletProofBase64({
              accountCommitment: commitment,
              walletAddress: resolvedWalletAddress,
            })
          : "");
      if (!resolvedWalletProofBase64) {
        throw new Error(
          "walletProofBase64 is required for account registration."
        );
      }
      return {
        ...(await buildEnvelope(5, {
          account_commitment: commitment,
          wallet_proof: resolvedWalletProofBase64,
          enrollment_token: enrollmentToken,
          enrollment_proof: enrollmentProofBase64
        })),
        accountCommitment: commitment
      };
    },
    submitRegisterAccount: (txJson) => post("/accounts", { tx: txJson }),
    async registerAccount(args) {
      const envelope = await this.buildRegisterAccount(args);
      await this.submitRegisterAccount(envelope.txJson);
      return envelope;
    },
    async buildIssueWire({
      assetId,
      accountCommitment,
      amount,
      timestamp = nowUnix()
    }) {
      return buildEnvelope(2, {
        asset_id: assetId,
        account_commitment: accountCommitment,
        amount: Number(amount),
        timestamp
      });
    },
    submitIssueWire: (txJson) => post("/mint", { tx: txJson }),
    async issueWire(args) {
      assertOperatorMode(operatorMode, "issueWire");
      const envelope = await this.buildIssueWire(args);
      await this.submitIssueWire(envelope.txJson);
      return envelope;
    },
    async buildIssueIntent({
      amount,
      destinationNetwork,
      destinationAddress,
      externalReference = ""
    }) {
      assertOperatorMode(operatorMode, "buildIssueIntent");
      assertSupportedNetwork(
        providerProfile,
        destinationNetwork,
        "Issue intent"
      );
      const payload = {
        kind: "issue",
        intent_id: await sha256hex(
          JSON.stringify({
            amount: Number(amount),
            destinationNetwork,
            destinationAddress,
            externalReference,
            nonce: randomHex(16)
          })
        ),
        provider: providerProfile.provider,
        provider_mode: providerProfile.mode,
        backing_asset: providerProfile.backingAsset,
        settlement_asset: providerProfile.settlementAsset,
        issuer_name: providerProfile.issuerName,
        supported_rails: providerProfile.supportedRails,
        requires_operator_review: providerProfile.requiresOperatorReview,
        amount: Number(amount),
        destination_network: destinationNetwork,
        destination_address: destinationAddress,
        external_reference: externalReference
      };
      return payload;
    },
    submitIssueIntent: (payload) => {
      if (!providerProfile.intentPath) {
        throw new Error(
          "shyconfig does not declare a wire provider intent path."
        );
      }
      return post(`${providerProfile.intentPath}/issue-intents`, payload);
    },
    async createIssueIntent(args, { dispatch = false } = {}) {
      const payload = await this.buildIssueIntent(args);
      const body = dispatch ? { ...payload, dispatch: true } : payload;
      if (!providerProfile.intentPath) {
        return {
          persisted: false,
          payload: body
        };
      }
      const result = await this.submitIssueIntent(body);
      return {
        persisted: true,
        payload: body,
        result
      };
    },
    async buildWire({
      scopingId,
      senderCommitment,
      recipientCommitment,
      amount,
      timestamp = nowUnix()
    }) {
      const submissionNonce = randomHex(32);
      const nullifier = await sha256hex(
        `${senderCommitment}:${scopingId}:${submissionNonce}`
      );
      const submissionId = await sha256hex(submissionNonce);
      return {
        ...(await buildEnvelope(4, {
          asset_id: scopingId,
          sender_commitment: senderCommitment,
          recipient_commitment: recipientCommitment,
          amount: Number(amount),
          nullifier,
          submission_nonce: submissionNonce,
          sender_proof: "AQ==",
          timestamp
        })),
        submissionId,
        submissionNonce,
        nullifier
      };
    },
    submitWire: (txJson) => post("/transfers", { tx: txJson }),
    async wireSubmission(args) {
      const envelope = await this.buildWire(args);
      await this.submitWire(envelope.txJson);
      return envelope;
    },
    async buildRedeemWire({
      assetId,
      accountCommitment,
      amount,
      timestamp = nowUnix()
    }) {
      return buildEnvelope(3, {
        asset_id: assetId,
        account_commitment: accountCommitment,
        amount: Number(amount),
        timestamp
      });
    },
    submitRedeemWire: (txJson) => post("/burn", { tx: txJson }),
    async redeemWire(args) {
      assertOperatorMode(operatorMode, "redeemWire");
      const envelope = await this.buildRedeemWire(args);
      await this.submitRedeemWire(envelope.txJson);
      return envelope;
    },
    async buildRedeemIntent({
      amount,
      accountCommitment,
      payoutRail = "blockchain",
      payoutNetwork = null,
      payoutDestination,
      externalReference = ""
    }) {
      assertOperatorMode(operatorMode, "buildRedeemIntent");
      assertSupportedRail(providerProfile, payoutRail, "Redeem intent");
      if (payoutRail === "blockchain") {
        assertSupportedNetwork(providerProfile, payoutNetwork, "Redeem intent");
      }
      return {
        kind: "redeem",
        intent_id: await sha256hex(
          JSON.stringify({
            amount: Number(amount),
            accountCommitment,
            payoutRail,
            payoutNetwork,
            payoutDestination,
            externalReference,
            nonce: randomHex(16)
          })
        ),
        provider: providerProfile.provider,
        provider_mode: providerProfile.mode,
        backing_asset: providerProfile.backingAsset,
        settlement_asset: providerProfile.settlementAsset,
        issuer_name: providerProfile.issuerName,
        supported_rails: providerProfile.supportedRails,
        requires_operator_review: providerProfile.requiresOperatorReview,
        amount: Number(amount),
        account_commitment: accountCommitment,
        payout_rail: payoutRail,
        payout_network: payoutNetwork,
        payout_destination: payoutDestination,
        external_reference: externalReference
      };
    },
    submitRedeemIntent: (payload) => {
      if (!providerProfile.intentPath) {
        throw new Error(
          "shyconfig does not declare a wire provider intent path."
        );
      }
      return post(`${providerProfile.intentPath}/redeem-intents`, payload);
    },
    async createRedeemIntent(args, { dispatch = false } = {}) {
      const payload = await this.buildRedeemIntent(args);
      const body = dispatch ? { ...payload, dispatch: true } : payload;
      if (!providerProfile.intentPath) {
        return {
          persisted: false,
          payload: body
        };
      }
      const result = await this.submitRedeemIntent(body);
      return {
        persisted: true,
        payload: body,
        result
      };
    }
  };
}

export function initializeFromShyConfig(shyconfig, options = {}) {
  assertWireManifest(shyconfig);

  if (
    shyconfig.api?.requires_auth &&
    typeof options.getAuthHeaders !== "function"
  ) {
    throw new Error(
      "shyconfig requires authenticated wire API access, but no auth header provider was supplied."
    );
  }

  return createWireClient({
    defaultBase: shyconfig.api?.base_url ?? "/api",
    defaultSubmitBase: shyconfig.api?.submit_base_url ?? null,
    storageKey:
      shyconfig.api?.storage_key ??
      options.storageKey ??
      "shyware_wire_api_base",
    fetchImpl: options.fetchImpl,
    getAuthHeaders: options.getAuthHeaders,
    manifest: shyconfig,
    operatorMode: options.operatorMode ?? false
  });
}
