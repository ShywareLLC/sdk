/**
 * Hardhat config for compiling ShywareTwoList.sol and running a local dev chain
 * to verify the EthereumLedgerInterface adapter end-to-end.
 *
 * Dev-only tooling for this adapter's own test suite — not part of the published
 * @shyware/sdk package (see ../../../../.gitignore-equivalent exclusions and the
 * root package.json `files` allowlist, which does not include this directory's
 * node_modules/artifacts/cache).
 */
/** @type {import('hardhat/config').HardhatUserConfig} */
module.exports = {
  solidity: {
    version: '0.8.24',
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  paths: {
    sources: './contracts',
    tests: './test',
    cache: './cache',
    artifacts: './artifacts',
  },
  networks: {
    hardhat: {},
  },
};
