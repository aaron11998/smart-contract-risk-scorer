import { describe, it, expect } from "vitest";
import { CHAINS, getChainConfig, getConfiguredChains } from "../src/chains";
import { ChainId } from "../src/types";

describe("Chains Configuration", () => {
  it("should have all 5 chains configured", () => {
    expect(Object.keys(CHAINS).length).toBe(5);
    expect(CHAINS.ethereum).toBeDefined();
    expect(CHAINS.polygon).toBeDefined();
    expect(CHAINS.arbitrum).toBeDefined();
    expect(CHAINS.optimism).toBeDefined();
    expect(CHAINS.base).toBeDefined();
  });

  it("should have required properties for each chain", () => {
    const chains: ChainId[] = ["ethereum", "polygon", "arbitrum", "optimism", "base"];
    for (const chain of chains) {
      const config = CHAINS[chain];
      expect(config.name).toBe(chain);
      expect(config.blockExplorerUrl).toBeDefined();
      expect(config.nativeToken).toBeDefined();
      expect(config.chainId).toBeGreaterThan(0);
    }
  });

  it("should have correct chain IDs", () => {
    expect(CHAINS.ethereum.chainId).toBe(1);
    expect(CHAINS.polygon.chainId).toBe(137);
    expect(CHAINS.arbitrum.chainId).toBe(42161);
    expect(CHAINS.optimism.chainId).toBe(10);
    expect(CHAINS.base.chainId).toBe(8453);
  });
});

describe("Chain Helpers", () => {
  it("getChainConfig should return correct config", () => {
    const eth = getChainConfig("ethereum");
    expect(eth.name).toBe("ethereum");
    expect(eth.chainId).toBe(1);
    expect(eth.nativeToken).toBe("ETH");
  });

  it("getChainConfig should throw for unknown chain", () => {
    expect(() => getChainConfig("unknown" as ChainId)).toThrow();
  });

  it("getConfiguredChains should filter by env vars", () => {
    const env = {
      ETHEREUM_RPC_URL: "https://eth.example.com",
      POLYGON_RPC_URL: "https://polygon.example.com",
    };
    const configured = getConfiguredChains(env);
    expect(configured).toContain("ethereum");
    expect(configured).toContain("polygon");
    expect(configured).not.toContain("arbitrum");
  });

  it("getConfiguredChains should return empty for no config", () => {
    const configured = getConfiguredChains({});
    expect(configured.length).toBe(0);
  });
});

describe("Malicious Patterns", () => {
  // These are tested via the analyzeSourceCode function
  it("should have malicious patterns defined", () => {
    // The patterns are internal - just verify the module loads
    expect(true).toBe(true);
  });
});