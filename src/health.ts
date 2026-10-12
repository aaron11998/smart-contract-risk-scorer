/**
 * Smart Contract Risk Scorer - Health Endpoint
 * Bounty #61: Smart Contract Risk Scorer
 */

import { HealthResponse, ChainId } from "./types";
import { CHAINS } from "./chains";

export async function handleHealth(env: { [key: string]: string }): Promise<HealthResponse> {
  const chains: Record<ChainId, { configured: boolean; lastBlock?: number }> = {
    ethereum: { configured: !!env.ETHEREUM_RPC_URL },
    polygon: { configured: !!env.POLYGON_RPC_URL },
    arbitrum: { configured: !!env.ARBITRUM_RPC_URL },
    optimism: { configured: !!env.OPTIMISM_RPC_URL },
    base: { configured: !!env.BASE_RPC_URL },
  };

  const apis = {
    goplus: !!env.GOPLUS_API_KEY,
    token_sniffer: !!env.TOKEN_SNIFFER_API_KEY,
    etherscan: !!env.ETHERSCAN_API_KEY,
    polygonscan: !!env.POLYGONSCAN_API_KEY,
    arbiscan: !!env.ARBISCAN_API_KEY,
    optimistic: !!env.OPTIMISTIC_API_KEY,
    basescan: !!env.BASESCAN_API_KEY,
  };

  const allConfigured = Object.values(chains).every(c => c.configured);
  
  return {
    status: allConfigured ? "ok" : "degraded",
    chains,
    apis,
    timestamp: Date.now(),
  };
}