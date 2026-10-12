/**
 * Smart Contract Risk Scorer - x402 Risk Scan Endpoint
 * Bounty #61: Smart Contract Risk Scorer
 */

import { RiskScanRequest, RiskScanResponse, X402Manifest } from "./types";
import { scanContractRisk } from "./chains";

const X402_NETWORK = "eip155:8453";
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const ORG_EVM_PAYTO = "0x76EfB727cd3271C7DE22f92437Be212766C9631f";

export async function handleRiskScan(request: Request, env: { [key: string]: string }): Promise<Response> {
  try {
    const body: RiskScanRequest = await request.json();
    
    // Validate required fields
    if (!body.contractAddress || !body.chain || !body.scanDepth) {
      return new Response(JSON.stringify({ error: "Missing required fields: contractAddress, chain, scanDepth" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Validate contract address format
    if (!/^0x[a-fA-F0-9]{40}$/.test(body.contractAddress)) {
      return new Response(JSON.stringify({ error: "Invalid contract address format" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Validate chain
    const validChains = ["ethereum", "polygon", "arbitrum", "optimism", "base"];
    if (!validChains.includes(body.chain)) {
      return new Response(JSON.stringify({ error: "Invalid chain. Must be one of: ethereum, polygon, arbitrum, optimism, base" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Validate scan depth
    if (!["quick", "deep"].includes(body.scanDepth)) {
      return new Response(JSON.stringify({ error: "Invalid scanDepth. Must be 'quick' or 'deep'" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Scan contract risk
    const result = await scanContractRisk(body, env);
    
    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Internal server error" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

export async function handleX402Manifest(): Promise<Response> {
  const manifest: X402Manifest = {
    x402Version: 2,
    resource: "/scan",
    description: "Smart Contract Risk Scorer: Analyze smart contracts for security vulnerabilities and rug pull indicators",
    accepts: [
      {
        scheme: "exact",
        network: X402_NETWORK,
        asset: USDC_BASE,
        payTo: ORG_EVM_PAYTO,
        maxAmountRequired: "10000", // $0.01 in USDC base units
        resource: "/scan",
        description: "One /scan API call",
      },
    ],
    free: ["/health", "/.well-known/x402.json"],
  };
  
  return new Response(JSON.stringify(manifest), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}