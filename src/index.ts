/**
 * Smart Contract Risk Scorer - Main Entry Point
 * Bounty #61: Smart Contract Risk Scorer
 * Cloudflare Worker with x402 payment gating
 */

import { Hono } from "hono";
import { paymentMiddleware } from "x402-hono";
import { handleHealth } from "./health";
import { handleRiskScan, handleX402Manifest } from "./scan_endpoint";

type Bindings = {
  ORG_EVM_PAYTO: string;
  ETHEREUM_RPC_URL: string;
  POLYGON_RPC_URL: string;
  ARBITRUM_RPC_URL: string;
  OPTIMISM_RPC_URL: string;
  BASE_RPC_URL: string;
  ETHERSCAN_API_KEY?: string;
  POLYGONSCAN_API_KEY?: string;
  ARBISCAN_API_KEY?: string;
  OPTIMISTIC_API_KEY?: string;
  BASESCAN_API_KEY?: string;
  GOPLUS_API_KEY?: string;
  TOKEN_SNIFFER_API_KEY?: string;
};

const app = new Hono<{ Bindings: Bindings }>();

// Free endpoints
app.get("/health", async (c) => {
  const health = await handleHealth(c.env);
  return c.json(health);
});

app.get("/.well-known/x402.json", async (c) => {
  return handleX402Manifest();
});

// Paid endpoint with x402
app.use("/scan", async (c, next) => {
  const mw = paymentMiddleware(c.env.ORG_EVM_PAYTO as `0x${string}`, {
    "/scan": {
      price: "$0.01",
      network: "base",
      config: {
        description: "Smart Contract Risk Scorer: Security analysis and rug pull detection",
      },
    },
  });
  return mw(c, next);
});

app.post("/scan", async (c) => {
  return handleRiskScan(c.req.raw, c.env);
});

export default app;