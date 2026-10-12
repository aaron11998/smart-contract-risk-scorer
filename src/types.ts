/**
 * Smart Contract Risk Scorer - Shared Types
 * Bounty #61: Smart Contract Risk Scorer
 */

// Supported chains
export type ChainId = "ethereum" | "polygon" | "arbitrum" | "optimism" | "base";

// Chain configuration
export interface ChainConfig {
  name: ChainId;
  rpcUrl: string;
  blockExplorerUrl: string;
  apiKey?: string;
  nativeToken: string;
  chainId: number;
}

// Scan depth
export type ScanDepth = "quick" | "deep";

// Vulnerability severity
export type Severity = "critical" | "high" | "medium" | "low" | "info";

// Vulnerability
export interface Vulnerability {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  location?: string; // Function or line reference
  recommendation: string;
  cwe?: string; // CWE ID if applicable
}

// Security check result
export interface SecurityCheck {
  name: string;
  passed: boolean;
  severity: Severity;
  details: string;
  evidence?: string;
}

// External API check
export interface ExternalCheck {
  source: "goplus" | "token_sniffer" | "etherscan" | "custom";
  passed: boolean;
  score?: number; // 0-100
  details: string;
  url?: string;
}

// Contract info
export interface ContractInfo {
  address: string;
  chain: ChainId;
  name?: string;
  symbol?: string;
  creator?: string;
  creationTx?: string;
  creationTimestamp?: number;
  verified: boolean;
  proxyDetected: boolean;
  implementationAddress?: string;
  isHoneypot: boolean;
  isProxy: boolean;
  ownerAddress?: string;
  ownerRenounced: boolean;
  timelockDetected: boolean;
  multisigDetected: boolean;
}

// Risk scan request
export interface RiskScanRequest {
  contractAddress: string;
  chain: ChainId;
  scanDepth: ScanDepth;
}

// Risk scan response
export interface RiskScanResponse {
  contract: ContractInfo;
  riskScore: number; // 0-100 (higher = more risky)
  riskLevel: "low" | "medium" | "high" | "critical";
  vulnerabilities: Vulnerability[];
  securityChecks: SecurityCheck[];
  externalChecks: ExternalCheck[];
  recommendations: string[];
  confidence: number; // 0.0-1.0
  scanDurationMs: number;
  warnings: string[];
  timestamp: number;
}

// Health endpoint response
export interface HealthResponse {
  status: "ok" | "degraded";
  chains: Record<ChainId, { configured: boolean; lastBlock?: number }>;
  apis: Record<string, boolean>;
  timestamp: number;
}

// x402 manifest
export interface X402Manifest {
  x402Version: number;
  resource: string;
  description: string;
  accepts: Array<{
    scheme: "exact";
    network: string;
    asset: string;
    payTo: string;
    maxAmountRequired: string;
    resource: string;
    description: string;
  }>;
  free: string[];
}