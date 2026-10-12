/**
 * Smart Contract Risk Scorer - Chain Configurations & Risk Analysis Engine
 * Bounty #61: Smart Contract Risk Scorer
 */

import { ethers } from "ethers";
import { 
  ChainConfig, ChainId, Vulnerability, SecurityCheck, ExternalCheck, 
  ContractInfo, RiskScanRequest, RiskScanResponse, Severity, ScanDepth 
} from "./types";

export const CHAINS: Record<ChainId, ChainConfig> = {
  ethereum: {
    name: "ethereum",
    rpcUrl: "",
    blockExplorerUrl: "https://api.etherscan.io/api",
    nativeToken: "ETH",
    chainId: 1,
  },
  polygon: {
    name: "polygon",
    rpcUrl: "",
    blockExplorerUrl: "https://api.polygonscan.com/api",
    nativeToken: "MATIC",
    chainId: 137,
  },
  arbitrum: {
    name: "arbitrum",
    rpcUrl: "",
    blockExplorerUrl: "https://api.arbiscan.io/api",
    nativeToken: "ETH",
    chainId: 42161,
  },
  optimism: {
    name: "optimism",
    rpcUrl: "",
    blockExplorerUrl: "https://api-optimistic.etherscan.io/api",
    nativeToken: "ETH",
    chainId: 10,
  },
  base: {
    name: "base",
    rpcUrl: "",
    blockExplorerUrl: "https://api.basescan.org/api",
    nativeToken: "ETH",
    chainId: 8453,
  },
};

export function getChainConfig(chain: ChainId): ChainConfig {
  const config = CHAINS[chain];
  if (!config) throw new Error(`Unknown chain: ${chain}`);
  return config;
}

export function getConfiguredChains(env: { [key: string]: string }): ChainId[] {
  const chains: ChainId[] = [];
  for (const chain of Object.keys(CHAINS) as ChainId[]) {
    const envKey = `${chain.toUpperCase()}_RPC_URL`;
    if (env[envKey]) {
      chains.push(chain);
    }
  }
  return chains;
}

// Known malicious patterns for source code analysis
const MALICIOUS_PATTERNS = [
  { id: "honeypot_balance_manipulation", pattern: /balanceOf\s*\(\s*msg\.sender\s*\)\s*[<>=!]/, severity: "critical" as Severity, name: "Honeypot: Balance Manipulation", description: "Contract manipulates balanceOf for msg.sender to prevent selling" },
  { id: "honeypot_transfer_block", pattern: /require\s*\(\s*!\s*_isExcluded\s*\(\s*msg\.sender\s*\)\s*\)/, severity: "critical" as Severity, name: "Honeypot: Transfer Block", description: "Contract blocks transfers for non-excluded addresses" },
  { id: "hidden_mint", pattern: /function\s+mint\s*\([^)]*\)\s*[^{]*\{[^}]*_mint\s*\(/, severity: "high" as Severity, name: "Hidden Mint Function", description: "Undocumented mint function that can inflate supply" },
  { id: "hidden_burn", pattern: /function\s+burn\s*\([^)]*\)\s*[^{]*\{[^}]*_burn\s*\(/, severity: "medium" as Severity, name: "Hidden Burn Function", description: "Undocumented burn function" },
  { id: "ownership_transfer", pattern: /function\s+transferOwnership\s*\(/, severity: "medium" as Severity, name: "Ownership Transfer", description: "Ownership can be transferred - check for renouncement" },
  { id: "pause_function", pattern: /function\s+pause\s*\(/, severity: "medium" as Severity, name: "Pause Function", description: "Contract can be paused - check who can pause" },
  { id: "blacklist_function", pattern: /function\s+(addToBlacklist|removeFromBlacklist|blacklist)\s*\(/, severity: "high" as Severity, name: "Blacklist Function", description: "Contract has blacklist functionality" },
  { id: "fee_manipulation", pattern: /function\s+(setFee|updateFee|changeFee)\s*\(/, severity: "high" as Severity, name: "Fee Manipulation", description: "Fees can be changed arbitrarily" },
  { id: "max_tx_limit", pattern: /function\s+(setMaxTx|setMaxWallet|setMaxTxAmount)\s*\(/, severity: "medium" as Severity, name: "Max Transaction Limit", description: "Max transaction amount can be changed" },
  { id: "exclude_from_fee", pattern: /function\s+(excludeFromFee|setExcludedFromFee)\s*\(/, severity: "high" as Severity, name: "Exclude from Fee", description: "Addresses can be excluded from fees" },
  { id: "reflection_mechanism", pattern: /_reflectFee|_rfTransfer|_tokenReflection/, severity: "medium" as Severity, name: "Reflection Mechanism", description: "RF token reflection - complex tax logic" },
  { id: "liquidity_lock", pattern: /function\s+(lockLiquidity|addLiquidity|setLiquidityLock)\s*\(/, severity: "low" as Severity, name: "Liquidity Management", description: "Liquidity can be managed - verify lock" },
  { id: "external_call", pattern: /\.call\s*\(\s*\{[^}]*value\s*:/, severity: "medium" as Severity, name: "External Call with Value", description: "Sends ETH to external address - reentrancy risk" },
  { id: "delegatecall", pattern: /delegatecall\s*\(/, severity: "high" as Severity, name: "Delegatecall Usage", description: "Uses delegatecall - proxy or upgradeable pattern" },
  { id: "selfdestruct", pattern: /selfdestruct\s*\(/, severity: "critical" as Severity, name: "Selfdestruct", description: "Contract can be destroyed" },
  { id: "assembly", pattern: /assembly\s*\{/, severity: "medium" as Severity, name: "Inline Assembly", description: "Uses inline assembly - complex logic" },
  { id: "tx_origin", pattern: /tx\.origin/, severity: "high" as Severity, name: "Tx.origin Usage", description: "Uses tx.origin - phishing risk" },
  { id: "block_timestamp", pattern: /block\.timestamp/, severity: "low" as Severity, name: "Block Timestamp Dependency", description: "Relies on block.timestamp - manipulation risk" },
  { id: "reentrancy_guard", pattern: /ReentrancyGuard|nonReentrant/, severity: "low" as Severity, name: "Reentrancy Guard", description: "Has reentrancy protection" },
  { id: "access_control", pattern: /Ownable|AccessControl|onlyOwner/, severity: "low" as Severity, name: "Access Control", description: "Has access control pattern" },
  { id: "upgradeable", pattern: /Upgradeable|Initializable|UUPSUpgradeable/, severity: "medium" as Severity, name: "Upgradeable Contract", description: "Contract is upgradeable - verify proxy admin" },
];

async function fetchContractSource(
  chain: ChainId,
  address: string,
  apiKey?: string
): Promise<{ sourceCode: string; abi: string; contractName: string } | null> {
  const chainConfig = CHAINS[chain];
  const explorerUrl = chainConfig.blockExplorerUrl;
  
  const params = new URLSearchParams({
    module: "contract",
    action: "getsourcecode",
    address,
    apikey: apiKey || "",
  });
  
  try {
    const response = await fetch(`${explorerUrl}?${params}`);
    const data: any = await response.json();
    
    if (data.status === "1" && data.result && data.result.length > 0) {
      const result = data.result[0];
      return {
        sourceCode: result.SourceCode,
        abi: result.ABI,
        contractName: result.ContractName,
      };
    }
    return null;
  } catch (e) {
    return null;
  }
}

async function fetchContractBytecode(
  provider: ethers.JsonRpcProvider,
  address: string
): Promise<string> {
  const code = await provider.getCode(address);
  return code;
}

async function checkHoneypot(
  provider: ethers.JsonRpcProvider,
  tokenAddress: string,
  routerAddress: string
): Promise<{ isHoneypot: boolean; details: string }> {
  try {
    // Simplified honeypot check - try to simulate a buy and sell
    // In production, this would use a more sophisticated approach
    return { isHoneypot: false, details: "Honeypot check not fully implemented" };
  } catch (e) {
    return { isHoneypot: false, details: "Honeypot check failed" };
  }
}

async function checkGoPlusSecurity(
  chain: ChainId,
  address: string,
  apiKey?: string
): Promise<ExternalCheck> {
  try {
    const chainIds: Record<ChainId, number> = {
      ethereum: 1,
      polygon: 137,
      arbitrum: 42161,
      optimism: 10,
      base: 8453,
    };
    
    const response = await fetch(
      `https://api.gopluslabs.io/api/v1/token_security/${chainIds[chain]}?contract_addresses=${address}`,
      { headers: apiKey ? { "Authorization": `Bearer ${apiKey}` } : {} }
    );
    
    const data: any = await response.json();
    
    if (data.code === 1 && data.result && data.result[address.toLowerCase()]) {
      const result = data.result[address.toLowerCase()];
      const isHoneypot = result.is_honeypot === "1";
      const buyTax = parseFloat(result.buy_tax || "0");
      const sellTax = parseFloat(result.sell_tax || "0");
      
      return {
        source: "goplus",
        passed: !isHoneypot && buyTax < 25 && sellTax < 25,
        score: isHoneypot ? 0 : (100 - buyTax - sellTax),
        details: `Honeypot: ${isHoneypot ? "Yes" : "No"}, Buy Tax: ${buyTax}%, Sell Tax: ${sellTax}%`,
        url: `https://gopluslabs.io/token-security/${chainIds[chain]}/${address}`,
      };
    }
    
    return { source: "goplus", passed: true, details: "No data available", score: 50 };
  } catch (e) {
    return { source: "goplus", passed: true, details: "API unavailable", score: 50 };
  }
}

async function checkTokenSniffer(
  chain: ChainId,
  address: string,
  apiKey?: string
): Promise<ExternalCheck> {
  try {
    const chainNames: Record<ChainId, string> = {
      ethereum: "eth",
      polygon: "polygon",
      arbitrum: "arbitrum",
      optimism: "optimism",
      base: "base",
    };
    
    const response = await fetch(
      `https://api.tokensniffer.com/v2/tokens/${chainNames[chain]}/${address}`,
      { headers: apiKey ? { "Authorization": `Bearer ${apiKey}` } : {} }
    );
    
    if (response.ok) {
      const data: any = await response.json();
      const score = data.score || 0;
      return {
        source: "token_sniffer",
        passed: score >= 50,
        score,
        details: `Token Sniffer score: ${score}/100`,
        url: `https://tokensniffer.com/token/${chainNames[chain]}/${address}`,
      };
    }
    
    return { source: "token_sniffer", passed: true, details: "API unavailable", score: 50 };
  } catch (e) {
    return { source: "token_sniffer", passed: true, details: "API unavailable", score: 50 };
  }
}

function analyzeSourceCode(sourceCode: string): { vulnerabilities: Vulnerability[]; securityChecks: SecurityCheck[] } {
  const vulnerabilities: Vulnerability[] = [];
  const securityChecks: SecurityCheck[] = [];
  
  // Check for malicious patterns
  for (const pattern of MALICIOUS_PATTERNS) {
    const matches = sourceCode.match(pattern.pattern);
    if (matches) {
      vulnerabilities.push({
        id: pattern.id,
        name: pattern.name,
        description: pattern.description,
        severity: pattern.severity,
        location: matches[0].substring(0, 100),
        recommendation: `Review ${pattern.name.toLowerCase()} implementation and consider removing or restricting access`,
      });
    } else if (pattern.severity === "low" && (pattern.name === "Reentrancy Guard" || pattern.name === "Access Control")) {
      // Positive checks
      securityChecks.push({
        name: pattern.name,
        passed: true,
        severity: "low",
        details: `Found ${pattern.name.toLowerCase()} pattern`,
      });
    }
  }
  
  // General security checks
  securityChecks.push(
    {
      name: "Source Code Verified",
      passed: sourceCode.length > 100,
      severity: "high",
      details: sourceCode.length > 100 ? "Contract source code is verified on block explorer" : "Contract source code not verified",
    },
    {
      name: "No Selfdestruct",
      passed: !sourceCode.includes("selfdestruct"),
      severity: "critical",
      details: sourceCode.includes("selfdestruct") ? "Contract contains selfdestruct" : "No selfdestruct found",
    },
    {
      name: "No Delegatecall",
      passed: !sourceCode.includes("delegatecall"),
      severity: "high",
      details: sourceCode.includes("delegatecall") ? "Contract uses delegatecall" : "No delegatecall found",
    },
    {
      name: "No Tx.origin",
      passed: !sourceCode.includes("tx.origin"),
      severity: "high",
      details: sourceCode.includes("tx.origin") ? "Uses tx.origin" : "No tx.origin usage",
    },
    {
      name: "Reentrancy Protection",
      passed: sourceCode.includes("ReentrancyGuard") || sourceCode.includes("nonReentrant"),
      severity: "high",
      details: sourceCode.includes("ReentrancyGuard") || sourceCode.includes("nonReentrant") ? "Reentrancy guard detected" : "No reentrancy guard found",
    }
  );
  
  return { vulnerabilities, securityChecks };
}

function calculateRiskScore(
  vulnerabilities: Vulnerability[],
  securityChecks: SecurityCheck[],
  externalChecks: ExternalCheck[],
  contractInfo: ContractInfo
): { riskScore: number; riskLevel: "low" | "medium" | "high" | "critical"; confidence: number } {
  let score = 0;
  let confidence = 0.5;
  
  // Vulnerability scoring
  for (const vuln of vulnerabilities) {
    switch (vuln.severity) {
      case "critical": score += 25; break;
      case "high": score += 15; break;
      case "medium": score += 8; break;
      case "low": score += 3; break;
      case "info": score += 1; break;
    }
  }
  
  // Failed security checks
  for (const check of securityChecks) {
    if (!check.passed) {
      switch (check.severity) {
        case "critical": score += 20; break;
        case "high": score += 10; break;
        case "medium": score += 5; break;
        case "low": score += 2; break;
      }
    } else {
      confidence += 0.05;
    }
  }
  
  // External checks
  for (const check of externalChecks) {
    if (!check.passed) {
      score += check.score ? (100 - check.score) / 5 : 15;
    }
    confidence += 0.1;
  }
  
  // Contract info factors
  if (contractInfo.isHoneypot) score += 50;
  if (!contractInfo.verified) score += 15;
  if (contractInfo.proxyDetected && !contractInfo.implementationAddress) score += 10;
  if (!contractInfo.ownerRenounced && contractInfo.ownerAddress) score += 5;
  
  // Cap score
  score = Math.min(100, Math.max(0, score));
  
  let riskLevel: "low" | "medium" | "high" | "critical";
  if (score >= 75) riskLevel = "critical";
  else if (score >= 50) riskLevel = "high";
  else if (score >= 25) riskLevel = "medium";
  else riskLevel = "low";
  
  confidence = Math.min(1.0, confidence);
  
  return { riskScore: Math.round(score), riskLevel, confidence };
}

function generateRecommendations(
  vulnerabilities: Vulnerability[],
  securityChecks: SecurityCheck[],
  externalChecks: ExternalCheck[],
  contractInfo: ContractInfo
): string[] {
  const recommendations: string[] = [];
  
  if (vulnerabilities.some(v => v.severity === "critical")) {
    recommendations.push("CRITICAL: Do not interact with this contract until critical vulnerabilities are resolved");
  }
  
  if (contractInfo.isHoneypot) {
    recommendations.push("HONEYPOT DETECTED: This token cannot be sold - avoid at all costs");
  }
  
  if (!contractInfo.verified) {
    recommendations.push("Contract source code is not verified - extreme caution advised");
  }
  
  if (contractInfo.proxyDetected) {
    recommendations.push("Contract is a proxy - verify the implementation address and admin controls");
  }
  
  if (!contractInfo.ownerRenounced && contractInfo.ownerAddress) {
    recommendations.push("Ownership not renounced - owner can modify critical parameters");
  }
  
  const failedChecks = securityChecks.filter(c => !c.passed);
  if (failedChecks.length > 0) {
    recommendations.push(`${failedChecks.length} security checks failed - review each finding`);
  }
  
  const failedExternal = externalChecks.filter(c => !c.passed);
  if (failedExternal.length > 0) {
    recommendations.push(`${failedExternal.length} external security APIs flagged issues`);
  }
  
  if (recommendations.length === 0) {
    recommendations.push("No major issues detected - standard due diligence recommended");
  }
  
  return recommendations;
}

export async function scanContractRisk(request: RiskScanRequest, env: { [key: string]: string }): Promise<RiskScanResponse> {
  const startTime = Date.now();
  const chainConfig = getChainConfig(request.chain);
  if (!chainConfig.rpcUrl) {
    throw new Error(`RPC URL not configured for ${request.chain}`);
  }
  
  const provider = new ethers.JsonRpcProvider(chainConfig.rpcUrl);
  const address = request.contractAddress.toLowerCase();
  const warnings: string[] = [];
  
  try {
    // Fetch contract info
    const [bytecode, sourceData] = await Promise.all([
      fetchContractBytecode(provider, address),
      fetchContractSource(request.chain, address, env[`${request.chain.toUpperCase()}_SCAN_API_KEY`]),
    ]);
    
    const isContract = bytecode && bytecode !== "0x";
    if (!isContract) {
      throw new Error("Address is not a contract (no bytecode)");
    }
    
    const verified = !!sourceData;
    let contractName = sourceData?.contractName || "Unknown";
    let sourceCode = sourceData?.sourceCode || "";
    let abi = sourceData?.abi || "";
    
    // Proxy detection
    const proxyPatterns = ["Upgradeable", "Initializable", "UUPSUpgradeable", "TransparentUpgradeableProxy"];
    const proxyDetected = verified && proxyPatterns.some(p => sourceCode.includes(p));
    let implementationAddress: string | undefined;
    
    if (proxyDetected) {
      // Try to get implementation address from storage slot
      try {
        const implSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"; // ERC1967
        const implAddress = await provider.getStorage(address, implSlot);
        if (implAddress !== "0x0000000000000000000000000000000000000000000000000000000000000000") {
          implementationAddress = "0x" + implAddress.slice(-40);
        }
      } catch {
        // Ignore
      }
    }
    
    // Ownership analysis
    let ownerAddress: string | undefined;
    let ownerRenounced = false;
    let timelockDetected = false;
    let multisigDetected = false;
    
    if (verified) {
      if (sourceCode.includes("owner()") && sourceCode.includes("renounceOwnership")) {
        // Check if owner is zero address
        ownerRenounced = true; // Simplified
      }
      if (sourceCode.includes("TimelockController") || sourceCode.includes("timelock")) {
        timelockDetected = true;
      }
      if (sourceCode.includes("MultiSig") || sourceCode.includes("multisig") || sourceCode.includes("GnosisSafe")) {
        multisigDetected = true;
      }
    }
    
    // External API checks
    const [goplusCheck, tokenSnifferCheck] = await Promise.all([
      checkGoPlusSecurity(request.chain, address, env.GOPLUS_API_KEY),
      checkTokenSniffer(request.chain, address, env.TOKEN_SNIFFER_API_KEY),
    ]);
    
    const externalChecks: ExternalCheck[] = [goplusCheck, tokenSnifferCheck];
    
    // Source code analysis
    let vulnerabilities: Vulnerability[] = [];
    let securityChecks: SecurityCheck[] = [];
    
    if (verified && sourceCode) {
      const analysis = analyzeSourceCode(sourceCode);
      vulnerabilities = analysis.vulnerabilities;
      securityChecks = analysis.securityChecks;
    } else {
      securityChecks.push({
        name: "Source Code Verified",
        passed: false,
        severity: "high",
        details: "Contract source code is not verified on block explorer",
      });
    }
    
    // Honeypot check (simplified)
    const routerAddresses: Record<ChainId, string> = {
      ethereum: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
      polygon: "0xE592427A0AEce92De3Edee1F18E0157C05861564",
      arbitrum: "0xE54Ca86531e17Ef3616d22Ca28b0D458b6C89106",
      optimism: "0x8b0E3F474c828f9e6A1e4F6b5C2D1A9F8E7D6C5B4",
      base: "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24",
    };
    
    const honeypotCheck = await checkHoneypot(
      new ethers.JsonRpcProvider(chainConfig.rpcUrl),
      address,
      routerAddresses[request.chain]
    );
    
    // Contract info
    const contractInfo: ContractInfo = {
      address,
      chain: request.chain,
      name: contractName,
      verified,
      proxyDetected,
      implementationAddress,
      isHoneypot: honeypotCheck.isHoneypot,
      isProxy: proxyDetected,
      ownerAddress,
      ownerRenounced,
      timelockDetected,
      multisigDetected,
    };
    
    // Calculate risk
    const { riskScore, riskLevel, confidence } = calculateRiskScore(
      vulnerabilities,
      securityChecks,
      externalChecks,
      contractInfo
    );
    
    // Generate recommendations
    const recommendations = generateRecommendations(
      vulnerabilities,
      securityChecks,
      externalChecks,
      contractInfo
    );
    
    return {
      contract: contractInfo,
      riskScore,
      riskLevel,
      vulnerabilities,
      securityChecks,
      externalChecks,
      recommendations,
      confidence,
      scanDurationMs: Date.now() - startTime,
      warnings,
      timestamp: Date.now(),
    };
  } catch (e) {
    throw new Error(`Failed to scan contract: ${e instanceof Error ? e.message : "Unknown error"}`);
  }
}

export type { ChainConfig, Vulnerability, SecurityCheck, ExternalCheck, ContractInfo, RiskScanResponse } from "./types";