import { PublicKey } from "@solana/web3.js";

export type RiskLevel = "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface TokenApproval {
  mint: string;
  tokenAccount: string;
  symbol?: string;
  name?: string;
  balance: number;
  decimals: number;
  delegate: string;
  delegatedAmount: number;
  hasFreezeAuthority: boolean;
  freezeAuthority?: string;
  riskLevel: RiskLevel;
  riskReasons: string[];
}

export interface SecurityAuditReport {
  wallet: string;
  solBalance: number;
  totalTokenAccounts: number;
  approvedTokenAccounts: number;
  securityScore: number; // 0 (Worst) to 100 (Safe)
  highestRisk: RiskLevel;
  approvals: TokenApproval[];
  recommendations: string[];
  scannedAt: string;
}

export interface BalanceDelta {
  account: string;
  preBalance: number;
  postBalance: number;
  delta: number;
}

export interface SimulationAuditResult {
  isSafe: boolean;
  riskLevel: RiskLevel;
  warnings: string[];
  solDeltas: BalanceDelta[];
  tokenDeltas: {
    mint: string;
    account: string;
    delta: number;
  }[];
  logs: string[];
  consumedComputeUnits?: number;
}
