import { Connection, PublicKey, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID } from "@solana/spl-token";
import { SecurityAuditReport, TokenApproval, RiskLevel } from "./types.js";

export class SolanaSentinelScanner {
  private connection: Connection;

  constructor(rpcUrl: string = "https://api.mainnet-beta.solana.com") {
    this.connection = new Connection(rpcUrl, "confirmed");
  }

  /**
   * Resolve an input string (public key or .sol domain) into a PublicKey
   */
  async resolveTarget(input: string): Promise<PublicKey> {
    const trimmed = input.trim();
    if (trimmed.endsWith(".sol")) {
      const name = trimmed.replace(".sol", "");
      const res = await fetch(`https://sns-sdk-proxy.bonfida.workers.dev/resolve/${encodeURIComponent(name)}`);
      if (!res.ok) {
        throw new Error(`Failed to resolve SNS domain: ${trimmed}`);
      }
      const data = (await res.json()) as { s: string; result?: string };
      if (data.s === "ok" && data.result) {
        return new PublicKey(data.result);
      }
      throw new Error(`SNS domain not registered or invalid: ${trimmed}`);
    }
    return new PublicKey(trimmed);
  }

  /**
   * Scan wallet for active token allowances and security risks
   */
  async scanWallet(walletAddress: string | PublicKey): Promise<SecurityAuditReport> {
    const pubkey = typeof walletAddress === "string" ? await this.resolveTarget(walletAddress) : walletAddress;
    const walletStr = pubkey.toBase58();

    // 1. Fetch SOL balance
    const solLamports = await this.connection.getBalance(pubkey);
    const solBalance = solLamports / LAMPORTS_PER_SOL;

    // 2. Fetch all SPL Token accounts (Standard & Token-2022)
    const [standardAccounts, token2022Accounts] = await Promise.all([
      this.connection.getParsedTokenAccountsByOwner(pubkey, { programId: TOKEN_PROGRAM_ID }),
      this.connection.getParsedTokenAccountsByOwner(pubkey, { programId: TOKEN_2022_PROGRAM_ID }).catch(() => ({ value: [] })),
    ]);

    const allAccounts = [...standardAccounts.value, ...token2022Accounts.value];
    const totalTokenAccounts = allAccounts.length;
    const approvals: TokenApproval[] = [];

    for (const item of allAccounts) {
      const parsedInfo = item.account.data.parsed?.info;
      if (!parsedInfo) continue;

      const mint = parsedInfo.mint;
      const tokenAccount = item.pubkey.toBase58();
      const tokenAmount = parsedInfo.tokenAmount;
      const balance = tokenAmount?.uiAmount ?? 0;
      const decimals = tokenAmount?.decimals ?? 0;

      const delegate = parsedInfo.delegate;
      const delegatedAmountInfo = parsedInfo.delegatedAmount;
      const delegatedAmount = delegatedAmountInfo?.uiAmount ?? 0;

      // Check if there is an active delegate
      if (delegate && delegatedAmount > 0) {
        const riskReasons: string[] = [];
        let riskLevel: RiskLevel = "LOW";

        if (delegatedAmount >= balance && balance > 0) {
          riskLevel = "CRITICAL";
          riskReasons.push(`Delegate has 100% full drainage authority over all ${balance} tokens.`);
        } else if (delegatedAmount > 0) {
          riskLevel = "HIGH";
          riskReasons.push(`Active delegate has allowance to transfer ${delegatedAmount} tokens without owner signature.`);
        }

        // Unknown delegate risk flag
        riskReasons.push(`Delegate contract/wallet: ${delegate}`);

        approvals.push({
          mint,
          tokenAccount,
          balance,
          decimals,
          delegate,
          delegatedAmount,
          hasFreezeAuthority: false,
          riskLevel,
          riskReasons,
        });
      }
    }

    // Calculate overall security score (0 to 100)
    let penalty = 0;
    let highestRisk: RiskLevel = "SAFE";

    for (const app of approvals) {
      if (app.riskLevel === "CRITICAL") {
        penalty += 40;
        highestRisk = "CRITICAL";
      } else if (app.riskLevel === "HIGH") {
        penalty += 20;
        if (highestRisk !== "CRITICAL") highestRisk = "HIGH";
      } else if (app.riskLevel === "MEDIUM") {
        penalty += 10;
        if (highestRisk === "SAFE" || highestRisk === "LOW") highestRisk = "MEDIUM";
      } else {
        penalty += 5;
        if (highestRisk === "SAFE") highestRisk = "LOW";
      }
    }

    const securityScore = Math.max(0, 100 - penalty);
    const recommendations: string[] = [];

    if (approvals.length > 0) {
      recommendations.push(`Revoke delegate allowances on ${approvals.length} exposed token account(s) using 'solana-sentinel revoke'.`);
      recommendations.push("Inspect all third-party dApps connected to this wallet and disconnect stale sessions.");
    } else {
      recommendations.push("No active token allowances detected. Wallet token access boundaries are intact.");
    }

    if (solBalance > 50) {
      recommendations.push("High SOL balance detected in hot wallet. Consider cold storage (Ledger/Safe) for reserve funds.");
    }

    return {
      wallet: walletStr,
      solBalance,
      totalTokenAccounts,
      approvedTokenAccounts: approvals.length,
      securityScore,
      highestRisk,
      approvals,
      recommendations,
      scannedAt: new Date().toISOString(),
    };
  }
}
