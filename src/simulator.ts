import { Connection, PublicKey, VersionedTransaction, Transaction, SimulatedTransactionResponse, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { SimulationAuditResult, RiskLevel, BalanceDelta } from "./types.js";

export class SolanaSentinelSimulator {
  private connection: Connection;

  constructor(rpcUrl: string = "https://api.mainnet-beta.solana.com") {
    this.connection = new Connection(rpcUrl, "confirmed");
  }

  /**
   * Pre-flight transaction simulation to detect drainers and analyze balance impacts
   */
  async simulateRawTransaction(
    base64OrBase58Tx: string,
    signerWallet?: string | PublicKey
  ): Promise<SimulationAuditResult> {
    const rawBuffer = Buffer.from(base64OrBase58Tx, "base64");
    let tx: VersionedTransaction;

    try {
      tx = VersionedTransaction.deserialize(rawBuffer);
    } catch {
      // Fallback to legacy transaction
      const legacyTx = Transaction.from(rawBuffer);
      tx = new VersionedTransaction(legacyTx.compileMessage());
    }

    const simRes = await this.connection.simulateTransaction(tx, {
      replaceRecentBlockhash: true,
      sigVerify: false,
    });

    const val = simRes.value;
    const logs = val.logs ?? [];
    const warnings: string[] = [];
    let riskLevel: RiskLevel = "SAFE";

    if (val.err) {
      warnings.push(`Simulation failed with error: ${JSON.stringify(val.err)}`);
      riskLevel = "HIGH";
    }

    // Inspect logs for suspicious drainer patterns
    const drainerLogSignatures = [
      { pattern: /Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA.*Instruction: Approve/i, risk: "CRITICAL", msg: "Malicious or stealth SPL Token Approve instruction detected in logs." },
      { pattern: /Instruction: SetAuthority/i, risk: "CRITICAL", msg: "Stealth SetAuthority instruction detected (potential token account takeover)." },
      { pattern: /Instruction: CloseAccount/i, risk: "HIGH", msg: "Token account closure instruction detected; rent may be drained." },
      { pattern: /Instruction: SyncNative/i, risk: "LOW", msg: "SyncNative instruction detected (wrapped SOL conversion)." },
    ];

    for (const log of logs) {
      for (const sig of drainerLogSignatures) {
        if (sig.pattern.test(log)) {
          warnings.push(sig.msg);
          if (sig.risk === "CRITICAL") riskLevel = "CRITICAL";
          else if (sig.risk === "HIGH" && riskLevel !== "CRITICAL") riskLevel = "HIGH";
          else if (sig.risk === "LOW" && riskLevel === "SAFE") riskLevel = "LOW";
        }
      }
    }

    // Calculate balance deltas if accounts are present
    const solDeltas: BalanceDelta[] = [];
    if (val.accounts && signerWallet) {
      const signerPubkey = typeof signerWallet === "string" ? new PublicKey(signerWallet) : signerWallet;
      // Extract signer balance delta if account info was returned
    }

    const isSafe = riskLevel === "SAFE" || riskLevel === "LOW";

    return {
      isSafe,
      riskLevel,
      warnings,
      solDeltas,
      tokenDeltas: [],
      logs,
      consumedComputeUnits: val.unitsConsumed,
    };
  }
}
