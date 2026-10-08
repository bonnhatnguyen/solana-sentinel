import { Connection, PublicKey, Transaction, TransactionInstruction } from "@solana/web3.js";
import { createRevokeInstruction, TOKEN_PROGRAM_ID } from "@solana/spl-token";
import { TokenApproval } from "./types.js";

export class SolanaSentinelRevoker {
  private connection: Connection;

  constructor(rpcUrl: string = "https://api.mainnet-beta.solana.com") {
    this.connection = new Connection(rpcUrl, "confirmed");
  }

  /**
   * Builds an unsigned transaction to revoke delegate authority on specified token accounts
   */
  async buildRevokeTransaction(
    ownerWallet: PublicKey,
    approvalsToRevoke: (TokenApproval | { tokenAccount: string })[]
  ): Promise<{ transaction: Transaction; instructionsCount: number }> {
    const tx = new Transaction();

    for (const item of approvalsToRevoke) {
      const tokenAccountPubkey = new PublicKey(item.tokenAccount);
      const revokeIx = createRevokeInstruction(
        tokenAccountPubkey,
        ownerWallet,
        [],
        TOKEN_PROGRAM_ID
      );
      tx.add(revokeIx);
    }

    const { blockhash } = await this.connection.getLatestBlockhash("confirmed");
    tx.recentBlockhash = blockhash;
    tx.feePayer = ownerWallet;

    return {
      transaction: tx,
      instructionsCount: approvalsToRevoke.length,
    };
  }

  /**
   * Serialize transaction to base64 for external wallet signing (Phantom, Solflare, etc.)
   */
  serializeUnsigned(tx: Transaction): string {
    return tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString("base64");
  }
}
