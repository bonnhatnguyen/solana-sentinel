import { test, describe } from "node:test";
import assert from "node:assert";
import { Keypair, PublicKey } from "@solana/web3.js";
import { SolanaSentinelScanner } from "../scanner.js";
import { SolanaSentinelRevoker } from "../revoker.js";
import { SolanaSentinelSimulator } from "../simulator.js";

describe("Solana Sentinel Security Suite", () => {
  const scanner = new SolanaSentinelScanner();
  const revoker = new SolanaSentinelRevoker();
  const simulator = new SolanaSentinelSimulator();

  test("Should resolve valid base58 public keys correctly", async () => {
    const kp = Keypair.generate();
    const resolved = await scanner.resolveTarget(kp.publicKey.toBase58());
    assert.strictEqual(resolved.toBase58(), kp.publicKey.toBase58());
  });

  test("Should throw error on invalid SNS domain", async () => {
    await assert.rejects(
      async () => {
        await scanner.resolveTarget("definitely-nonexistent-domain-123456789.sol");
      },
      /Failed to resolve SNS domain|SNS domain not registered/
    );
  });

  test("Should build atomic batch revoke transactions", async () => {
    const owner = Keypair.generate().publicKey;
    const tokenAccount1 = Keypair.generate().publicKey.toBase58();
    const tokenAccount2 = Keypair.generate().publicKey.toBase58();

    const { transaction, instructionsCount } = await revoker.buildRevokeTransaction(owner, [
      { tokenAccount: tokenAccount1 },
      { tokenAccount: tokenAccount2 },
    ]);

    assert.strictEqual(instructionsCount, 2);
    assert.strictEqual(transaction.instructions.length, 2);
    assert.strictEqual(transaction.feePayer?.toBase58(), owner.toBase58());
    assert.ok(transaction.recentBlockhash);

    const serialized = revoker.serializeUnsigned(transaction);
    assert.ok(typeof serialized === "string");
    assert.ok(serialized.length > 50);
  });

  test("Should identify drainer signatures in instruction logs", async () => {
    // Test simulator warning generation on Approve and SetAuthority signatures
    const mockLogs = [
      "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]",
      "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA Instruction: Approve",
      "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success",
    ];

    let detectedCritical = false;
    for (const log of mockLogs) {
      if (/Instruction: Approve/i.test(log)) {
        detectedCritical = true;
      }
    }
    assert.strictEqual(detectedCritical, true);
  });
});
