#!/usr/bin/env node
import { Command } from "commander";
import { PublicKey } from "@solana/web3.js";
import { SolanaSentinelScanner } from "./scanner.js";
import { SolanaSentinelSimulator } from "./simulator.js";
import { SolanaSentinelRevoker } from "./revoker.js";

const program = new Command();

program
  .name("solana-sentinel")
  .description("🛡️ High-Performance Security Scanner & Drainer Detector for Solana Wallets")
  .version("1.0.0");

function formatRiskBadge(score: number): string {
  if (score >= 90) return `\x1b[32m[EXCELLENT: ${score}/100]\x1b[0m`;
  if (score >= 70) return `\x1b[33m[MODERATE: ${score}/100]\x1b[0m`;
  return `\x1b[31m[CRITICAL RISK: ${score}/100]\x1b[0m`;
}

program
  .command("scan <wallet>")
  .description("Audit a Solana wallet address or .sol domain for token approvals and drainer vulnerabilities")
  .option("-r, --rpc <url>", "Custom Solana RPC URL", "https://api.mainnet-beta.solana.com")
  .option("--json", "Output results in JSON format")
  .action(async (walletInput: string, options: { rpc: string; json?: boolean }) => {
    try {
      const scanner = new SolanaSentinelScanner(options.rpc);
      if (!options.json) {
        console.log(`\x1b[36m⚡ Scanning Solana Wallet:\x1b[0m \x1b[1m${walletInput}\x1b[0m`);
      }

      const report = await scanner.scanWallet(walletInput);

      if (options.json) {
        console.log(JSON.stringify(report, null, 2));
        return;
      }

      console.log("\n=======================================================");
      console.log(` 🛡️  SOLANA SENTINEL AUDIT REPORT: ${report.wallet}`);
      console.log("=======================================================");
      console.log(` 💰 SOL Balance:          ${report.solBalance.toFixed(4)} SOL`);
      console.log(` 📦 Total Token Accounts: ${report.totalTokenAccounts}`);
      console.log(` ⚠️  Exposed Delegations:  ${report.approvedTokenAccounts}`);
      console.log(` 📊 Security Score:       ${formatRiskBadge(report.securityScore)}`);
      console.log(` 🚨 Highest Risk Level:   ${report.highestRisk}`);
      console.log("-------------------------------------------------------");

      if (report.approvals.length > 0) {
        console.log("\n[!] DETECTED TOKEN DELEGATE ALLOWANCES:");
        for (const app of report.approvals) {
          console.log(`  - Mint:             ${app.mint}`);
          console.log(`    Token Account:    ${app.tokenAccount}`);
          console.log(`    Delegate Address: \x1b[31m${app.delegate}\x1b[0m`);
          console.log(`    Delegated Amount: ${app.delegatedAmount} / ${app.balance}`);
          console.log(`    Risk Assessment:  \x1b[31m${app.riskLevel}\x1b[0m`);
          for (const reason of app.riskReasons) {
            console.log(`      * ${reason}`);
          }
          console.log("");
        }
      } else {
        console.log("\n\x1b[32m✔ No active token delegate allowances found. Wallet permissions are clean.\x1b[0m\n");
      }

      console.log("📋 RECOMMENDATIONS:");
      for (const rec of report.recommendations) {
        console.log(`  • ${rec}`);
      }
      console.log("=======================================================\n");
    } catch (err: any) {
      console.error(`\x1b[31mError during scan:\x1b[0m ${err.message}`);
      process.exit(1);
    }
  });

program
  .command("revoke <wallet>")
  .description("Generate an unsigned batch transaction to revoke all token delegate authorities")
  .option("-r, --rpc <url>", "Custom Solana RPC URL", "https://api.mainnet-beta.solana.com")
  .action(async (walletInput: string, options: { rpc: string }) => {
    try {
      const scanner = new SolanaSentinelScanner(options.rpc);
      const revoker = new SolanaSentinelRevoker(options.rpc);

      console.log(`\x1b[36m🔍 Inspecting token accounts with active delegates for:\x1b[0m ${walletInput}`);
      const report = await scanner.scanWallet(walletInput);

      if (report.approvals.length === 0) {
        console.log("\x1b[32m✔ No token approvals to revoke. All token permissions are safe.\x1b[0m");
        return;
      }

      console.log(`Found ${report.approvals.length} exposed token account(s). Building batch revoke transaction...`);
      const ownerPubkey = new PublicKey(report.wallet);
      const { transaction, instructionsCount } = await revoker.buildRevokeTransaction(ownerPubkey, report.approvals);
      const base64Tx = revoker.serializeUnsigned(transaction);

      console.log("\n=======================================================");
      console.log(" 📝 UNSIGNED BATCH REVOKE TRANSACTION GENERATED");
      console.log("=======================================================");
      console.log(` Instructions: ${instructionsCount} revoke calls`);
      console.log(` Fee Payer:    ${ownerPubkey.toBase58()}`);
      console.log("\nBase64 Payload (Ready for wallet signing / execution):");
      console.log(`\x1b[33m${base64Tx}\x1b[0m\n`);
      console.log("Copy and import into your Solana wallet or CLI to execute.");
      console.log("=======================================================\n");
    } catch (err: any) {
      console.error(`\x1b[31mError generating revoke transaction:\x1b[0m ${err.message}`);
      process.exit(1);
    }
  });

program
  .command("simulate <transactionBase64>")
  .description("Pre-flight dry-run of a serialized transaction to detect drainer signatures before signing")
  .option("-r, --rpc <url>", "Custom Solana RPC URL", "https://api.mainnet-beta.solana.com")
  .action(async (txBase64: string, options: { rpc: string }) => {
    try {
      const simulator = new SolanaSentinelSimulator(options.rpc);
      console.log("\x1b[36m🧪 Running pre-flight transaction simulation...\x1b[0m");

      const result = await simulator.simulateRawTransaction(txBase64);

      console.log("\n=======================================================");
      console.log(` 🛡️  TRANSACTION SIMULATION RESULT`);
      console.log("=======================================================");
      console.log(` Status:           ${result.isSafe ? "\x1b[32mSAFE\x1b[0m" : "\x1b[31mUNSAFE / RISKY\x1b[0m"}`);
      console.log(` Risk Level:       ${result.riskLevel}`);
      console.log(` Compute Units:    ${result.consumedComputeUnits ?? "N/A"}`);
      console.log("-------------------------------------------------------");

      if (result.warnings.length > 0) {
        console.log("\x1b[31m[!] WARNINGS & DRAINER SIGNATURES DETECTED:\x1b[0m");
        for (const w of result.warnings) {
          console.log(`  ⚠️  ${w}`);
        }
      } else {
        console.log("\x1b[32m✔ No known malicious drainer signatures detected in instruction logs.\x1b[0m");
      }
      console.log("=======================================================\n");
    } catch (err: any) {
      console.error(`\x1b[31mSimulation error:\x1b[0m ${err.message}`);
      process.exit(1);
    }
  });

program.parse(process.argv);
