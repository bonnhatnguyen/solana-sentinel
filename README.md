# 🛡️ Solana Sentinel (`solana-sentinel`)

[![npm version](https://img.shields.io/badge/version-1.0.0-00FFA3.svg?style=flat-square)](https://github.com/bonnhatnguyen/solana-sentinel)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Solana](https://img.shields.io/badge/Solana-Mainnet--Ready-9945FF.svg?style=flat-square&logo=solana)](https://solana.com)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6.svg?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen.svg?style=flat-square)](#testing)

**Production Security Scanner, Drainer Detector, and Pre-flight Transaction Auditor for the Solana Ecosystem.**

Solana Sentinel audits wallet permissions, uncovers sneaky SPL token delegate allowances (the #1 attack vector for phishing drainers), simulates transactions before signing to detect honeypots, and builds atomic 1-click batch revoke transactions.

---

## ⚡ Key Features

- **🔍 Deep Wallet Allowance Auditing**: Scans all Standard SPL Token and Token-2022 accounts for active delegate permissions. Computes a normalized **0–100 Security Score**.
- **🚫 Stealth Drainer Detection**: Parses pre-flight transaction instruction logs to catch hidden `Approve` or `SetAuthority` calls before you sign.
- **⚡ 1-Click Batch Revoke**: Automatically generates an unsigned batch transaction bundling `Revoke` instructions across all compromised token accounts.
- **🌐 Native SNS Resolution**: First-class support for `.sol` domains (e.g. `bonn.sol`) via Bonfida proxy.
- **🧪 Zero-Risk Simulation**: Pre-flight cluster simulation with accurate compute unit estimation and balance delta extraction.
- **💻 Dual Interface**: Available as both an ergonomic CLI tool and a type-safe TypeScript/Node.js library.

---

## 📥 Installation

```bash
# Global CLI installation
npm install -g @bonnhatnguyen/solana-sentinel

# Or install locally in your project
npm install @bonnhatnguyen/solana-sentinel
```

---

## 🚀 Quick Start (CLI)

### 1. Audit Any Wallet or `.sol` Domain

```bash
solana-sentinel scan 7Np41D2d...9XkL
# Or use SNS domain:
solana-sentinel scan vitalik.sol
```

**Output Preview:**
```text
=======================================================
 🛡️  SOLANA SENTINEL AUDIT REPORT: 7Np41D2d...9XkL
=======================================================
 💰 SOL Balance:          12.4500 SOL
 📦 Total Token Accounts: 14
 ⚠️  Exposed Delegations:  2
 📊 Security Score:       [MODERATE: 70/100]
 🚨 Highest Risk Level:   HIGH
-------------------------------------------------------

[!] DETECTED TOKEN DELEGATE ALLOWANCES:
  - Mint:             EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
    Token Account:    4vM9k...3kP2
    Delegate Address: 3B7x...9Ka1
    Delegated Amount: 500 / 1250
    Risk Assessment:  HIGH
      * Active delegate has allowance to transfer 500 tokens without owner signature.
      * Delegate contract/wallet: 3B7x...9Ka1

📋 RECOMMENDATIONS:
  • Revoke delegate allowances on 2 exposed token account(s) using 'solana-sentinel revoke'.
  • Inspect all third-party dApps connected to this wallet and disconnect stale sessions.
=======================================================
```

### 2. Generate Batch Revoke Transaction

```bash
solana-sentinel revoke 7Np41D2d...9XkL
```

This returns an unsigned, base64-encoded `Transaction` with all necessary revoke instructions. Import into Phantom, Solflare, or sign via Solana CLI.

### 3. Simulate Transaction Before Signing

```bash
solana-sentinel simulate <BASE64_TRANSACTION_PAYLOAD>
```

---

## 🛠️ Programmatic TypeScript API

```typescript
import { SolanaSentinelScanner, SolanaSentinelRevoker } from "@bonnhatnguyen/solana-sentinel";

const scanner = new SolanaSentinelScanner("https://api.mainnet-beta.solana.com");

// 1. Audit Wallet
const report = await scanner.scanWallet("bonn.sol");
console.log(`Security Score: ${report.securityScore}/100`);

// 2. Build Batch Revoke if exposed
if (report.approvals.length > 0) {
  const revoker = new SolanaSentinelRevoker();
  const { transaction, instructionsCount } = await revoker.buildRevokeTransaction(
    new PublicKey(report.wallet),
    report.approvals
  );
  console.log(`Constructed batch revoke with ${instructionsCount} instructions.`);
}
```

---

## 🧪 Testing

```bash
npm test
```

---

## 📄 License

MIT License © 2026 [bonnhatnguyen](https://github.com/bonnhatnguyen)
