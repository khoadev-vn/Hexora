<div align="center">
  <img src="../assets/banner.png" alt="Hexora Guide" width="100%" />
</div>

# 📖 HEXORA COMPLETE USER GUIDE (FROM A TO Z)
> **Designed for everyone:** Developers, Security Auditors, Tech Leads, DevOps Engineers & AI Agent Enthusiasts.

---

## 🌟 TABLE OF CONTENTS
1. [System Requirements](#1-system-requirements)
2. [Option 1: Instant Zero-Install Execution (Recommended)](#2-option-1-instant-zero-install-execution-recommended)
3. [Option 2: Global System Installation (Global CLI)](#3-option-2-global-system-installation-global-cli)
4. [Detailed Target Scanning Guide](#4-detailed-target-scanning-guide)
5. [Understanding & Using Audit Reports (PDF, TXT, HTML, SARIF)](#5-understanding--using-audit-reports-pdf-txt-html-sarif)
6. [1-Click AI Agent Integration (Antigravity, Cursor, Claude & Windsurf)](#6-1-click-ai-agent-integration-antigravity-cursor-claude--windsurf)
7. [Real-time Autonomous Watch Mode (On Save Guard)](#7-real-time-autonomous-watch-mode-on-save-guard)
8. [Git Pre-Commit Gate (Prevent Secret & Code Leaks)](#8-git-pre-commit-gate-prevent-secret--code-leaks)
9. [Running Adversarial Benchmarks vs Snyk / Semgrep / SonarQube](#9-running-adversarial-benchmarks-vs-snyk--semgrep--sonarqube)
10. [Ingesting Zero-Day & Custom CVE Threat Intelligence](#10-ingesting-zero-day--custom-cve-threat-intelligence)
11. [CI/CD Automation with GitHub Actions](#11-cicd-automation-with-github-actions)
12. [CLI Command Cheatsheet](#12-cli-command-cheatsheet)

---

## 1. System Requirements
Hexora is lightweight and has zero dependency on Docker, heavy JVMs, or external databases:
- **Node.js**: Version 18.0.0 or higher. (Check with: `node -v`)
- **Operating System**: Windows, macOS, Linux (Ubuntu, Debian, Fedora, Arch, etc.).

---

## 2. Option 1: Instant Zero-Install Execution (Recommended)
You don't need to clone or install anything globally. Simply open your Terminal in your project root and run:

```bash
npx hexora .
```

*On first run, `npx` automatically fetches the latest Hexora engine and completes a full workspace audit in under 3 seconds.*

---

## 3. Option 2: Global System Installation (Global CLI)
If you frequently audit multiple projects and want ultra-concise commands (`hexora` or `audit`):

### Option A: Install Directly from GitHub (Fastest)
```bash
npm install -g khoadev-vn/Hexora
```

### Option B: Automated One-Line Installer
- **Linux / macOS**:
```bash
curl -fsSL https://raw.githubusercontent.com/khoadev-vn/Hexora/main/install.sh | bash
```

- **Windows PowerShell**:
```powershell
irm https://raw.githubusercontent.com/khoadev-vn/Hexora/main/install.ps1 | iex
```

### Option C: Install from Source (For Contributors)
```bash
# 1. Clone repository
git clone https://github.com/khoadev-vn/Hexora.git
cd Hexora

# 2. Install dependencies & build TypeScript source
npm install
npm run build

# 3. Register global binary symlink
npm link
```

Now you can run Hexora from any folder:
```bash
hexora .
# Or short alias:
audit
```

---

## 4. Detailed Target Scanning Guide

### A. Scan the Current Project Directory
```bash
npx hexora .
```

**Live Terminal Output:**
```text
PS D:\my-app> npx hexora .

Hexora

Scanning project...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Secrets                  1 finding
Security vulnerabilities 2 findings
Vulnerable dependencies  1 finding
Insecure configuration   0 findings

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
4 findings detected (Adversarial filtered 6 false positives)

Critical: 1
High:     2
Medium:   1
Low:      0

Report:
  📄 Text (Structured): ./hexora-report.txt
  📑 PDF (Executive):   ./hexora-report.pdf
  📝 Markdown:          ./hexora-report.md
  🌐 HTML Dashboard:    ./hexora-report.html
```

* **Engine Mechanics:** Hexora automatically executes a 4-tier pipeline:
  1. AST semantic parsing and data-flow taint analysis.
  2. Shannon Entropy credential & high-entropy secret detection.
  3. Software Composition Analysis (SCA) checking global CVE vulnerability advisories.
  4. Red-Team Dual-Agent Adversarial filter disproving mock environments, sanitizers, and framework protections to eliminate false positives.

### B. Scan a Specific Directory or File
```bash
npx hexora ./path/to/my-web-app
npx hexora /var/www/ecommerce/src/auth.ts
```

### C. Audit a Remote GitHub Repository (Isolated Sandbox)
Hexora includes an automated sandbox cloner: it performs a shallow clone into an ephemeral workspace, audits the codebase, and outputs reports without touching your local project:
```bash
npx hexora facebook/react
npx hexora expressjs/express
```

### D. Detailed 4-Tier Audit Logs (Verbose Mode)
If you want to inspect each phase of AST parsing, Shannon entropy calculation, dependency graph analysis, and Red-Team adversarial reasoning:
```bash
npx hexora . --verbose
```

### E. Non-Breaking CI Scan (No-Fail Mode)
By default, detecting `CRITICAL` or `HIGH` vulnerabilities returns an `exit code 1` to block broken builds. To audit without failing the process:
```bash
npx hexora . --no-fail
```

---

## 5. Understanding & Using Audit Reports (PDF, TXT, HTML, SARIF)

Upon completion, Hexora automatically generates comprehensive reports in standard industry formats:

| Report File | Purpose & Recommended Audience |
| :--- | :--- |
| **`hexora-report.pdf`** | **Executive Summary (PDF)**: High-resolution graphical report with executive risk matrix, CVSS severity breakdowns, PoC reproduction steps, and unified diff patches. Perfect for stakeholders, clients, and compliance reviews. |
| **`hexora-report.txt`** | **Structured Plain Text (UNIX / Dev Friendly)**: Clean text format designed for terminal inspection, `grep`, `cat`, piping, or review inside lightweight editors (Notepad, Vim, Nano). |
| **`hexora-report.html`** | **Interactive Web Dashboard**: Open in any browser (Chrome, Edge, Safari). Features an interactive dark-mode cyberpunk interface with real-time severity filters and expandable code diffs. |
| **`hexora-report.md`** | **Markdown Report**: GitHub Flavored Markdown ready to paste directly into GitHub Issues, Pull Request descriptions, or internal documentation. |
| **`.hexora-results/audit-report.sarif`** | **OASIS SARIF Standard**: Ingested directly by GitHub **Security > Code Scanning** tab, SonarQube, and enterprise vulnerability management suites. |

---

## 6. 1-Click AI Agent Integration (Antigravity, Cursor, Claude & Windsurf)

Using **Google Antigravity**, **Cursor IDE**, **Claude Code / Desktop**, **Windsurf**, or autonomous coding agents? Hexora configures them automatically with zero manual JSON editing:

### Option 1: Direct Skill & MCP Setup for Google Antigravity
```bash
npx hexora skill antigravity
```

**Terminal Output:**
```text
PS D:\my-app> npx hexora skill antigravity

======================================================
📦 HEXORA AI AGENT SKILL & MCP INSTALLER
   Target: ANTIGRAVITY
   Workspace: D:\my-app
======================================================

✅ Installed Google Antigravity Skill & MCP server:
   - C:\Users\user\.gemini\config\mcp_config.json
   - D:\my-app\.agents\skills\hexora\SKILL.md
   - C:\Users\user\.gemini\config\skills\hexora\SKILL.md
   - D:\my-app\.agents\rules\hexora-security.md
   - D:\my-app\GEMINI.md

✨ Installation complete! Your AI agents are ready to audit code.
```

### Option 2: Universal Multi-Agent Interactive Wizard
```bash
npx hexora init
```

**Interactive Menu:**
```text
PS D:\my-app> npx hexora init

======================================================
🚀 HEXORA UNIVERSAL AI AGENT & SECURITY SETUP
======================================================

Where do you want to integrate Hexora?

  [1] Google Antigravity (IDE & CLI - MCP & Skills)
  [2] Cursor (MCP Server & .cursor/rules)
  [3] Claude Code (CLI ~/.claude.json)
  [4] Claude Desktop (claude_desktop_config.json)
  [5] VS Code (Workspace Tasks & Extension)
  [6] Windsurf (.windsurf & .windsurfrules)
  [7] Terminal Global Shortcuts & Git Pre-commit Hook
  [8] All Integrations (Recommended for Full AI Stack)

Select an option (1-8): 8

======================================================
⚡ INTEGRATING HEXORA SECURITY PROTOCOL
   Workspace: D:\my-app
======================================================

✅ Configured Google Antigravity Skill & MCP server
✅ Configured Cursor MCP (.cursor/mcp.json) & Rules (.cursor/rules/hexora.mdc)
✅ Configured Claude Code (~/.claude.json)
✅ Configured Claude Desktop (claude_desktop_config.json)
✅ Added VS Code tasks (.vscode/tasks.json)
✅ Created Terminal shortcuts 'hexora' and 'audit'
✅ Installed pre-commit security hook (.git/hooks/pre-commit)

🎉 Hexora configured successfully across all environments!
```

---

### 🤖 14 MCP Security Tools Provided to AI Agents:

Hexora exposes a comprehensive security toolkit to autonomous AI models:

| MCP Tool | Core Function | Example Agent Prompt |
| :--- | :--- | :--- |
| `scan_project` | Run full workspace audit with adversarial verification | *"Scan this entire repository with Hexora"* |
| `audit_scan_file` | Instantly audit a specific file or in-memory buffer | *"Check the security of my modified authController.ts"* |
| `get_findings` | Retrieve verified vulnerability findings grouped by severity | *"List all CRITICAL security findings in this project"* |
| `apply_fix` | Apply minimal, safe unified diff patch to source code | *"Apply the recommended Hexora patch for the SQL injection"* |
| `audit_explain_vulnerability` | Deep root-cause analysis, CVSS scoring, and architectural risk | *"Explain why this function is vulnerable to Reentrancy"* |
| `audit_generate_poc` | Generate non-destructive reproduction PoC script | *"Generate a PoC test script proving this privilege bypass"* |
| `audit_get_workspace_posture` | Compute security posture score (A+ to F) and risk breakdown | *"Evaluate the overall security posture score of the repo"* |
| `validate_finding` | Adversarially challenge finding to rule out mock/sanitized code | *"Validate whether this finding is a false positive"* |
| `audit_check_snippet` | Rapidly audit an isolated code snippet or function | *"Is this regex vulnerable to ReDoS?"* |
| `audit_learn_report` | Ingest new CVE or bug bounty writeup into threat memory | *"Learn this newly disclosed CVE writeup into memory"* |
| `audit_search_knowledge` | Query attack mechanisms & defenses from threat database | *"Find attack variants related to Solana CPI hijack"* |
| `audit_get_threat_intel_stats` | Inspect statistics on learned attack vectors and CVEs | *"Show me current threat intelligence database stats"* |
| `audit_export_skill` | Export skill rules & MCP configs to target workspace | *"Export Hexora skill to the current Cursor workspace"* |
| `audit_scan_directory` | Audit a specific directory and produce targeted findings | *"Audit only the src/controllers folder"* |

---

## 7. Real-time Autonomous Watch Mode (On Save Guard)

Want active real-time protection while coding without manual terminal commands?

```bash
npx hexora watch
```

**Live Terminal Watch Output:**
```text
PS D:\my-app> npx hexora watch

======================================================
👁️  HEXORA REAL-TIME WATCH ENGINE
   Monitoring: D:\my-app
   Auto-scans and verifies code on every save (Ctrl+S)
======================================================

⚡ Watcher active! Listening for file changes... (Press Ctrl+C to stop)

[20:15:10] 🟢 CLEAN: src/services/user.service.ts (0 issues, 13.5ms)
[20:15:42] 🟢 CLEAN: src/utils/format.ts (0 issues, 10.2ms)

------------------------------------------------------
[20:16:05] 🚨 SECURITY ALERT: src/routes/auth.ts (18.1ms)
Found 1 genuine vulnerability(ies):

  🔴 CRITICAL | Hardcoded Cloud Access Key (Line 14) [CWE-798]
  Target: src/routes/auth.ts:14
  💡 Suggested Fix: Extract credentials to environment variables (.env) and access via process.env.
------------------------------------------------------
```

* **Key Highlights:**
  - Background daemon monitors file save events with a 250ms debouncing window.
  - Micro-delta AST parsing analyzes modified files in under **20 milliseconds**—zero IDE lag.
  - Generates immediate terminal alerts with line-accurate locations and actionable remediation advice.

---

## 8. Git Pre-Commit Gate (Prevent Secret & Code Leaks)

Prevent team members from accidentally committing secrets, API keys, or SQL injections into Git history:

```bash
npx hexora hook
```

**Hook Installation:**
```text
PS D:\my-app> npx hexora hook
✅ Installed pre-commit hook at D:\my-app\.git\hooks\pre-commit
```

**Enforcement Demo (Commit Intercepted):**
```text
PS D:\my-app> git add src/routes/payment.ts
PS D:\my-app> git commit -m "feat: integrate stripe payment"

🛡️ Hexora Pre-Commit Gate: Verifying staged files...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Secrets                  1 finding
Security vulnerabilities 0 findings
Vulnerable dependencies  0 findings
Insecure configuration   0 findings
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

❌ [Hexora Pre-Commit Hook] Hardcoded Secret Detected!
   File: src/routes/payment.ts:18 -> Unencrypted Stripe API Secret Key
   
Commit rejected to protect repository history.
To inspect or fix, run: npx hexora .
```

---

## 9. Running Adversarial Benchmarks vs Snyk / Semgrep / SonarQube

Verify Hexora's detection accuracy and false-positive elimination rate against industry benchmarks:

```bash
npx hexora bench
```

**Benchmark Results:**
```text
PS D:\my-app> npx hexora bench

======================================================
🥊 HEXORA GLOBAL VULNERABILITY BENCHMARK ARENA
======================================================
Running 11 high-fidelity test suites across Web2, Web3, and AI Agents...

[Suite 1/11] SQL Injection in ORM Bypass ............. ✅ DETECTED (Confirmed)
[Suite 2/11] False Positive: Mock Test DB Client ..... 🛡️ DISPROVED (Adversarial)
[Suite 3/11] Solana Arbitrary CPI Missing Signer ..... ✅ DETECTED (Confirmed)
[Suite 4/11] False Positive: Constant In-Memory Key .. 🛡️ DISPROVED (Adversarial)
[Suite 5/11] Prompt Injection & Tool Exfiltration ... ✅ DETECTED (Confirmed)
...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BENCHMARK RESULTS SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
True Positive Detection Rate:     100.0% (11/11)
False Positive Elimination Rate:  100.0% (0 false positives)
Execution Time:                   412ms
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 10. Ingesting Zero-Day & Custom CVE Threat Intelligence

When new CVE advisories or bug bounty writeups are published, ingest them immediately into Hexora's detection engine:

```bash
npx hexora learn ./exploits/solana-cpi-writeup.md
```

**Terminal Output:**
```text
PS D:\my-app> npx hexora learn ./exploits/solana-cpi-writeup.md

📚 [Hexora Threat Ingestion] Processing: ./exploits/solana-cpi-writeup.md...
✨ Successfully ingested report: [CVE-2024-SOL-01] "Arbitrary CPI Execution in Solana Anchor"
   - Attack Variants learned: cpi_spoofing, missing_program_id_check
   - Mitigation: Verify program_id matches expected Pubkey before invoking invoke_signed

PS D:\my-app> npx hexora intel

======================================================
🧠 HEXORA THREAT INTELLIGENCE KNOWLEDGE VAULT
======================================================
Total Reports Learned: 14
Total Attack Variants: 48

📌 [CVE-Database] CVE-2024-SOL-01: Arbitrary CPI Execution (CRITICAL)
   - Ecosystem: Solana | Class: CPI_HIJACK
   - Attack Variants: cpi_spoofing; missing_program_id_check
```

---

## 11. CI/CD Automation with GitHub Actions

Add Hexora to your GitHub Actions pipeline in just a few lines of YAML.

Create `.github/workflows/security.yml` in your project repository:
```yaml
name: Hexora Security Gate

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run Hexora Security Audit
        run: npx --yes hexora .

      - name: Upload SARIF Report to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: .hexora-results/audit-report.sarif
```

---

## 12. CLI Command Cheatsheet

| Task | Command |
| :--- | :--- |
| **Audit Current Workspace** | `hexora .` or `npx hexora .` |
| **Verbose 4-Tier Audit** | `hexora . --verbose` |
| **Audit Remote GitHub Repo** | `hexora <owner>/<repo>` |
| **Real-Time Watch on Save** | `hexora watch` |
| **AI Agent Setup (Cursor, Claude, Antigravity)** | `hexora init` |
| **Install Git Pre-Commit Hook** | `hexora hook` |
| **Run Adversarial Benchmark** | `hexora bench` |
| **Ingest CVE / Threat Writeup** | `hexora learn <file.md>` |
| **Inspect Threat Intelligence** | `hexora intel` |
| **Display CLI Help** | `hexora --help` |

---
*Authored and verified by Khoa Dev & Hexora Core Contributors.*
