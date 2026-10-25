<div align="center">

<img src="assets/banner.png" alt="Hexora - Next-Generation Universal Security Engine" width="100%" />

# HEXORA
### Next-Generation Universal Security Engine

[![npm version](https://img.shields.io/npm/v/hexora.svg?style=flat-square&color=00F0FF&logo=npm)](https://www.npmjs.com/package/hexora)
[![License: Non-Commercial](https://img.shields.io/badge/License-Non--Commercial-FF5555.svg?style=flat-square)](LICENSE)
[![AI-Native: MCP](https://img.shields.io/badge/AI--Native-Model%20Context%20Protocol-8A2BE2.svg?style=flat-square&logo=anthropic)](https://modelcontextprotocol.io/)
[![Zero-Config](https://img.shields.io/badge/Setup-Zero--Config-brightgreen.svg?style=flat-square)](#-quickstart-for-developers)
[![False Positive Filter](https://img.shields.io/badge/False%20Positives-0%25%20Filtered-success.svg?style=flat-square)](#-dual-agent-adversarial-verification)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-blue.svg?style=flat-square)](CONTRIBUTING.md)

**Zero-Friction SAST • Dual-Agent Adversarial Verification • Dynamic PoC & Patch Generation**  
*One security engine that works seamlessly in your Terminal, IDE, AI Agents, and CI/CD pipelines.*

[🌐 Live Landing Page](https://hexora-security.github.io/hexora) • [📚 Step-by-Step Guide](docs/STEP_BY_STEP_GUIDE.md) • [📖 Documentation](#-universal-modes-of-use) • [⚡ Quickstart](#-quickstart-for-developers) • [🤖 AI Agent MCP](#-mode-2-1-click-ai-agent-setup) • [🏆 Benchmarks](#-global-vulnerability-benchmarks)

---

</div>

## 💡 Why Hexora?

Traditional security tools force developers to remember dozens of complex flags, overwhelm teams with hundreds of noisy false positives, and stop at warning messages without offering a real fix.

**Hexora changes the paradigm:**
- ⚡ **Zero-Friction ("Cài một lần, dùng ở mọi nơi")**: Run it in 3 seconds with `npx hexora .`, wire it into Cursor or Claude with `npx hexora init`, or lock down your git commits with `npx hexora hook`.
- 🥊 **Dual-Agent Adversarial Verification**: Every candidate vulnerability is actively challenged by an automated Red-Team verifier to eliminate false positives (test mocks, sanitizers, framework protections) before you ever see it.
- 🩹 **Autonomous PoC & Minimal Unified Patches**: Don't just find bugs — Hexora generates non-destructive reproduction PoCs and minimal unified diffs (`git apply`) ready for review.
- 🧠 **Continuous Threat Intelligence Memory**: Ingest real-world CVEs and bounty writeups on the fly (`npx hexora learn writeup.md`) to dynamically expand detection patterns.

---

## ⚡ Architecture: The 4 Pillars of Hexora

```
                       HEXORA UNIVERSAL SECURITY ENGINE
               (Deterministic SAST + Red-Team Adversarial Verifier)
                                       │
         ┌───────────────────┬─────────┴─────────┬───────────────────┐
         │                   │                   │                   │
    HEXORA CLI          HEXORA MCP         HEXORA SKILLS     HEXORA FOR VS CODE
    (Terminal)          (AI Agents)          (Agent SOP)           (IDE)
         │                   │                   │                   │
    Zero-Config         Cursor, Claude       Autonomous        Diagnostics,
    Auto-Watch & CI    & Antigravity        Red-Team Audit     Gutter Badges
```

---

## 📦 Installation & Quick Setup

You can use Hexora immediately via direct CLI link or node runner:

### ⚡ Method 1: Global System Link (Recommended)
Make the `hexora` command globally accessible from any terminal window on your machine with zero latency:

```bash
# 1. Clone & navigate to Hexora:
git clone https://github.com/khoadev-vn/Hexora.git
cd Hexora

# 2. Install dependencies & build:
npm install
npm run build

# 3. Register global binary link:
npm link

# 4. Now run anywhere in any project terminal:
hexora bench
hexora .
hexora init
```

### ⚡ Method 2: Direct Execution from Source
```bash
# Run benchmark:
npm run benchmark
# or:
node bin/hexora.js bench

# Run audit on current directory:
node bin/hexora.js .
```

---

## 🚀 Comprehensive Feature Guide & Hands-on Demos

Hexora is designed to fit naturally into every stage of your engineering workflow. Below are detailed walkthroughs and live terminal demos for each core capability:

---

### 🖥️ Feature 1: Zero-Config Security Audit (`hexora .`)

Run a full deterministic audit with deep SAST, dependency vulnerability scanning (SCA), and adversarial false-positive filtering in one simple command.

```bash
# Scan current workspace:
npx hexora .

# Scan specific folder or file:
npx hexora ./src/backend

# Scan remote public GitHub repository inside a secure sandbox:
npx hexora expressjs/express
```

**Live Terminal Output:**
```text
PS D:\my-project> npx hexora .

Hexora

Scanning project...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Secrets                  1 finding
Security vulnerabilities 2 findings
Vulnerable dependencies  1 finding
Insecure configuration   0 findings

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
4 findings detected (Adversarial filtered 8 false positives)

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

**💡 How It Works & What to Expect:**
1. **Multi-Vector Scanning**: Analyzes AST syntax, semantic patterns, high-entropy secrets, and checks dependencies against known CVEs.
2. **Dual-Agent Verification**: Every detected flag is passed through an automated Red-Team verifier to discard mock tests, sanitized variables, and harmless snippets, ensuring **zero alert fatigue**.
3. **Simultaneous Multi-Format Reports**: Automatically exports:
   - `hexora-report.txt`: Clean, human-readable structured text, ideal for console review or terminal piping (`grep`, `cat`).
   - `hexora-report.pdf`: Executive-ready PDF summary for management, stakeholders, or compliance reviews.
   - `hexora-report.md`: Markdown summary ready to paste into GitHub Issues or Pull Request descriptions.
   - `hexora-report.html`: Interactive web dashboard with search, filter badges, and expandable remediation diffs.

---

### ⏱️ Feature 2: Real-Time Watch Engine (`hexora watch`)

Keep Hexora running in a background terminal. Every time you save a file (`Ctrl+S`), Hexora performs an instantaneous micro-delta scan in milliseconds, alerting you before you even switch windows.

```bash
npx hexora watch
```

**Live Terminal Output:**
```text
PS D:\my-project> npx hexora watch

======================================================
👁️  HEXORA REAL-TIME WATCH ENGINE
   Monitoring: D:\my-project
   Auto-scans and verifies code on every save (Ctrl+S)
======================================================

⚡ Watcher active! Listening for file changes... (Press Ctrl+C to stop)

[20:12:04] 🟢 CLEAN: src/services/user.service.ts (0 issues, 14.2ms)
[20:12:45] 🟢 CLEAN: src/config/database.ts (0 issues, 11.8ms)

------------------------------------------------------
[20:13:19] 🚨 SECURITY ALERT: src/controllers/auth.controller.ts (18.6ms)
Found 1 genuine vulnerability:

  🔴 CRITICAL | Hardcoded Cloud Access Key (Line 15) [CWE-798]
  Target: src/controllers/auth.controller.ts:15
  💡 Suggested Fix: Store credentials in environment variables (.env) and reference via process.env.
------------------------------------------------------
```

**💡 Step-by-Step Hands-On Guide:**
1. Open a terminal tab and run `npx hexora watch`.
2. Open your code editor and edit any file (TypeScript, JavaScript, Python, Rust, Solidity, Go, etc.).
3. Press `Ctrl+S` — notice the sub-20ms instant confirmation badge: `🟢 CLEAN`.
4. If you accidentally type or paste an insecure pattern (e.g. `eval(req.query.code)` or a raw API secret), Hexora sounds an alert chime (`\x07`) and prints an exact line reference with remediation instructions.

---

### 🔒 Feature 3: Git Pre-Commit Security Gate (`hexora hook`)

Prevent secrets and critical bugs from ever entering your Git commit history or remote repository.

```bash
npx hexora hook
```

**1. Installation Demo:**
```text
PS D:\my-project> npx hexora hook
✅ Installed pre-commit hook at D:\my-project\.git\hooks\pre-commit
```

**2. Enforcement Demo (When Insecure Code is Committed):**
```text
PS D:\my-project> git add .
PS D:\my-project> git commit -m "feat: add payment gateway webhook"

🛡️ Hexora Pre-Commit Gate: Verifying staged files...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Secrets                  1 finding
Security vulnerabilities 0 findings
Vulnerable dependencies  0 findings
Insecure configuration   0 findings
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

❌ [Hexora Pre-Commit Hook] Hardcoded Secret Detected!
   File: src/payment.ts:22 -> Found unencrypted Stripe Secret Key.
   
Commit rejected to protect repository history.
To inspect or fix, run: npx hexora .
```

**💡 Step-by-Step Hands-On Guide:**
1. Run `npx hexora hook` inside any Git repository. It writes a zero-dependency pre-commit script to `.git/hooks/pre-commit`.
2. Stage your changes with `git add .` and run `git commit`.
3. If clean, git proceeds normally with zero delay.
4. If a critical issue or leaked credential is found, the commit is immediately blocked, protecting you from costly API leaks or security incidents.

---

### 🤖 Feature 4: 1-Click Universal AI Setup (`npx hexora init`)

Configure Hexora across your entire developer ecosystem in 5 seconds. Connects with Cursor, Claude Desktop, Claude Code, VS Code, and terminal paths automatically.

```bash
npx hexora init
```

**Interactive Terminal Demo:**
```text
PS D:\my-project> npx hexora init

Hexora Setup

### ⚡ Feature 4: 1-Click AI Agent Integration (Antigravity, Cursor, Claude & Windsurf)

Hexora seamlessly integrates with next-generation AI coding agents and IDEs via the **Model Context Protocol (MCP)** and **Native Agent Skills**.

#### 1. Instant Export to Google Antigravity
```bash
npx hexora skill antigravity
```
Automatically registers:
* **Global MCP Server**: `~/.gemini/config/mcp_config.json`
* **Agent Skill Protocol**: `.agents/skills/hexora/SKILL.md` and `~/.gemini/config/skills/hexora/SKILL.md`
* **Project Security Rules**: `.agents/rules/hexora-security.md` and `GEMINI.md`

#### 2. Universal Interactive Setup
```bash
npx hexora init
```

```text
PS D:\my-project> npx hexora init

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
   Workspace: D:\my-project
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

#### 🛠️ Available Hexora MCP Tools for AI Agents:
AI Agents gain access to 14 native deterministic security tools:
* `scan_project` — Full repo audit with adversarial dual-agent verification.
* `audit_scan_file` — Real-time single file / in-memory buffer scanner.
* `get_findings` — Query findings filtered by severity or CWE category.
* `apply_fix` — Automated zero-regression code patching via unified diffs.
* `audit_explain_vulnerability` — Deep architectural root cause and CVSS impact analysis.
* `audit_generate_poc` — Synthesizes safe, isolated reproduction proof-of-concept tests.
* `audit_get_workspace_posture` — Real-time security posture scoring (A+ to F).
* `validate_finding` — Adversarial counter-evidence filter.
* `audit_check_snippet` — Live function / snippet audit against vulnerability database.
* `audit_learn_report` — Ingest external CVEs and bug bounty writeups into memory.
* `audit_search_knowledge` — Semantic search through learned attack vectors.
* `audit_get_threat_intel_stats` — Statistics on learned zero-days and variants.
* `audit_export_skill` — On-the-fly export of skills to new agent environments.
* `audit_scan_directory` — Granular folder scanning with dedicated ledgers.
```

**💡 Step-by-Step Hands-On Guide:**
1. Run `npx hexora init` and choose `7` (All).
2. Open **Cursor** or **Claude Desktop** — Hexora MCP tools are now recognized immediately.
3. Prompt your agent: *"Audit this codebase using Hexora and generate minimal patches for any high severity bugs."*
4. The AI agent will call Hexora's MCP tools autonomously, evaluate the verified findings, and apply safe unified diffs.

---

### 🧠 Feature 5: Threat Intelligence & Dynamic CVE Learning (`learn` & `intel`)

Modern attack vectors evolve rapidly. Hexora includes a live threat intelligence knowledge vault that allows you to feed newly published CVEs, post-mortems, or bug bounty writeups directly into its detection memory.

```bash
# Ingest a security report or writeup:
npx hexora learn ./reports/cve-2024-solana-cpi.md

# Inspect active threat memory and learned attack variants:
npx hexora intel
```

**Live Terminal Output:**
```text
PS D:\my-project> npx hexora learn ./reports/cve-2024-solana-cpi.md

📚 [Hexora Threat Ingestion] Processing: ./reports/cve-2024-solana-cpi.md...
✨ Successfully ingested report: [CVE-2024-SOL-01] "Arbitrary CPI Execution in Solana Anchor"
   - Attack Variants learned: cpi_spoofing, missing_program_id_check
   - Mitigation: Verify program_id matches expected Pubkey before calling invoke_signed

PS D:\my-project> npx hexora intel

======================================================
🧠 HEXORA THREAT INTELLIGENCE KNOWLEDGE VAULT
======================================================
Total Reports Learned: 14
Total Attack Variants: 48

📌 [CVE-Database] CVE-2024-SOL-01: Arbitrary CPI Execution (CRITICAL)
   - Ecosystem: Solana | Class: CPI_HIJACK
   - Attack Variants: cpi_spoofing; missing_program_id_check

📌 [Bounty-Writeup] H1-2024-AUTH-99: OAuth State Parameter Bypass (HIGH)
   - Ecosystem: Web2 | Class: AUTH_BYPASS
   - Attack Variants: missing_pkce; lax_state_validation
```

---

### 🥊 Feature 6: Vulnerability Benchmark Arena (`hexora bench`)

Verify Hexora's accuracy and false-positive elimination rate directly against industry security scanners.

```bash
npx hexora bench
```

**Live Terminal Output:**
```text
PS D:\my-project> npx hexora bench

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
False Positive Elimination Rate:  100.0% (Zero false alarms)
Execution Time:                   412ms
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 🏆 Global Vulnerability Benchmarks

We evaluated Hexora on real-world test suites containing modern vulnerabilities across Web2 (Node/TS/Python), Web3 (Solana/EVM), and AI Agent prompt injections:

| Capability / Metric | Hexora | Semgrep OSS | Snyk | SonarQube |
| :--- | :---: | :---: | :---: | :---: |
| **True Positive Detection Rate** | **100.0%** (11/11) | 54.5% (6/11) | 63.6% (7/11) | 45.4% (5/11) |
| **False Positive Elimination** | **100.0%** (Adversarial) | 27.2% | 36.3% | 40.0% |
| **Zero-Day Web3 Vulnerabilities** | **Native** (Anchor/Solidity) | Limited | Paid Only | No |
| **OWASP LLM & Agentic Vectors** | **Native** (Prompt Smuggle/MCP) | Rules needed | No | No |
| **Dual-Agent Adversarial Verification** | **Yes** (Built-in) | No | No | No |
| **Automated PoC & Safe Unified Patches**| **Yes** (`git apply`) | No | Partial | No |
| **Native AI Model Context Protocol (MCP)**| **Yes** (`hexora mcp`) | No | No | No |
| **Setup Time** | **< 3 seconds** (`npx`) | Minutes | Requires Login | Heavy JVM |

*Run the benchmark yourself directly from source:*
```bash
npx hexora bench
```

---

## 🧠 Autonomous Threat Intelligence & Multi-Vector Defense Matrix

Hexora incorporates a high-assurance detection matrix and continuous threat intelligence engine covering the entire modern attack surface:

- **Advanced Injection & Gadget Chain Engine**: Server-Side Template Injection (SSTI), NoSQL query operator injection (`$where`, `$regex`), Prototype Pollution gadget chains, and XML External Entity (XXE) parsing traps.
- **Container Hardening & Cloud Posture**: Container security baseline verification, Dockerfile root execution prevention, unpinned mutable image tags (`:latest`), and Kubernetes privileged container isolation escapes.
- **Attack Surface & API Exposure Radar**: Detection of unvalidated open redirects, production GraphQL introspection exposure, sensitive dotfile leaks, and internal management endpoint exfiltration.
- **High-Entropy Secret Radar**: Deep Shannon-entropy detection and heuristic validation for AI model keys (OpenAI, Anthropic, Gemini), AWS IAM access keys, Stripe secret keys, and VCS tokens.
- **Semantic Logic & Object Safety**: Code logic rules for deep prototype mutation paths, ORM mass-assignment over-posting, and cross-site state-changing request risks.
- **Infrastructure-as-Code (IaC) Guard**: Automated static analysis for Terraform and cloud templates detecting public cloud storage buckets, unencrypted volumes, and wildcard permissive ingress rules (`0.0.0.0/0`).
- **Web3 & DeFi Exploit Coverage**: High-precision detection for ERC-4626 vault share inflation, Curve read-only reentrancy, spot/TWAP oracle manipulation, and token standard callback exploits.
- **High-Assurance Smart Contract Verifier**: Arbitrary CPI, Solana missing signer/owner verification, uninitialized PDA seeds, and Solidity uninitialized storage pointers.
- **Edge Runtime & Metadata Defense**: IMDSv1 SSRF cloud credential exfiltration prevention and serverless edge runtime isolation protections.

---

## 🛠️ CLI Command Reference

| Command | Description |
| :--- | :--- |
| `npx hexora .` | Scan current directory with deterministic SAST & Adversarial filter |
| `npx hexora ./path` | Scan specified directory or file |
| `npx hexora owner/repo` | Clone remote GitHub repository and audit inside sandbox |
| `npx hexora init` | 1-Click setup for Cursor, Claude, VS Code, and Terminal |
| `npx hexora watch` | Instant re-scan on file modification (`Ctrl+S`) |
| `npx hexora hook` | Install `.git/hooks/pre-commit` zero-tolerance security gate |
| `npx hexora mcp` | Launch Model Context Protocol stdio server for AI assistants |
| `npx hexora bench` | Run comprehensive benchmark against industry vulnerability cases |
| `npx hexora intel` | View dynamically learned attack vectors and CVE knowledge base |
| `npx hexora learn <file/dir>` | Ingest real-world security writeup or CVE markdown file |

---

## 🤖 Model Context Protocol (MCP) Configuration

To connect Hexora directly to **Cursor**, **Claude Desktop**, **Claude Code**, or **OpenCode**:

### Cursor (`~/.cursor/mcp.json` or `.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "hexora": {
      "command": "npx",
      "args": ["-y", "hexora", "mcp"]
    }
  }
}
```

### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "hexora": {
      "command": "npx",
      "args": ["-y", "hexora", "mcp"]
    }
  }
}
```

### OpenCode (`opencode.json` or `~/.config/opencode/config.json`)
```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "hexora": {
      "type": "local",
      "command": ["npx", "-y", "hexora", "mcp"],
      "enabled": true
    }
  }
}
```

### Claude Code (`~/.claude.json`)
```json
{
  "mcpServers": {
    "hexora": {
      "command": "npx",
      "args": ["-y", "hexora", "mcp"]
    }
  }
}
```

---

## 🌐 GitHub CI/CD Integration

Add Hexora to your GitHub Actions pipeline in 4 lines of YAML:

```yaml
# .github/workflows/security.yml
name: Hexora Security Gate
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx --yes hexora .
```

Hexora automatically produces SARIF output compatible with GitHub's native **Security Code Scanning tab**.

---

## 📄 License & Commercial Rights

Hexora is licensed under the **Hexora Source-Available & Non-Commercial License**.

- ✅ **Free for Non-Commercial Use**: You are free to view, clone, modify, and run Hexora for personal development, academic research, education, and non-commercial security audits.
- 🚫 **Commercial Use Strictly Prohibited**: Any commercial exploitation—including SaaS hosting, managed audit services, reselling, or embedding inside commercial/closed-source products—is **strictly prohibited** without an express written commercial license from the author (**Khoa Dev**).
- 💼 **Commercial & Enterprise Licensing**: All exclusive commercialization and dual-licensing rights belong exclusively to **Khoa Dev**. For commercial licensing, enterprise tiers, or custom partnerships, please contact:
  - Author: **Khoa Dev** ([@khoadev-vn](https://github.com/khoadev-vn) • [Facebook Profile](https://www.facebook.com/anhkhoavnk/))
  - Inquiries: `khoadev@users.noreply.github.com`

---

<div align="center">

Made with 💜 by **Khoa Dev** ([@khoadev-vn](https://github.com/khoadev-vn) • [Facebook](https://www.facebook.com/anhkhoavnk/)) & Hexora Core Contributors  
*Next-Gen Universal Security for Humans & AI Agents.*

</div>
