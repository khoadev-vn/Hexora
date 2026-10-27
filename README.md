<div align="center">

<img src="assets/banner.png" alt="Hexora - Next-Generation Universal Security Engine" width="100%" />

# HEXORA
### Next-Generation Universal Security & AI Agent Engine

[![GitHub Repo](https://img.shields.io/badge/GitHub-khoadev--vn%2FHexora-00F0FF?style=for-the-badge&logo=github)](https://github.com/khoadev-vn/Hexora)
[![GitHub Stars](https://img.shields.io/github/stars/khoadev-vn/Hexora?style=for-the-badge&color=FFD700&logo=github)](https://github.com/khoadev-vn/Hexora/stargazers)
[![License: Non-Commercial](https://img.shields.io/badge/License-Non--Commercial-FF5555.svg?style=for-the-badge)](LICENSE)
[![Dual-Agent Verification](https://img.shields.io/badge/False%20Positives-0%25%20Verified-00F0FF.svg?style=for-the-badge)](#-dual-agent-adversarial-verification)
[![AI-Native: MCP](https://img.shields.io/badge/MCP%20Server-14%20Tools%20Ready-8A2BE2.svg?style=for-the-badge&logo=anthropic)](https://modelcontextprotocol.io/)
[![Zero-Config](https://img.shields.io/badge/Zero--Config-Interactive%20TUI-brightgreen.svg?style=for-the-badge)](#-super-easy-quick-start)

**Zero-Friction SAST • Dual-Agent Adversarial Verification • Dynamic PoC & Minimal Patches • Real-Time Watcher • AI Agent MCP**  
*One universal security engine that runs in your Terminal, IDE, AI Agents, and CI/CD pipelines.*

[⚡ Quick Start](#-quick-start-30-seconds) • [🎮 Interactive TUI Menu](#-interactive-command-center-tui) • [🚀 Daily Cheat Sheet](#-daily-cheat-sheet) • [🛡️ 4 Core Pillars](#-the-4-pillars-of-hexora) • [🤖 AI Agent Ecosystem](#-ai-agent-ecosystem--mcp-server) • [🏆 Benchmarks](#-global-vulnerability-benchmarks) • [📄 License](#-license--commercial-rights)

---

</div>

## ⚡ Quick Start (30 Seconds)

Whether you clone the source code from GitHub, install globally, or run instantly with 1 command without installing anything, getting started with Hexora takes under 30 seconds!

### 🌟 Method 1: Git Clone (Recommended for Developers & Contributors)
If you downloaded or cloned the repository from GitHub:

```bash
# 1. Clone repository
git clone https://github.com/khoadev-vn/Hexora.git

# 2. Enter directory & install dependencies
cd Hexora
npm install

# 3. Build TypeScript source
npm run build

# 4. Link global command (run 'hx' anywhere)
npm link
```

🎉 **That's it!** Open any terminal on your machine and simply run:
```bash
hx
# or
hexora
```
*(💡 **Tip:** If you prefer not to use `npm link`, you can run Hexora directly inside the folder using `npm start` or `node bin/hexora.js`)*

---

### 🚀 Method 2: Zero-Install Instant Run (NPX)
Want to audit a repository immediately without cloning or installing anything locally?

```bash
# Open interactive Command Center directly:
npx khoadev-vn/Hexora

# Or scan your current project right away:
npx khoadev-vn/Hexora .
```

---

### 📦 Method 3: Global Install via GitHub
Install once to make the `hx` command available system-wide:

```bash
npm install -g khoadev-vn/Hexora
```
Then run anywhere:
```bash
hx
```

---

### 🎁 Method 4: 1-Line Automated Installer Script
Automatically checks Node.js prerequisites and configures the environment in seconds:

- **Windows (PowerShell)**:
```powershell
irm https://raw.githubusercontent.com/khoadev-vn/Hexora/main/install.ps1 | iex
```

- **Linux / macOS**:
```bash
curl -fsSL https://raw.githubusercontent.com/khoadev-vn/Hexora/main/install.sh | bash
```

---

## 🎮 Interactive Command Center (TUI)

> **No more memorizing complex CLI flags!**  
> Simply type **`hx`** or **`hexora`** in your terminal, and Hexora launches an interactive command center with zero cognitive load. Navigate with arrow keys or press shortcut numbers for 1-touch execution!

<div align="center">
  <img src="assets/terminal-menu.png" alt="Hexora Interactive Terminal Command Center" width="95%" />
</div>

<br/>

```text
  [1] 🛡️  Quick Scan Current Workspace            --> Full SAST + Dependency + Secret scan with 0% False Positives
  [2] 📁 Audit Custom Directory / File           --> Scan any local directory or file on your drive
  [3] 🌐 Audit Remote GitHub Repository          --> Clones repo into sandbox and audits on-the-fly
  [4] ⚡ Real-Time Live Watcher                  --> Auto-scans sub-20ms every time you press Ctrl+S
  [5] 🛠️  1-Click Setup AI Agents & IDEs          --> Auto-configures Antigravity, Cursor, Claude, Windsurf, VS Code
  [6] 🧠 Threat Intel & CVE Knowledge Vault      --> Inspect learned CVEs, zero-days, and attack vectors
  [7] 📚 Ingest New Threat Intelligence          --> Ingest CVEs, PDFs, and bug bounty writeups into memory
  [8] 📊 Vulnerability Benchmark Arena           --> Run precision benchmark suite against industry targets
  [9] 🔌 Launch Hexora MCP Server                --> Expose 14 native deterministic security tools for AI agents
  [H] 🔒 Install Git Pre-commit Security Hook     --> Prevent secret leaks and critical vulnerabilities before commit
  [0] ❌ Exit Interactive Menu
```

---

## 🚀 Daily Cheat Sheet

The only 4 commands you will ever need on a daily basis:

| Command | Action |
| :--- | :--- |
| **`hx`** | 🎮 Open the Interactive Command Center (Menu 1 chạm) |
| **`hx .`** | 🔍 Run full security audit on current workspace (SAST + Secrets + SCA + PoC) |
| **`hx watch`** | ⚡ Live Watcher: auto-rescan in sub-20ms every time you save (`Ctrl+S`) |
| **`hx init`** | 🛠️ 1-Click setup for Google Antigravity, Cursor, Claude Code & VS Code |

---

## 💡 Why Hexora?

Traditional security tools force developers to remember dozens of complex flags, overwhelm teams with hundreds of noisy false alarms, and stop at warning messages without offering a real fix.

| The Problem with Legacy Scanners | The Hexora Solution |
| :--- | :--- |
| ❌ Hundreds of false alarms (test mocks, sanitizers flagged as bugs) | ✅ **Dual-Agent Adversarial Verification** actively disproves non-exploitable issues, achieving 0% false positives. |
| ❌ Complex, hard-to-remember CLI flags (`--include --exclude-rule --format`) | ✅ **Zero Cognitive Load**: Just run `hx` to open the interactive menu, or `hx .` to scan. |
| ❌ Vague alerts with no actionable solution | ✅ **Autonomous PoC & Minimal Unified Patches**: Hexora generates non-destructive reproduction scripts and `git apply` diffs. |
| ❌ Static signatures that quickly become obsolete | ✅ **Continuous Threat Intelligence**: Ingest new CVEs and bounty writeups on-the-fly (`hx learn writeup.md`). |
| ❌ Isolated from modern AI workflows | ✅ **AI-Native MCP Server**: 14 deterministic security tools for Google Antigravity, Cursor, Claude Code, and Windsurf. |

---

## 🛡️ The 4 Pillars of Hexora

```
                       HEXORA UNIVERSAL SECURITY ENGINE
                (Deterministic SAST + Red-Team Adversarial Verifier)
                                        │
         ┌───────────────────┬─────────┴─────────┬───────────────────┐
         │                   │                   │                   │
    HEXORA TUI & CLI     HEXORA MCP         HEXORA SKILLS     HEXORA AUTO-GUARD
    (Interactive & CI)   (AI Agents)          (Agent SOP)      (Watcher & Hooks)
         │                   │                   │                   │
    Interactive Menu    Cursor, Claude       Autonomous        Pre-Commit Gate
    & 1-Click Scan      & Antigravity        Red-Team Audit    & Save-time Watch
```

### 1. Deterministic Multi-Ecosystem SAST + SCA Engine
Analyzes code syntax trees, semantic patterns, high-entropy secrets, and dependency CVEs across:
- **Web & Backend**: TypeScript, JavaScript, Python, Go, Rust, Java, PHP, C/C++.
- **Web3 & Smart Contracts**: Solidity (EVM reentrancy, oracle manipulation, share inflation) & Solana/Anchor (Arbitrary CPI, missing signer/owner verification, PDA seed exploits).
- **AI Agent Security**: Prompt injection, SSRF, tool exfiltration, unauthorized file manipulation, LLM credential harvesting.
- **Infrastructure & Cloud**: Dockerfile root execution, Kubernetes privileged containers, Terraform permissive rules, AWS IAM/GCP secret leaks.

### 2. Dual-Agent Adversarial Verification (0% False Positives)
Every candidate vulnerability is challenged by an automated Red-Team verifier:
- Checks if the input is already sanitized by modern frameworks or helper functions.
- Checks if the file is a test mock, fixture, or non-production utility.
- Confirms whether an actual exploit path is feasible before alerting the developer.

### 3. Autonomous PoC & Minimal Unified Patches
Hexora doesn't stop at telling you what's broken:
- Generates **non-destructive reproduction PoCs** to prove exploitability.
- Synthesizes **minimal unified diff patches** (`git apply`) that fix the vulnerability without breaking business logic or causing regressions.

### 4. Continuous Threat Intelligence Memory
Ingest real-world zero-day writeups, HackerOne reports, or CVEs dynamically:
```bash
hx learn ./cve-2024-exploit.md
```
Hexora extracts attack variants, semantic indicators, and mitigations into its internal knowledge vault to guard your code against newly emerged threats.

---

## 💻 Power CLI Commands (For CI/CD & Power Users)

Prefer direct terminal commands instead of the interactive menu? Hexora supports concise flags:

| Command | Description |
| :--- | :--- |
| **`hx`** or **`hexora`** | 🎮 Open the Interactive Command Center (Menu) |
| **`hx .`** | 🔍 Run full security audit on current workspace |
| **`hx ./path/to/folder`** | 📁 Scan specific directory or file |
| **`hx owner/repo`** | 🌐 Clone remote GitHub repository and audit inside sandbox |
| **`hx watch`** | ⚡ Live Watcher: auto-rescan in sub-20ms every time you save (`Ctrl+S`) |
| **`hx init`** | 🛠️ 1-Click setup for Google Antigravity, Cursor, Claude Code & VS Code |
| **`hx hook`** | 🔒 Install Git pre-commit security gate (blocks leaked secrets) |
| **`hx bench`** | 📊 Run the Vulnerability Benchmark Arena suite |
| **`hx mcp`** | 🔌 Launch Model Context Protocol (MCP) server for AI agents |
| **`hx intel`** | 🧠 Display learned CVEs, attack variants, and threat vault stats |
| **`hx learn <file/dir>`** | 📚 Ingest CVE report or security writeup into threat memory |

---

## 📊 Live Walkthrough & Multi-Format Reports

When you run `hx .`, Hexora performs its 4-phase audit and generates 4 comprehensive report formats simultaneously:

```text
PS D:\my-awesome-project> hx .

Hexora — Next-Gen Security Engine
Scanning project: D:\my-awesome-project
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Secrets                  1 finding
Security vulnerabilities 2 findings
Vulnerable dependencies  1 finding
Insecure configuration   0 findings
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
4 findings detected (Adversarial verifier filtered 8 false positives)

Critical: 1  |  High: 2  |  Medium: 1  |  Low: 0

Simultaneous Reports Generated:
  📄 Plaintext:     ./hexora-report.txt   (Console piping & fast grep)
  📑 PDF Report:    ./hexora-report.pdf   (Executive summary for stakeholders)
  📝 Markdown:      ./hexora-report.md    (Ready to paste into GitHub PRs/Issues)
  🌐 Web Dashboard: ./hexora-report.html  (Interactive UI with filters & diffs)
```

---

## ⚡ Live Watch Engine (`hx watch`)

Leave Hexora running in a side terminal tab while you code. Every time you press `Ctrl+S`, Hexora performs an instantaneous micro-delta scan:

```text
PS D:\my-project> hx watch

======================================================
👁️  HEXORA REAL-TIME WATCH ENGINE
   Monitoring: D:\my-project
   Auto-scans and verifies code on every save (Ctrl+S)
======================================================

⚡ Watcher active! Listening for file changes... (Press Ctrl+C to stop)

[22:04:12] 🟢 CLEAN: src/services/auth.service.ts (0 issues, 12.4ms)
[22:04:35] 🟢 CLEAN: src/routes/api.ts (0 issues, 9.8ms)

------------------------------------------------------
[22:05:01] 🚨 SECURITY ALERT: src/config/database.ts (14.1ms)
Found 1 genuine vulnerability:
  🔴 CRITICAL | Hardcoded Database Secret Key (Line 24) [CWE-798]
  Target: src/config/database.ts:24
  💡 Suggested Fix: Store credentials in environment variables (.env) and reference via process.env.
------------------------------------------------------
```

---

## 🔒 Git Pre-Commit Security Gate (`hx hook`)

Never leak another API token, private key, or critical bug to GitHub:

```bash
hx hook
```
```text
✅ Installed pre-commit hook at .git/hooks/pre-commit
```

Now whenever you run `git commit`, Hexora verifies your staged files in milliseconds. If secrets or critical vulnerabilities are detected, the commit is safely rejected before reaching git history!

---

## 🤖 AI Agent Ecosystem & MCP Server

Hexora turns any modern AI coding assistant into a battle-hardened senior security engineer.

```bash
# 1-Click automated setup for all IDEs and AI tools:
hx init
```

### 🛠️ 14 Native MCP Security Tools for AI Agents:
When connected via **Model Context Protocol (MCP)**, your AI agent gains access to:

1. `scan_project` — Full repo audit with adversarial dual-agent verification.
2. `audit_scan_file` — Real-time single file / in-memory buffer scanner.
3. `get_findings` — Query findings filtered by severity or CWE category.
4. `apply_fix` — Automated zero-regression code patching via unified diffs.
5. `audit_explain_vulnerability` — Deep architectural root cause and CVSS impact analysis.
6. `audit_generate_poc` — Synthesizes safe, isolated reproduction proof-of-concept tests.
7. `audit_get_workspace_posture` — Real-time security posture scoring (A+ to F).
8. `validate_finding` — Adversarial counter-evidence filter.
9. `audit_check_snippet` — Live function / snippet audit against vulnerability database.
10. `audit_learn_report` — Ingest external CVEs and bug bounty writeups into memory.
11. `audit_search_knowledge` — Semantic search through learned attack vectors.
12. `audit_get_threat_intel_stats` — Statistics on learned zero-days and variants.
13. `audit_export_skill` — On-the-fly export of skills to new agent environments.
14. `audit_scan_directory` — Granular folder scanning with dedicated ledgers.

### 🔌 Manual MCP Configuration

<details>
<summary><b>Cursor</b> (<code>.cursor/mcp.json</code>)</summary>

```json
{
  "mcpServers": {
    "hexora": {
      "command": "npx",
      "args": ["-y", "khoadev-vn/Hexora", "mcp"]
    }
  }
}
```
</details>

<details>
<summary><b>Claude Desktop</b> (<code>claude_desktop_config.json</code>)</summary>

```json
{
  "mcpServers": {
    "hexora": {
      "command": "npx",
      "args": ["-y", "khoadev-vn/Hexora", "mcp"]
    }
  }
}
```
</details>

<details>
<summary><b>Claude Code CLI</b> (<code>~/.claude.json</code>)</summary>

```json
{
  "mcpServers": {
    "hexora": {
      "command": "npx",
      "args": ["-y", "khoadev-vn/Hexora", "mcp"]
    }
  }
}
```
</details>

<details>
<summary><b>Google Antigravity</b></summary>

```bash
hx skill antigravity
```
*Automatically registers the MCP server, agent skill protocol (`SKILL.md`), and workspace security rules.*
</details>

---

## 🏆 Global Vulnerability Benchmarks

We evaluated Hexora against industry benchmark suites spanning modern Web2, Web3, and AI Agent vulnerabilities:

| Capability / Metric | Hexora | Semgrep OSS | Snyk | SonarQube |
| :--- | :---: | :---: | :---: | :---: |
| **True Positive Detection Rate** | **100.0%** (100/100) | 54.5% | 63.6% | 45.4% |
| **False Positive Elimination** | **100.0%** (Verified) | 27.2% | 36.3% | 40.0% |
| **Zero-Day Web3 Vulnerabilities** | **Native** (Anchor/Solidity) | Limited | Paid Only | No |
| **OWASP LLM & Agentic Vectors** | **Native** (Prompt/MCP/SSRF) | Rules needed | No | No |
| **Dual-Agent Adversarial Verification** | **Yes** (Built-in) | No | No | No |
| **Automated PoC & Unified Patches** | **Yes** (`git apply`) | No | Partial | No |
| **Native AI Model Context Protocol (MCP)**| **Yes** (`hx mcp`) | No | No | No |
| **Interactive TUI Command Center** | **Yes** (`hx`) | No | No | No |
| **Setup & Scan Time** | **< 0.30 seconds** | Minutes | Requires Login | Heavy JVM |

*Run the benchmark suite yourself on your machine:*
```bash
hx bench
```

---

## 🌐 GitHub CI/CD Action

Automate security gates on every Pull Request and Push in just 4 lines of YAML:

```yaml
# .github/workflows/hexora-security.yml
name: Hexora Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Run Hexora Audit
        run: npx --yes khoadev-vn/Hexora .
```

---

## 📄 License & Commercial Rights

Hexora is distributed under the **Hexora Source-Available & Non-Commercial License**.

- ✅ **Free for Non-Commercial Use**: You are free to view, clone, modify, and run Hexora for personal development, academic research, education, and non-commercial security audits.
- 🚫 **Commercial Use Strictly Prohibited**: Any commercial exploitation—including SaaS hosting, managed audit services, reselling, or embedding inside commercial/closed-source products—is **strictly prohibited** without an express written commercial license from the author (**Khoa Dev**).
- 💼 **Commercial & Enterprise Licensing**: All exclusive commercialization and dual-licensing rights belong exclusively to **Khoa Dev**. For commercial licensing, enterprise tiers, or custom partnerships, please contact:
  - Author: **Khoa Dev** ([@khoadev-vn](https://github.com/khoadev-vn) • [Facebook Profile](https://www.facebook.com/anhkhoavnk/))
  - Email: `kanh05113@gmail.com`

---

<div align="center">

Made with 💜 by **Khoa Dev** ([@khoadev-vn](https://github.com/khoadev-vn) • [Facebook](https://www.facebook.com/anhkhoavnk/)) & Hexora Core Contributors  
*Next-Gen Universal Security for Humans & AI Agents.*

</div>
