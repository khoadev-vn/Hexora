<div align="center">

# 🛡️ HEXORA
### Next-Generation Universal Security Engine

[![npm version](https://img.shields.io/npm/v/hexora.svg?style=flat-square&color=00F0FF&logo=npm)](https://www.npmjs.com/package/hexora)
[![License: Non-Commercial](https://img.shields.io/badge/License-Non--Commercial-FF5555.svg?style=flat-square)](LICENSE)
[![AI-Native: MCP](https://img.shields.io/badge/AI--Native-Model%20Context%20Protocol-8A2BE2.svg?style=flat-square&logo=anthropic)](https://modelcontextprotocol.io/)
[![Zero-Config](https://img.shields.io/badge/Setup-Zero--Config-brightgreen.svg?style=flat-square)](#-quickstart-for-developers)
[![False Positive Filter](https://img.shields.io/badge/False%20Positives-0%25%20Filtered-success.svg?style=flat-square)](#-dual-agent-adversarial-verification)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-blue.svg?style=flat-square)](CONTRIBUTING.md)

**Zero-Friction SAST • Dual-Agent Adversarial Verification • Dynamic PoC & Patch Generation**  
*One security engine that works seamlessly in your Terminal, IDE, AI Agents, and CI/CD pipelines.*

[🌐 Live Landing Page](https://hexora-security.github.io/hexora) • [📖 Documentation](#-universal-modes-of-use) • [⚡ Quickstart](#-quickstart-for-developers) • [🤖 AI Agent MCP](#-mode-2-1-click-ai-agent-setup) • [🏆 Benchmarks](#-global-vulnerability-benchmarks)

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

## 🚀 Quickstart for Developers

### 🖥️ Mode 1: Terminal CLI (Zero-Config)
Run Hexora directly across your projects:

```bash
# Scan current directory:
hexora .

# Scan any target project:
hexora ./path-to-project

# Scan any remote GitHub repository in an isolated sandbox:
hexora owner/repo
```

**Clean, Actionable Output:**
```text
Hexora

Scanning project...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Secrets                  2 findings
Security vulnerabilities 3 findings
Insecure configuration   1 finding
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
6 findings confirmed (12 false positives eliminated by Adversarial Verifier)

Critical: 1  |  High: 2  |  Medium: 2  |  Low: 1

Report: ./hexora-report.html  (Interactive HTML & SARIF generated)
```

---

### 🤖 Mode 2: 1-Click AI Agent Setup (`npx hexora init`)
Tired of manually configuring JSON files for Cursor, Claude, or Windsurf? Just run:

```bash
npx hexora init
```

Hexora automatically detects and configures:
- ✅ **Cursor MCP** (`.cursor/mcp.json`)
- ✅ **Claude Desktop** (`claude_desktop_config.json`)
- ✅ **Claude Code & Agentic IDEs**
- ✅ **VS Code Tasks & Pre-commit Git Hooks**

Once configured, simply instruct your AI Assistant:
> *"Audit this project with Hexora and automatically apply the recommended patches."*

---

### ⏱️ Mode 3: Live Auto-Scan on Save (`watch`)
Keep Hexora running in the background. Every time you hit `Ctrl+S`, Hexora performs an instant micro-delta scan in milliseconds:

```bash
npx hexora watch
```

---

### 🔒 Mode 4: Git Pre-Commit Security Gate
Block leaked API keys and critical vulnerabilities before they ever enter Git history:

```bash
npx hexora hook
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

To connect Hexora directly to **Cursor** or **Claude Desktop**:

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
  - Author: **Khoa Dev** ([@khoadev-vn](https://github.com/khoadev-vn))
  - Inquiries: `khoadev@users.noreply.github.com`

---

<div align="center">

Made with 💜 by **Khoa Dev** ([@khoadev-vn](https://github.com/khoadev-vn)) & Hexora Core Contributors  
*Next-Gen Universal Security for Humans & AI Agents.*

</div>
