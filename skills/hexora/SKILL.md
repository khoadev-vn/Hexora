---
name: hexora-security-audit
description: Hexora Universal Security Audit Protocol combining deterministic SAST, dynamic Threat Intelligence & CVE report cross-matching, dual-agent adversarial verification, dynamic PoC generation, and automated diff remediation across Web2, Web3, Cloud, and AI Agent systems.
---

# Hexora: Next-Gen Universal Security Engine & Threat Intelligence Protocol

Audit any codebase against real-world CVEs, bug bounty reports (Immunefi, Code4rena, Sherlock, Cloudflare Research, OpenZeppelin, Trail of Bits), and exploit attack variants. Features an autonomous Red-Team adversarial verifier that eliminates false positives, synthesizes safe reproduction PoCs, and generates minimal unified patches.

## Core Capabilities

1. **Deterministic Multi-Language SAST Engine**:
   - Ultra-fast regex & AST-grade rule database covering **OWASP Top 10**, **CWE Top 25**, **SANS Top 25**, **SWC Registry**, and **OWASP LLM Top 10**.
   - Languages supported: TypeScript, JavaScript, Python, Rust (Solana Anchor), Solidity (EVM), Go, JSON, YAML, Dockerfile.
2. **Comprehensive Multi-Vector Threat Intelligence Engine**:
   - **Exploit & Injection Defense**: Advanced coverage for Server-Side Template Injection (SSTI), NoSQL query operator injection, Prototype Pollution gadget chains, and XML External Entity (XXE) parsing traps.
   - **Container & IaC Posture**: Container hardening, unpinned `:latest` tags, Dockerfile root executions, and Kubernetes privileged pod escapes.
   - **API & Attack Surface Discovery**: Rapid detection for open redirects, GraphQL introspection in production, Spring Boot Actuator heapdumps, and sensitive dotfile exposures.
   - **High-Entropy Secret Radar**: Deep Shannon-entropy analysis for GitHub PATs, AWS Access Keys, Stripe keys, Slack tokens, and AI provider credentials (OpenAI, Anthropic, Gemini).
   - **Semantic Logic & Object Safety**: Code logic verification covering prototype pollution merges, ORM mass assignment, and CSRF misconfigurations.
   - **Infrastructure-as-Code (IaC) Guard**: Infrastructure checks for public AWS S3 buckets, permissive security groups (0.0.0.0/0 on SSH/RDP), and unencrypted cloud storage volumes.
   - **Web3 & DeFi Exploit Coverage**: Real-world DeFi attack patterns including ERC-4626 vault share inflation, Mango Markets oracle manipulation, and CDN supply chain compromises.
   - **Static Security Auditing**: Python security auditing for dangerous `subprocess(shell=True)` and broken MD5/SHA-1 cryptographic hashing.
   - **Smart Contract Verification**: Smart contract analysis for ERC-777 hook reentrancy, dangerous `block.timestamp` manipulation, and uninitialized storage pointers.
   - **Edge Runtime & Metadata Defense**: Multi-phase reconnaissance, coverage ledger (`audit-coverage.json`), adversarial verifier, network profiling, TLS evaluation, and Workers edge environment runtime protections.
3. **Dynamic Threat Intelligence & Exploit Variant Memory**:
   - Out-of-the-box verified incident reports:
     - **Cloudflare Research**: REP-CF-AI-001 (Indirect Prompt Injection & Hidden Markdown), REP-CF-FLAN-001 (Port Exposure), REP-CF-WORKERS-001 (Edge Subrequest SSRF & Env Leakage), REP-CLOUDFLARE-METADATA (Cloud IMDSv1 SSRF Theft).
     - **Web3 EVM**: Nomad Bridge $190M (Uninitialized Root), Euler Finance $197M (donateToReserves Insolvent Liquidation), Curve Read-Only Reentrancy, KyberSwap Elastic $54M (Tick Rounding Math).
     - **Web3 Solana**: Wormhole $320M (InstructionsSysvar Introspection Bypass), Cashio $52M (Unvalidated Collateral Bank & Mint), Missing Signer / Owner checks, Arbitrary CPI, PDA bump canonicalization.
     - **AI Agent & LLM**: OWASP LLM01 Prompt Injection & Comment Smuggling, OWASP LLM02 Insecure MCP Tool Execution, CVE-2023-39659 LangChain REPL RCE, PyTorch Unsafe Checkpoint Deserialization.
     - **Web2 & Cloud**: CVE-2024-34351 Next.js Server Actions SSRF, CVE-2021-44228 Log4j Nested JNDI RCE, Prototype Pollution RCE Gadgets, IMDSv1 Cloud Credential Theft, Docker Socket Escapes.
   - Continuous Learning: Ingest and memorize any CVE or Bug Bounty writeup on-the-fly via CLI (`hexora learn <path>`) or MCP (`audit_learn_report`).
4. **Dual-Agent Adversarial Red-Team Falsifier**:
   - Actively challenges every candidate finding to disprove test fixtures, mocks, and framework mitigations.
   - Calculates verdict confidence (0.0 to 1.0) and filters false positives before final reporting.
5. **Automated PoC & Minimal Unified Patch Synthesis**:
   - Non-destructive, safe curl commands, Foundry test skeletons, or local mock fixtures.
   - Minimal git-ready unified diff patches (`git apply`).
6. **Universal IDE & MCP Integration**:
   - MCP Server (`hexora mcp`) providing native tools for AI Agents in Antigravity, VS Code, Cursor, and Windsurf.

---

## The 7-Step Autonomous AI Agent Workflow

When instructed to audit or fix security issues in a project, the AI Agent must follow this deterministic, safe workflow:

1. **Identify Project Target Directory**:
   - Determine workspace root or target module folder.
2. **Execute Scan via MCP**:
   - Call `scan_project` (or `npx hexora .` / `audit`).
3. **Parse Report & Coverage Ledger**:
   - Query `get_findings` to retrieve confirmed vulnerabilities, attack surfaces, and correlated CVEs.
4. **Verify Critical & High Findings**:
   - Review code location and context for each confirmed finding.
5. **Classify False Positives & Test Fixtures**:
   - If a finding is inside mock/test data or mitigated by a reverse-proxy/WAF, use `validate_finding` to formally invalidate it.
6. **Propose Minimal, Actionable Fixes**:
   - Present the developer with safe explanations and git-ready unified diffs. *Never apply dangerous changes without permission!*
7. **Re-Scan to Validate Remediation**:
   - Run `scan_project` again to guarantee zero regressions and verify the vulnerability is eradicated.

---

## Architectural Separation of Concerns

```
                  HEXORA ENGINE (Core SAST + Adversarial Verifier)
                                  |
            +---------------------+---------------------+
            |                     |                     |
           CLI                   MCP                 SDK/API
        (Terminal)           (AI Agents)          (Applications)
                                  |
                           +------+------+
                           |             |
                         Skills         IDEs
                           |
                     AI-Assisted
                      Workflow
```

- **Skill**: Standard Operating Procedure (SOP) guiding AI Agents on how, when, and why to audit.
- **MCP**: Communication protocol letting AI Agents invoke security tools with structured JSON.
- **CLI**: Zero-config terminal interface for humans and CI/CD pipelines (`npx hexora .`).
- **Engine**: The core brain performing multi-language parsing, threat correlation, and adversarial verification.

---

## MCP Server Tools Reference

When running in an MCP-compatible IDE or Agent environment (Cursor, Claude Code, Antigravity, VS Code):

| Tool Name | Purpose | Key Parameters |
| :--- | :--- | :--- |
| `scan_project` | Scan repository, generate HTML/SARIF/Markdown reports, return metrics | `targetPath` |
| `get_findings` | Query structured findings filtered by severity or category | `severity`, `category`, `targetPath` |
| `validate_finding` | Adversarially challenge a candidate finding & synthesize safe PoC | `findingJson` |
| `audit_check_snippet` | Live-audit a code snippet or function against rules & threat reports | `code`, `filePath`, `category` |
| `audit_learn_report` | Feed and memorize a new security report, CVE, or incident writeup | `title`, `contentOrPath`, `source`, `attackVariants` |
| `audit_search_knowledge` | Search learned threat reports and known exploit techniques | `query` |
| `audit_get_threat_intel_stats` | Inspect knowledge base metrics and cataloged attack variants | *(none)* |

---

## Zero-Config CLI Usage

```bash
# 1. Zero-config scan current directory
npx hexora .
# Or short global command:
audit

# 2. Scan a specific project folder
npx hexora ./my-project

# 3. Scan a remote GitHub repository directly
npx hexora owner/repo

# 4. 1-Click Interactive Setup for Cursor, Claude, VS Code & Terminal
npx hexora init

# 5. Continuous Watcher (Auto-rescan on file save)
npx hexora watch
```
