---
name: hexora-security
description: >-
  Universal Security Audit & Adversarial Verification Protocol for Antigravity AI Agents, Cursor, and Claude Code. Use when the user asks to scan repositories, audit code for vulnerabilities or leaked secrets, check CVE reports, inspect smart contracts (EVM / Solana), perform SCA on dependencies, or auto-remediate security bugs with verified unified diff patches.
---

# Hexora: Universal Security Audit & Threat Intelligence Protocol

Hexora combines deterministic SAST, dynamic Threat Intelligence & CVE report cross-matching, dual-agent adversarial verification, dynamic PoC generation, and automated diff remediation across Web2, Web3, Cloud, and AI Agent systems.

## Core Capabilities

1. **Deterministic Multi-Language SAST Engine**:
   - Covers **OWASP Top 10**, **CWE Top 25**, **SANS Top 25**, **SWC Registry**, and **OWASP LLM Top 10**.
   - Languages supported: TypeScript, JavaScript, Python, Rust (Solana Anchor), Solidity (EVM), Go, JSON, YAML, Dockerfile.
2. **Comprehensive Multi-Vector Threat Intelligence Engine**:
   - Exploit & Injection Defense: SSTI, NoSQL injection, Prototype Pollution gadget chains, XXE, Cloud IMDSv1 SSRF.
   - High-Entropy Secret Radar: Shannon-entropy detection for GitHub PATs, AWS Access Keys, OpenAI/Anthropic/Gemini keys, Stripe keys, Slack tokens.
   - Web3 & DeFi Exploit Coverage: ERC-4626 inflation, Solana missing owner/signer checks, arbitrary CPI, flash loan oracle traps.
   - AI Agent Defense: Prompt injection, indirect hidden markdown exfiltration, insecure tool invocations.
3. **Dual-Agent Adversarial Red-Team Falsifier**:
   - Actively challenges candidate findings to disprove test fixtures and mocks.
   - Calculates confidence (0.0 to 1.0) and filters false positives before final reporting.
4. **Autonomous AI Remediation & Patch Engine**:
   - Minimal git-ready unified diffs or safe direct code replacements.
   - Re-scans modified files automatically to ensure zero regressions.
5. **Universal IDE & Agent Integration**:
   - Native MCP Server (`hexora mcp`) with full support for Google Antigravity, Cursor, Claude Code, Windsurf, and VS Code.

---

## MCP Server Tools Reference

When running in an MCP-compatible IDE or Agent environment (Google Antigravity, Cursor, Claude Code, Windsurf, VS Code):

| Tool Name | Purpose | Key Parameters |
| :--- | :--- | :--- |
| `scan_project` | Scan repository, generate reports (PDF/HTML/SARIF/MD/TXT), return metrics | `targetPath` |
| `audit_scan_file` | Fast, real-time security audit on an active file or in-memory code buffer | `filePath`, `content` |
| `get_findings` | Query structured findings filtered by severity or category | `severity`, `category`, `targetPath` |
| `apply_fix` | Safely apply automated patch or code replacement to fix confirmed issues | `filePath`, `target`, `replacement`, `unifiedDiff` |
| `audit_explain_vulnerability` | Deep architectural root cause & CVSS breakdown of an issue | `ruleId`, `findingJson` |
| `audit_generate_poc` | Synthesize safe, executable reproduction PoC test scripts | `findingJson`, `format` |
| `audit_get_workspace_posture` | Real-time workspace security grade (A+ to F) & stats | `targetPath` |
| `validate_finding` | Adversarially challenge a candidate finding & synthesize safe PoC | `findingJson` |
| `audit_check_snippet` | Live-audit a code snippet or function against rules & threat reports | `code`, `filePath`, `category` |
| `audit_learn_report` | Feed and memorize a new security report, CVE, or incident writeup | `title`, `contentOrPath`, `source` |
| `audit_search_knowledge` | Search learned threat reports and known exploit techniques | `query` |
| `audit_get_threat_intel_stats` | Inspect knowledge base metrics and cataloged attack variants | *(none)* |
| `audit_export_skill` | Export Hexora skill and rules to Antigravity, Cursor, Claude, Windsurf | `platform`, `workspaceDir` |

---

## The 7-Step Autonomous AI Agent Workflow

When instructed to audit or fix security issues in a project, the AI Agent must follow this deterministic, safe workflow:

1. **Reconnaissance & Workspace Posture**:
   - Check `audit_get_workspace_posture()` to review historical findings and overall security grade.
2. **Execute Scan via MCP**:
   - For repository: Call `scan_project({ targetPath: "." })`.
   - For targeted file: Call `audit_scan_file({ filePath: "src/..." })`.
3. **Parse Report & Findings**:
   - Query `get_findings` to retrieve confirmed vulnerabilities, attack surfaces, and correlated CVEs.
4. **Verify Findings & Filter False Positives**:
   - If a finding is inside mock/test data or mitigated by a reverse-proxy/WAF, use `validate_finding` to formally invalidate it.
5. **Architectural Explanation**:
   - Call `audit_explain_vulnerability({ ruleId })` to understand root cause and safe coding pattern.
6. **Synthesize Safe PoC**:
   - Call `audit_generate_poc({ findingJson, format: "AUTO" })` to test reproduction safely.
7. **Propose & Apply Remediation**:
   - Call `apply_fix({ filePath, target, replacement })` to apply the fix, followed by `audit_scan_file` to confirm eradication.

---

## CLI Quick Reference

```bash
# 1. Zero-config scan current directory
npx hexora .
audit

# 2. 1-Click Setup for Antigravity, Cursor, Claude Code, Windsurf & VS Code
npx hexora init
# Or install Antigravity skill directly:
npx hexora skill antigravity

# 3. Continuous Watcher (Auto-rescan on file save)
npx hexora watch

# 4. Start MCP Server directly
npx hexora mcp

# 5. Git Pre-Commit Security Gate
npx hexora hook
```
