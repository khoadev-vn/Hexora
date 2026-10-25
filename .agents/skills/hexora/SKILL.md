---
name: hexora-security
description: >-
  Universal Security Audit & Adversarial Verification Protocol for Antigravity AI Agents. Use when the user asks to scan repositories, audit code for vulnerabilities or leaked secrets, check CVE reports, inspect smart contracts (EVM / Solana), perform SCA on dependencies, or auto-remediate security bugs with verified unified diff patches.
---

# Hexora: Universal Security Audit & Zero-Day Defense Engine

Hexora is an enterprise-grade security audit engine natively integrated into Antigravity via MCP tools and autonomous workflows. It provides deterministic multi-language SAST, CVE cross-matching, continuous threat intelligence, and a dual-agent adversarial verifier that eliminates false positives.

## Available Hexora MCP Tools

Antigravity Agents should use Hexora's MCP tools for all security tasks:

| MCP Tool | Purpose | Key Inputs |
| :--- | :--- | :--- |
| `scan_project` | Complete repository scan with full adversarial verification | `targetPath` |
| `audit_scan_file` | Fast single-file or in-memory code scan on edit/save | `filePath`, `content` |
| `get_findings` | Retrieve verified findings filtered by severity or category | `severity`, `category` |
| `apply_fix` | Safely apply automated patch or replacement to source code | `filePath`, `target`, `replacement`, `unifiedDiff` |
| `audit_explain_vulnerability` | Deep architectural root cause & CVSS breakdown of an issue | `ruleId`, `findingJson` |
| `audit_generate_poc` | Synthesize safe, executable reproduction PoC test scripts | `findingJson`, `format` |
| `audit_get_workspace_posture` | Real-time workspace security grade (A+ to F) & stats | `targetPath` |
| `validate_finding` | Challenge candidate finding to filter false positives | `findingJson` |
| `audit_check_snippet` | Live-audit a code snippet or function against rules | `code`, `filePath` |
| `audit_learn_report` | Ingest a new CVE or bug bounty writeup into memory | `title`, `contentOrPath` |
| `audit_search_knowledge` | Search learned threat database for exploit mechanisms | `query` |
| `audit_get_threat_intel_stats` | Inspect threat intelligence knowledge base metrics | *(none)* |

## Standard Antigravity Security Workflow

1. **Pre-Audit Reconnaissance**:
   - Check workspace posture: call `audit_get_workspace_posture()` to see overall health score.
2. **Scan Codebase or Target File**:
   - For full project: call `scan_project({ targetPath: "." })`.
   - For single file or during editing: call `audit_scan_file({ filePath: "src/..." })`.
3. **Review & Adversarial Verification**:
   - Call `get_findings({ severity: "CRITICAL" })` to inspect confirmed issues.
   - For any ambiguous issue, call `validate_finding({ findingJson })` to ensure it is not a test mock.
4. **Explain Root Cause**:
   - Call `audit_explain_vulnerability({ ruleId })` to get deep technical context.
5. **Generate PoC**:
   - Call `audit_generate_poc({ findingJson, format: "AUTO" })` to build a safe test harness.
6. **Apply Verified Remediation**:
   - Call `apply_fix({ filePath, target, replacement })` or present unified diff to user.
7. **Re-verify Zero Regressions**:
   - Call `audit_scan_file` to confirm the vulnerability is 100% resolved.
