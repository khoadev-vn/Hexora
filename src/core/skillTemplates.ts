export const ANTIGRAVITY_SKILL_MD = `---
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
| \`scan_project\` | Complete repository scan with full adversarial verification | \`targetPath\` |
| \`audit_scan_file\` | Fast single-file or in-memory code scan on edit/save | \`filePath\`, \`content\` |
| \`get_findings\` | Retrieve verified findings filtered by severity or category | \`severity\`, \`category\` |
| \`apply_fix\` | Safely apply automated patch or replacement to source code | \`filePath\`, \`target\`, \`replacement\`, \`unifiedDiff\` |
| \`audit_explain_vulnerability\` | Deep architectural root cause & CVSS breakdown of an issue | \`ruleId\`, \`findingJson\` |
| \`audit_generate_poc\` | Synthesize safe, executable reproduction PoC test scripts | \`findingJson\`, \`format\` |
| \`audit_get_workspace_posture\` | Real-time workspace security grade (A+ to F) & stats | \`targetPath\` |
| \`validate_finding\` | Challenge candidate finding to filter false positives | \`findingJson\` |
| \`audit_check_snippet\` | Live-audit a code snippet or function against rules | \`code\`, \`filePath\` |
| \`audit_learn_report\` | Ingest a new CVE or bug bounty writeup into memory | \`title\`, \`contentOrPath\` |
| \`audit_search_knowledge\` | Search learned threat database for exploit mechanisms | \`query\` |
| \`audit_get_threat_intel_stats\` | Inspect threat intelligence knowledge base metrics | *(none)* |

## Standard Antigravity Security Workflow

1. **Pre-Audit Reconnaissance**:
   - Check workspace posture: call \`audit_get_workspace_posture()\` to see overall health score.
2. **Scan Codebase or Target File**:
   - For full project: call \`scan_project({ targetPath: "." })\`.
   - For single file or during editing: call \`audit_scan_file({ filePath: "src/..." })\`.
3. **Review & Adversarial Verification**:
   - Call \`get_findings({ severity: "CRITICAL" })\` to inspect confirmed issues.
   - For any ambiguous issue, call \`validate_finding({ findingJson })\` to ensure it is not a test mock.
4. **Explain Root Cause**:
   - Call \`audit_explain_vulnerability({ ruleId })\` to get deep technical context.
5. **Generate PoC**:
   - Call \`audit_generate_poc({ findingJson, format: "AUTO" })\` to build a safe test harness.
6. **Apply Verified Remediation**:
   - Call \`apply_fix({ filePath, target, replacement })\` or present unified diff to user.
7. **Re-verify Zero Regressions**:
   - Call \`audit_scan_file\` to confirm the vulnerability is 100% resolved.
`;

export const ANTIGRAVITY_RULES_MD = `# Hexora Security Guardrails for Antigravity

- **Zero Leaked Secrets Policy**: Never commit or hardcode private keys, AWS tokens, OpenAI/Gemini keys, Solana secret keys, or database credentials.
- **Continuous Single-File Audit**: When editing sensitive files (auth, payments, crypto, API handlers, prompts), invoke Hexora \`audit_scan_file\` before completing turns.
- **Input Sanitization & Injection Defense**: Prevent SQL, NoSQL, SSTI, Command Injection, and Prompt Injection (OWASP LLM01).
- **Smart Contract Safety**: Enforce reentrancy protection, CEI pattern, Solana account owner/signer checks, and safe math.
- **Automated Verification**: Challenge any candidate finding with Hexora Adversarial Verifier before presenting reports to users.
`;

export const CURSOR_RULE_MDC = `---
description: Hexora Security Audit & Remediation Guidelines
globs: *
---
# Hexora Security Rules for Cursor

When generating or editing code:
1. Never hardcode API keys, private keys, or credentials.
2. Use Hexora MCP tools (\`scan_project\`, \`audit_scan_file\`, \`apply_fix\`) to verify security posture.
3. Validate all external inputs against injection vulnerabilities (SQL, NoSQL, SSTI, Shell, LLM Prompt Injection).
4. If a vulnerability is detected, verify with Hexora Adversarial Verifier and apply safe unified patches.
`;

export const CLAUDE_CODE_MD = `# Hexora Security Protocol for Claude Code

Hexora is configured as an MCP server in this workspace.
Available commands:
- \`scan_project\`: Run comprehensive multi-language security audit.
- \`audit_scan_file\`: Inspect a single file for vulnerabilities.
- \`apply_fix\`: Automatically patch confirmed security bugs.
- \`audit_explain_vulnerability\`: Deep dive into vulnerability mechanics and fix strategies.

Always check for high-entropy secrets and unsafe deserialization before pushing code.
`;

export const WINDSURF_RULES_MD = `# Hexora Security Protocol for Windsurf

When building and refactoring software:
- Follow OWASP Top 10, CWE Top 25, and SWC Registry security best practices.
- Use Hexora MCP server tools to scan workspaces, detect vulnerabilities, and synthesize safe diff fixes.
- Proactively verify dependencies with SCA checks.
`;
