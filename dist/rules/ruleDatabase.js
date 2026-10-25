export const BUILTIN_RULES = [
    // ==================== 1. HARDCODED SECRETS & KEYS ====================
    {
        id: 'HEX-SEC-001',
        name: 'Hardcoded Private Key or High-Entropy Secret',
        severity: 'CRITICAL',
        category: 'SECRET',
        cwe: 'CWE-798',
        owasp: 'A07:2021-Identification and Authentication Failures',
        languages: ['js', 'ts', 'py', 'go', 'rs', 'json', 'env', 'sol'],
        pattern: /(?:private[_-]?key|secret[_-]?key|api[_-]?key|wallet[_-]?key|mnemonic|seed_phrase)\s*[:=]\s*["']([a-zA-Z0-9_\-\.]{24,})["']/i,
        description: 'A sensitive credential, API key, or private key is hardcoded directly in source code.',
        remediationAdvice: 'Extract secrets to secure environment variables or a key vault (e.g. AWS KMS, HashiCorp Vault). Never commit credentials to version control.'
    },
    {
        id: 'HEX-SEC-002',
        name: 'Exposed Solana or EVM Raw Private Key',
        severity: 'CRITICAL',
        category: 'WEB3',
        cwe: 'CWE-312',
        owasp: 'A07:2021-Identification and Authentication Failures',
        languages: ['js', 'ts', 'py', 'sol'],
        pattern: /(?:0x[a-fA-F0-9]{64}|[1-9A-HJ-NP-Za-km-z]{87,88})/,
        validate: (match, content, _path) => {
            const val = match[0];
            if (val.startsWith('0x') && val.length === 66) {
                return /key|secret|signer|deployer/i.test(content.slice(Math.max(0, match.index - 50), match.index + 50));
            }
            return val.length >= 87; // Base58 64-byte Solana secret key
        },
        description: 'Raw cryptographic private key detected. Unauthorized access leads to total asset depletion.',
        remediationAdvice: 'Revoke and rotate the compromised key immediately. Use hardware wallets or HSM for key signing.'
    },
    // ==================== 2. COMMAND & CODE INJECTION ====================
    {
        id: 'HEX-INJ-001',
        name: 'OS Command Injection via Shell Execution',
        severity: 'CRITICAL',
        category: 'INJECTION',
        cwe: 'CWE-78',
        owasp: 'A03:2021-Injection',
        languages: ['js', 'ts', 'py'],
        pattern: /(?:(?:child_process|cp)\.)?(?:exec|execSync)\s*\(\s*`[^`]*\${.+}[^`]*`|os\.system\s*\(|subprocess\.call\s*\([^,]+shell\s*=\s*True/,
        description: 'Dynamic user input concatenated directly into a shell execution string allows arbitrary remote code execution (RCE).',
        remediationAdvice: 'Use execFile or spawn with argument arrays rather than string interpolation with shell: true.'
    },
    {
        id: 'HEX-INJ-002',
        name: 'Dynamic Code Evaluation (eval / Function)',
        severity: 'HIGH',
        category: 'INJECTION',
        cwe: 'CWE-95',
        owasp: 'A03:2021-Injection',
        languages: ['js', 'ts', 'py'],
        pattern: /(?:eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*["'`])/,
        description: 'Dynamic evaluation of code via eval() or Function constructor allows untrusted code injection.',
        remediationAdvice: 'Refactor logic into safe lookup tables, AST interpreters, or strict JSON.parse.'
    },
    // ==================== 3. SQL & NOSQL INJECTION ====================
    {
        id: 'HEX-INJ-003',
        name: 'SQL Injection via Template Literal Concatenation',
        severity: 'CRITICAL',
        category: 'INJECTION',
        cwe: 'CWE-89',
        owasp: 'A03:2021-Injection',
        languages: ['js', 'ts', 'py'],
        pattern: /(?:query|raw|execute)\s*\(\s*`\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+[^`]*\${.+}[^`]*`|\b(?:SELECT\s+[\w*,\s]+\s+FROM|INSERT\s+INTO\s+\w+|UPDATE\s+\w+\s+SET|DELETE\s+FROM\s+\w+|DROP\s+TABLE)\b[^;\n]*['"]\s*\+\s*[a-zA-Z0-9_.]+/i,
        validate: (match, content, filePath) => {
            // Must not match crypto or stream update calls like crypto.createHash('sha1').update(...)
            if (/createHash|cipher|hmac|digest|cacheKey/i.test(match.input.slice(Math.max(0, match.index - 50), match.index + 50))) {
                return false;
            }
            return true;
        },
        description: 'SQL queries built with unescaped string interpolation allow database compromise and data exfiltration.',
        remediationAdvice: 'Use parameterized queries, prepared statements, or ORM parameter binding (e.g. $1, ?).'
    },
    // ==================== 4. SSRF & PATH TRAVERSAL ====================
    {
        id: 'HEX-NET-001',
        name: 'Potential Server-Side Request Forgery (SSRF)',
        severity: 'HIGH',
        category: 'INJECTION',
        cwe: 'CWE-918',
        owasp: 'A10:2021-Server-Side Request Forgery',
        languages: ['js', 'ts', 'py'],
        pattern: /(?:fetch|axios\.(?:get|post|request)|http\.(?:get|request)|requests\.(?:get|post))\s*\(\s*(?:req\.(?:query|body|params)|(?:targetUrl|inputUrl|userUrl|untrustedUrl)\b)/,
        validate: (match, content, filePath) => {
            // Relative paths or frontend URLs are not SSRF
            const matched = match[0];
            if (/['"]\//.test(matched))
                return false;
            return true;
        },
        description: 'Outbound HTTP requests constructed directly from untrusted input allow internal network pivoting and metadata theft (e.g. 169.254.169.254).',
        remediationAdvice: 'Validate target hosts against a strict domain allowlist and block private IP ranges (RFC 1918, loopback, link-local).'
    },
    {
        id: 'HEX-FS-001',
        name: 'Path Traversal via Unsanitized File Path',
        severity: 'HIGH',
        category: 'INJECTION',
        cwe: 'CWE-22',
        owasp: 'A01:2021-Broken Access Control',
        languages: ['js', 'ts', 'py'],
        pattern: /fs\.(?:readFile|readFileSync|createReadStream|writeFile|unlink)\s*\(\s*(?:path\.(?:join|resolve)\([^)]*(?:req\.|user|input|query|params|filename|filePath|targetPath)|req\.(?:params|query|body)|target\b)/,
        validate: (match, content, filePath) => {
            // Disqualify if reading purely static files (all string literals in path.join without variables)
            const afterSink = content.slice(match.index, match.index + 120);
            const isStaticPath = /path\.join\(\s*__dirname\s*,\s*['"][^'"]+['"]\s*\)/.test(afterSink);
            if (isStaticPath)
                return false;
            return true;
        },
        description: 'Unvalidated user input in filesystem operations allows reading or overwriting arbitrary host files via dot-dot-slash (../).',
        remediationAdvice: 'Resolve absolute paths and verify path starts with the trusted root directory: path.resolve(root, input).startsWith(root).'
    },
    // ==================== 5. AUTHENTICATION & ACCESS CONTROL (OWASP A01/A07) ====================
    {
        id: 'HEX-AUTH-001',
        name: 'Insecure Permissive CORS Configuration',
        severity: 'MEDIUM',
        category: 'MISCONFIG',
        cwe: 'CWE-942',
        owasp: 'A05:2021-Security Misconfiguration',
        languages: ['js', 'ts'],
        pattern: /origin\s*:\s*(?:true|['"]\*['"])\s*,\s*credentials\s*:\s*true/i,
        description: 'Wildcard CORS with credentials enabled allows malicious third-party origins to read authenticated session data.',
        remediationAdvice: 'Specify an explicit, validated list of allowed origins when credentials: true is required.'
    },
    {
        id: 'HEX-AUTH-002',
        name: 'Insecure JWT Verification / None Algorithm Acceptance',
        severity: 'HIGH',
        category: 'AUTH',
        cwe: 'CWE-345',
        owasp: 'A07:2021-Identification and Authentication Failures',
        languages: ['js', 'ts', 'py'],
        pattern: /jwt\.(?:decode\s*\(|verify\s*\([^,]+,[^,]+,\s*\{[^}]*algorithms\s*:\s*\[[^\]]*['"]none['"])/i,
        description: 'Using jwt.decode() instead of jwt.verify(), or accepting the "none" signature algorithm enables token forgery and privilege escalation.',
        remediationAdvice: 'Always use jwt.verify() with explicitly whitelisted asymmetric algorithms like RS256 or secure HMAC keys with HS256.'
    },
    {
        id: 'HEX-AUTH-003',
        name: 'Broken Object Level Authorization (BOLA / IDOR)',
        severity: 'HIGH',
        category: 'AUTH',
        cwe: 'CWE-639',
        owasp: 'A01:2021-Broken Access Control',
        languages: ['js', 'ts', 'py'],
        pattern: /(?:findById|findOne|delete|update)\s*\(\s*(?:req\.params\.id|req\.body\.id)\s*\)(?!\s*\.where\s*\(.*user)/i,
        description: 'Accessing or mutating records based solely on client-supplied ID parameters without validating tenant/user ownership.',
        remediationAdvice: 'Enforce authorization checks scoping records to the authenticated session context (e.g. { id: req.params.id, ownerId: req.user.id }).'
    },
    {
        id: 'HEX-DESER-001',
        name: 'Insecure Deserialization of Untrusted Data',
        severity: 'CRITICAL',
        category: 'INJECTION',
        cwe: 'CWE-502',
        owasp: 'A08:2021-Software and Data Integrity Failures',
        languages: ['py', 'js', 'ts'],
        pattern: /(?:pickle\.loads|yaml\.unsafe_load|node-serialize\.unserialize|serialize\.unserialize)\s*\(/,
        description: 'Deserializing untrusted data with unsafe parsers (pickle, yaml.unsafe_load, node-serialize) leads to instant remote code execution.',
        remediationAdvice: 'Use safe data serialization formats like JSON.parse() or yaml.safe_load(), and sign serialized state with HMAC.'
    },
    {
        id: 'HEX-REDOS-001',
        name: 'Catastrophic Regex Backtracking (ReDoS)',
        severity: 'MEDIUM',
        category: 'DOS',
        cwe: 'CWE-1333',
        owasp: 'A05:2021-Security Misconfiguration',
        languages: ['js', 'ts', 'py'],
        pattern: /\/([a-zA-Z0-9_\-\.\*]+\+)+\+\/|\/([a-zA-Z0-9_\-\.\*]+\*)+\*\/|\(([a-zA-Z0-9_\-\.]+[\+\*])\)\+/,
        description: 'Nested quantifiers in regular expressions create exponential backtracking during mismatch on crafted inputs, freezing the event loop.',
        remediationAdvice: 'Use linear-time regex engines (re2) or atomic groups/possessive quantifiers to prevent polynomial/exponential backtracking.'
    },
    // ==================== 6. AI AGENT & LLM SAFETY (OWASP LLM TOP 10) ====================
    {
        id: 'HEX-AI-001',
        name: 'Insecure Direct Prompt Concatenation',
        severity: 'HIGH',
        category: 'AI_AGENT',
        cwe: 'CWE-20',
        owasp: 'OWASP LLM01: Prompt Injection',
        languages: ['js', 'ts', 'py'],
        pattern: /(?:prompt|messages)\s*[:=]\s*(?:`[^`]*\${(?:req|user|input|query|instruction)[^`]*`|.*(?:\+|concat\().*(?:user|instruction|input|query))/i,
        description: 'Direct string interpolation of untrusted user input into system prompts enables Prompt Injection and guardrail bypass.',
        remediationAdvice: 'Separate system instructions and untrusted inputs into distinct structured roles (system vs user messages). Apply input sanitization.'
    },
    {
        id: 'HEX-AI-002',
        name: 'Unconstrained AI Tool / MCP Execution',
        severity: 'CRITICAL',
        category: 'AI_AGENT',
        cwe: 'CWE-862',
        owasp: 'OWASP LLM02: Insecure Output Handling',
        languages: ['js', 'ts', 'py'],
        pattern: /(?:run_command|execute_shell|system_call|execTool)\s*\(\s*(?:llmResponse|toolCall\.args)/,
        description: 'Executing AI tool outputs directly into shell or high-privilege APIs without human-in-the-loop or capability boundaries.',
        remediationAdvice: 'Enforce strict schema validation, capability sandboxes, and explicit user authorization for side-effecting operations.'
    },
    {
        id: 'HEX-AI-003',
        name: 'Insecure Model Weight Deserialization',
        severity: 'CRITICAL',
        category: 'AI_AGENT',
        cwe: 'CWE-502',
        owasp: 'OWASP LLM05: Supply Chain Vulnerabilities',
        languages: ['py'],
        pattern: /torch\.load\s*\([^)]*(?!weights_only\s*=\s*True)[^)]*\)/,
        description: 'Loading PyTorch model checkpoints without weights_only=True allows pickled arbitrary code execution when loading third-party models.',
        remediationAdvice: 'Pass weights_only=True in torch.load() or migrate to modern safetensors format.'
    },
    {
        id: 'HEX-AI-004',
        name: 'AI Context Flooding / Unbounded Memory Ingestion',
        severity: 'MEDIUM',
        category: 'AI_AGENT',
        cwe: 'CWE-400',
        owasp: 'OWASP LLM04: Model Denial of Service',
        languages: ['js', 'ts', 'py'],
        pattern: /(?:messages|chatHistory)\.push\s*\(\s*\{[^}]*content\s*:\s*(?:untrustedWebData|rawDoc|scrapedContent)/,
        description: 'Ingesting unbounded third-party web content or user documents directly into context memory causes token starvation, excessive cost, or context window overflow.',
        remediationAdvice: 'Truncate input lengths, apply token budget rate limiting, and summarize large external contexts through a dedicated sandboxed extractor.'
    },
    // ==================== 7. WEB3 SMART CONTRACTS: EVM & SOLIDITY ====================
    {
        id: 'HEX-W3-001',
        name: 'Solidity External Call Before State Update (Reentrancy)',
        severity: 'CRITICAL',
        category: 'WEB3',
        cwe: 'CWE-841',
        owasp: 'SWC-107: Reentrancy',
        languages: ['sol'],
        pattern: /\.call\{value:[^}]*\}\s*\(.*?\);[\s\S]{1,120}(?:balances\[|totalDeposit\s*=)/,
        description: 'State variable modification occurring after an external value transfer creates a classic reentrancy vulnerability.',
        remediationAdvice: 'Follow the Checks-Effects-Interactions pattern or utilize OpenZeppelin ReentrancyGuard.'
    },
    {
        id: 'HEX-W3-003',
        name: 'Solidity Arbitrary Delegatecall to User-Controlled Address',
        severity: 'CRITICAL',
        category: 'WEB3',
        cwe: 'CWE-829',
        owasp: 'SWC-112: Delegatecall to Untrusted Callee',
        languages: ['sol'],
        pattern: /(?:target|callee|impl)\.delegatecall\s*\(/,
        description: 'Executing delegatecall on a dynamically supplied or untrusted address allows the target contract to rewrite the caller storage and drain assets.',
        remediationAdvice: 'Only delegatecall to hardcoded immutable implementation addresses verified through upgradeable proxy patterns.'
    },
    {
        id: 'HEX-W3-004',
        name: 'Solidity Authorization via tx.origin',
        severity: 'HIGH',
        category: 'WEB3',
        cwe: 'CWE-306',
        owasp: 'SWC-115: Authorization through tx.origin',
        languages: ['sol'],
        pattern: /require\s*\(\s*tx\.origin\s*==\s*(?:owner|admin|authority)/,
        description: 'Using tx.origin for access control leaves contract accounts vulnerable to phishing attacks via malicious intermediary contracts.',
        remediationAdvice: 'Use msg.sender instead of tx.origin to authenticate callers.'
    },
    {
        id: 'HEX-W3-005',
        name: 'Solidity Unprotected Selfdestruct Instruction',
        severity: 'CRITICAL',
        category: 'WEB3',
        cwe: 'CWE-284',
        owasp: 'SWC-106: Unprotected SELFDESTRUCT',
        languages: ['sol'],
        pattern: /selfdestruct\s*\(\s*(?:payable\s*\()?[a-zA-Z0-9_\.]+\s*\)?/,
        description: 'Contract contains selfdestruct without bulletproof multisig or timelock access controls, risking permanent bricking of protocol logic and funds.',
        remediationAdvice: 'Avoid selfdestruct (deprecated in Cancun EVM EIP-6780). If necessary, gate behind strict OpenZeppelin Ownable2Step / Timelock.'
    },
    {
        id: 'HEX-W3-006',
        name: 'Solidity Unchecked ERC-20 Return Value',
        severity: 'HIGH',
        category: 'WEB3',
        cwe: 'CWE-252',
        owasp: 'SWC-104: Unchecked Return Value',
        languages: ['sol'],
        pattern: /IERC20\([^)]+\)\.(?:transfer|transferFrom)\s*\(/,
        description: 'Tokens like USDT return false or do not return a boolean on transfer failure. Failing to verify the return value leads to phantom deposits.',
        remediationAdvice: 'Use OpenZeppelin SafeERC20 library (safeTransfer, safeTransferFrom).'
    },
    {
        id: 'HEX-W3-007',
        name: 'DeFi AMM Spot Price Manipulation / Flash Loan Oracle Risk',
        severity: 'CRITICAL',
        category: 'WEB3',
        cwe: 'CWE-682',
        owasp: 'DeFi-Vulnerability: Spot Price Oracle',
        languages: ['sol', 'rs'],
        pattern: /(?:reserves\[0\]\s*\/\s*reserves\[1\]|getReserves\(\)|slot0\(\)\.sqrtPriceX96)/,
        description: 'Using instantaneous spot prices or raw AMM reserves as a pricing oracle enables attackers to manipulate valuations using flash loans.',
        remediationAdvice: 'Use Uniswap v3 TWAP or decentralized off-chain oracles like Chainlink / Pyth with staleness and deviation checks.'
    },
    // ==================== 8. WEB3 SMART CONTRACTS: SOLANA SEALEVEL & ANCHOR ====================
    {
        id: 'HEX-W3-002',
        name: 'Solana Missing Signer or Owner Verification',
        severity: 'CRITICAL',
        category: 'WEB3',
        cwe: 'CWE-285',
        owasp: 'Solana OWASP: Missing Signer Check',
        languages: ['rs', 'ts'],
        pattern: /(?:AccountInfo|ctx\.accounts\.[a-zA-Z0-9_]+)(?!\.is_signer|\.signer)[^;\n]*\.(?:transfer|burn|close)/,
        description: 'Critical Solana program operation executed on an account without verifying is_signer or program ownership.',
        remediationAdvice: 'Use Anchor Signer<\'info> or explicitly require ctx.accounts.authority.is_signer.'
    },
    {
        id: 'HEX-W3-008',
        name: 'Solana Arbitrary CPI / Missing Target Program ID Verification',
        severity: 'CRITICAL',
        category: 'WEB3',
        cwe: 'CWE-284',
        owasp: 'Solana OWASP: Arbitrary CPI',
        languages: ['rs'],
        pattern: /solana_program::program::invoke(?:_signed)?\s*\([^,]+,\s*&\[[^\]]*ctx\.accounts\./,
        description: 'Cross-Program Invocations (CPI) without verifying the target program ID allow attackers to pass fake programs and spoof successful executions.',
        remediationAdvice: 'Verify target program ID: require_keys_eq!(*ctx.accounts.token_program.key, anchor_spl::token::ID).'
    },
    {
        id: 'HEX-W3-009',
        name: 'Solana Missing Canonical Bump Seed Verification',
        severity: 'HIGH',
        category: 'WEB3',
        cwe: 'CWE-345',
        owasp: 'Solana OWASP: PDA Canonicalization',
        languages: ['rs'],
        pattern: /Pubkey::create_program_address\s*\(/,
        description: 'Using create_program_address instead of find_program_address, or failing to store and check canonical bumps enables PDA spoofing attacks.',
        remediationAdvice: 'Use find_program_address and store the resulting canonical bump in the account, validating it with Anchor bump constraint.'
    },
    {
        id: 'HEX-W3-010',
        name: 'Solana Account Revival / Missing Discriminator Zeroing',
        severity: 'HIGH',
        category: 'WEB3',
        cwe: 'CWE-672',
        owasp: 'Solana OWASP: Closing Account Revival',
        languages: ['rs'],
        pattern: /close\s*=\s*[a-zA-Z0-9_]+(?![^}]*8_bytes_zero)/,
        description: 'Closing an Anchor account transfers lamports but leaves data intact within the same transaction, allowing subsequent instructions to revive it.',
        remediationAdvice: 'Zero out the 8-byte Anchor account discriminator when closing accounts, or use modern Anchor close constraints.'
    },
    // ==================== 9. CLOUD & INFRASTRUCTURE MISCONFIGURATIONS ====================
    {
        id: 'HEX-CLOUD-001',
        name: 'Exposed Cloud Instance Metadata (IMDSv1) Query',
        severity: 'CRITICAL',
        category: 'CLOUD',
        cwe: 'CWE-918',
        owasp: 'A10:2021-SSRF',
        languages: ['js', 'ts', 'py', 'sh'],
        pattern: /169\.254\.169\.254|metadata\.google\.internal/,
        description: 'Direct queries to Cloud Instance Metadata Services can be leveraged by SSRF to extract temporary IAM STS credentials.',
        remediationAdvice: 'Enforce IMDSv2 with hop-limit 1 and block local network requests to link-local IP 169.254.169.254.'
    },
    {
        id: 'HEX-CLOUD-002',
        name: 'Exposed Docker Daemon Socket / Container Privilege Escalation',
        severity: 'CRITICAL',
        category: 'CLOUD',
        cwe: 'CWE-250',
        owasp: 'A05:2021-Security Misconfiguration',
        languages: ['yml', 'yaml', 'json'],
        pattern: /\/var\/run\/docker\.sock|privileged\s*:\s*true/,
        description: 'Mounting the Docker socket inside containers or running containers with privileged: true grants container processes root access to the host node.',
        remediationAdvice: 'Remove Docker socket mounts, drop all Linux capabilities, and run containers as non-root unprivileged users.'
    },
    // ==================== 10. CLOUDFLARE EDGE & NETWORK SECURITY ====================
    {
        id: 'HEX-CF-001',
        name: 'Cloudflare Workers Edge Environment Secret Leakage',
        severity: 'CRITICAL',
        category: 'CLOUD',
        cwe: 'CWE-200',
        owasp: 'A01:2021-Broken Access Control',
        languages: ['js', 'ts'],
        pattern: /(?:Response\s*\(\s*JSON\.stringify\s*\(\s*env\b|new\s+Response\s*\([^)]*env\.(?:API_KEY|SECRET|TOKEN|PRIVATE_KEY|DATABASE_URL))/i,
        description: 'Cloudflare Workers edge function returns raw env object or sensitive environment bindings directly in HTTP response payloads.',
        remediationAdvice: 'Never serialize the whole env context into responses. Only return explicitly sanitized fields.'
    },
    {
        id: 'HEX-CF-002',
        name: 'Cloudflare Client IP Header Trust Without Proxy Range Validation',
        severity: 'MEDIUM',
        category: 'AUTH',
        cwe: 'CWE-290',
        owasp: 'A07:2021-Identification and Authentication Failures',
        languages: ['js', 'ts', 'py'],
        pattern: /(?:req\.headers|headers\.get)\s*\(?['"]cf-connecting-ip['"]\)?(?!\s*&&.*isCloudflareIp)/i,
        description: 'Relying on cf-connecting-ip or x-forwarded-for without verifying that the upstream connection originates strictly from Cloudflare public IP ranges allows IP spoofing and rate limit bypass.',
        remediationAdvice: 'Enforce Cloudflare authenticated origin pull (mTLS) or validate upstream remoteAddress against official Cloudflare CIDR blocks.'
    },
    {
        id: 'HEX-CF-003',
        name: 'Cloudflare CFSSL / Deprecated Insecure TLS Version',
        severity: 'HIGH',
        category: 'MISCONFIG',
        cwe: 'CWE-326',
        owasp: 'A02:2021-Cryptographic Failures',
        languages: ['json', 'yml', 'yaml', 'js', 'ts', 'go'],
        pattern: /(?:min_version|minVersion|ssl_protocols)\s*[:=]\s*["'](?:TLSv1|TLSv1\.0|TLSv1\.1|SSLv3)["']/i,
        description: 'Configuring TLS endpoints with legacy protocol versions (TLS 1.0, TLS 1.1, SSLv3) exposes traffic to known cryptographic attacks (POODLE, BEAST).',
        remediationAdvice: 'Enforce TLSv1.2 as minimum version, ideally TLSv1.3 as recommended by Cloudflare CFSSL profiles.'
    },
    {
        id: 'HEX-CF-004',
        name: 'Cloudflare Flan / High-Risk Database or Debug Port Exposed on 0.0.0.0',
        severity: 'HIGH',
        category: 'MISCONFIG',
        cwe: 'CWE-200',
        owasp: 'A05:2021-Security Misconfiguration',
        languages: ['js', 'ts', 'py', 'yml', 'yaml'],
        pattern: /(?:listen|bind)\s*\(\s*(?:9229|6379|27017|2375|8500)\s*,\s*['"]0\.0\.0\.0['"]/i,
        description: 'Binding debug or datastore ports (Node inspector 9229, Redis 6379, MongoDB 27017, Docker socket 2375) to 0.0.0.0 makes them vulnerable to external network scanning (Cloudflare Flan Scan detection).',
        remediationAdvice: 'Bind administrative and datastore ports to 127.0.0.1 or internal private VPC subnets only.'
    },
    // ==================== 11. HEXORA SECRET RADAR: HIGH-ENTROPY SECRETS & API KEYS ====================
    {
        id: 'HEX-GITL-001',
        name: 'Secret Radar: GitHub Personal Access Token (Classic / Fine-Grained)',
        severity: 'CRITICAL',
        category: 'SECRET',
        cwe: 'CWE-798',
        owasp: 'A07:2021-Identification and Authentication Failures',
        languages: ['js', 'ts', 'py', 'go', 'rs', 'json', 'env', 'yml', 'yaml'],
        pattern: /(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})/,
        description: 'Exposed GitHub Personal Access Token detected via entropy analysis. Can grant full repository, organization, or workflow access.',
        remediationAdvice: 'Revoke the token immediately in GitHub Settings > Developer Settings > Personal Access Tokens and rotate all secrets.'
    },
    {
        id: 'HEX-GITL-002',
        name: 'Secret Radar: AWS Access Key ID & Secret Access Key',
        severity: 'CRITICAL',
        category: 'SECRET',
        cwe: 'CWE-798',
        owasp: 'A07:2021-Identification and Authentication Failures',
        languages: ['js', 'ts', 'py', 'go', 'rs', 'json', 'env', 'yml', 'yaml'],
        pattern: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
        description: 'Direct AWS Access Key ID exposed in plaintext source or configuration files.',
        remediationAdvice: 'Revoke IAM access keys via AWS IAM Console. Enforce IAM roles and instance profiles instead of long-lived access keys.'
    },
    {
        id: 'HEX-GITL-003',
        name: 'Secret Radar: Stripe Live Secret API Key',
        severity: 'CRITICAL',
        category: 'SECRET',
        cwe: 'CWE-798',
        owasp: 'A07:2021-Identification and Authentication Failures',
        languages: ['js', 'ts', 'py', 'json', 'env'],
        pattern: /sk_live_[0-9a-zA-Z]{24,}/,
        description: 'Exposed Stripe Live API Secret Key enables unauthorized financial transactions and charge modifications.',
        remediationAdvice: 'Roll the API key in the Stripe Dashboard > Developers > API keys and restrict key capabilities.'
    },
    {
        id: 'HEX-GITL-004',
        name: 'Secret Radar: AI Provider API Key (OpenAI / Anthropic / Google Cloud)',
        severity: 'CRITICAL',
        category: 'SECRET',
        cwe: 'CWE-798',
        owasp: 'A07:2021-Identification and Authentication Failures',
        languages: ['js', 'ts', 'py', 'go', 'rs', 'json', 'env'],
        pattern: /(?:sk-[a-zA-Z0-9]{48}|sk-proj-[a-zA-Z0-9_-]{48,}|AIza[0-9A-Za-z\-_]{35}|sk-ant-api[0-9]{2}-[a-zA-Z0-9_\-]{80,})/,
        description: 'High-privilege LLM provider API key hardcoded in source repository. Vulnerable to quota depletion and model abuse.',
        remediationAdvice: 'Store AI API keys in environment variables or cloud secrets managers. Set usage limits and rotate leaked tokens.'
    },
    // ==================== 12. HEXORA SEMANTIC LOGIC & OBJECT MUTATION ENGINE ====================
    {
        id: 'HEX-SEMGREP-001',
        name: 'Object Mutation: JavaScript Prototype Pollution via Recursive Object Merge',
        severity: 'HIGH',
        category: 'INJECTION',
        cwe: 'CWE-1321',
        owasp: 'A03:2021-Injection',
        languages: ['js', 'ts'],
        pattern: /(?:target\[key\]\s*=\s*source\[key\]|Object\.assign\s*\([^,]+,\s*(?:req\.body|data)[\),]|__proto__|prototype\[)/,
        validate: (_m, content) => !content.includes('Object.prototype.hasOwnProperty') || content.includes('__proto__'),
        description: 'Merging untrusted objects without prototype property filtering allows modifying Object.prototype, leading to privilege escalation or RCE.',
        remediationAdvice: 'Block "__proto__", "constructor", and "prototype" keys, or use Object.create(null) or Map data structures.'
    },
    {
        id: 'HEX-SEMGREP-002',
        name: 'Data Integrity: Mass Assignment / Over-Posting in ORM Records',
        severity: 'HIGH',
        category: 'MISCONFIG',
        cwe: 'CWE-915',
        owasp: 'A04:2021-Insecure Design',
        languages: ['js', 'ts', 'py'],
        pattern: /(?:User|Account|Profile|Order)\.(?:create|update|updateMany)\s*\(\s*req\.body\s*\)/i,
        description: 'Directly passing unsanitized req.body into database creation/update methods allows attackers to overwrite administrative attributes (e.g. role: admin, isSuperuser: true).',
        remediationAdvice: 'Pick only explicitly permitted fields using schema validators like Zod or lodash.pick(req.body, ["name", "email"]).'
    },
    {
        id: 'HEX-SEMGREP-003',
        name: 'Session Security: Missing CSRF Protection on Mutating State Routes',
        severity: 'MEDIUM',
        category: 'MISCONFIG',
        cwe: 'CWE-352',
        owasp: 'A01:2021-Broken Access Control',
        languages: ['js', 'ts', 'py'],
        pattern: /session\s*\(\s*\{[^}]*sameSite\s*:\s*['"]none['"][^}]*secure\s*:\s*false/i,
        description: 'Session cookies configured with sameSite: "none" and secure: false allow cross-site request forgery attacks from arbitrary origins.',
        remediationAdvice: 'Set sameSite: "lax" or "strict", require secure: true, and validate CSRF anti-forgery tokens on state-changing requests.'
    },
    // ==================== 13. HEXORA CONTAINER & CLOUD-NATIVE POSTURE ENGINE ====================
    {
        id: 'HEX-CONT-001',
        name: 'Container Hardening: Dockerfile Running as Root / Missing Non-Root USER',
        severity: 'HIGH',
        category: 'CLOUD',
        cwe: 'CWE-250',
        owasp: 'A05:2021-Security Misconfiguration',
        languages: ['Dockerfile', 'dockerfile', 'yml', 'yaml'],
        pattern: /^USER\s+root$/m,
        description: 'Containers executing processes as root user inherit elevated host privileges if a container escape occurs.',
        remediationAdvice: 'Create and switch to a dedicated non-root user in Dockerfile: RUN adduser -D appuser && USER appuser.'
    },
    {
        id: 'HEX-CONT-002',
        name: 'Supply Chain Guard: Unpinned Floating Container Base Image Tag (:latest)',
        severity: 'MEDIUM',
        category: 'CLOUD',
        cwe: 'CWE-829',
        owasp: 'A08:2021-Software and Data Integrity Failures',
        languages: ['Dockerfile', 'dockerfile', 'yml', 'yaml'],
        pattern: /FROM\s+[a-zA-Z0-9_\-\.\/]+:latest\b/i,
        description: 'Using mutable :latest image tags in production containers risks breaking changes and supply chain image poisoning.',
        remediationAdvice: 'Pin container images to specific semantic version tags or immutable cryptographic SHA256 digests (e.g. node:22-alpine@sha256:...).'
    },
    {
        id: 'HEX-CONT-003',
        name: 'Cloud Native Isolation: Kubernetes Host PID / Host Network / Privileged Escalation',
        severity: 'CRITICAL',
        category: 'CLOUD',
        cwe: 'CWE-250',
        owasp: 'A05:2021-Security Misconfiguration',
        languages: ['yml', 'yaml', 'json'],
        pattern: /(?:hostPID|hostNetwork|privileged)\s*:\s*true/,
        description: 'Kubernetes pod manifest with hostPID: true, hostNetwork: true, or privileged: true enables pods to sniff host traffic and escape container boundaries.',
        remediationAdvice: 'Enforce Kubernetes Pod Security Standards (Restricted profile) and disable privileged modes.'
    },
    // ==================== 14. HEXORA ATTACK SURFACE & API RECON ENGINE ====================
    {
        id: 'HEX-EXP-001',
        name: 'API Routing: Unvalidated Open Redirect Vulnerability',
        severity: 'MEDIUM',
        category: 'INJECTION',
        cwe: 'CWE-601',
        owasp: 'A01:2021-Broken Access Control',
        languages: ['js', 'ts', 'py'],
        pattern: /(?:res\.redirect|response\.redirect|redirect)\s*\(\s*(?:req\.query\.(?:url|next|redirect|target|to)|request\.args\.get\(['"]next['"]\))/i,
        description: 'Redirecting users directly to an unvalidated URL parameter enables phishing attacks and OAuth token interception.',
        remediationAdvice: 'Validate redirect URLs against a whitelist of trusted relative paths or verified domain origins.'
    },
    {
        id: 'HEX-EXP-002',
        name: 'API Surface: Production GraphQL Introspection Enabled',
        severity: 'LOW',
        category: 'MISCONFIG',
        cwe: 'CWE-200',
        owasp: 'A05:2021-Security Misconfiguration',
        languages: ['js', 'ts', 'py'],
        pattern: /introspection\s*:\s*true\b/i,
        description: 'Enabling GraphQL schema introspection in production exposes internal queries, mutations, and business logic to attackers.',
        remediationAdvice: 'Disable introspection in production environments: introspection: process.env.NODE_ENV !== "production".'
    },
    {
        id: 'HEX-EXP-003',
        name: 'Credential Exposure: Sensitive Environment or Credential File Committed in Codebase',
        severity: 'HIGH',
        category: 'SECRET',
        cwe: 'CWE-552',
        owasp: 'A05:2021-Security Misconfiguration',
        languages: ['js', 'ts', 'py', 'json', 'yml'],
        pattern: /(?:path\.join\([^)]*['"]\.env['"]|createReadStream\([^)]*['"]\.aws\/credentials['"])/,
        description: 'Referencing or reading sensitive configuration files (.env, .aws/credentials, id_rsa) without proper access controls.',
        remediationAdvice: 'Ensure sensitive dotfiles are added to .gitignore and injected exclusively via encrypted runtime secrets.'
    },
    // ==================== 15. HEXORA SMART CONTRACT STATIC ENGINE: SOLIDITY & EVM ====================
    {
        id: 'HEX-EVM-001',
        name: 'EVM State Manipulation: Dangerous block.timestamp / now Reliance in Critical Logic',
        severity: 'MEDIUM',
        category: 'WEB3',
        cwe: 'CWE-337',
        owasp: 'SWC-116: Block values as a proxy for time',
        languages: ['sol'],
        pattern: /(?:block\.timestamp|now)\s*(?:%|\/|==|<=|>=)\s*[a-zA-Z0-9_\.]+(?![^;]*\+\s*1\s*days)/,
        description: 'Solidity contract utilizes block.timestamp for pseudorandomness or tight timing windows that can be manipulated by miners/validators within drift allowances.',
        remediationAdvice: 'Never use block.timestamp for randomness. Use Chainlink VRF for verifiable randomness and allow tolerance windows for time locks.'
    },
    {
        id: 'HEX-EVM-002',
        name: 'EVM Reentrancy: ERC-777 / ERC-1155 Reentrancy via tokensReceived Callback Hook',
        severity: 'CRITICAL',
        category: 'WEB3',
        cwe: 'CWE-841',
        owasp: 'SWC-107: Reentrancy',
        languages: ['sol'],
        pattern: /(?:tokensReceived|onERC1155Received|onERC721Received)\s*\(/,
        description: 'Contract interacts with ERC-777 or ERC-1155 tokens which invoke arbitrary callbacks on recipient addresses, enabling reentrancy even without native ether transfers.',
        remediationAdvice: 'Apply OpenZeppelin nonReentrant modifier to all token deposit, withdraw, and liquidation functions.'
    },
    {
        id: 'HEX-EVM-003',
        name: 'EVM Storage Corruption: Uninitialized Storage Pointer / Struct Overwrite',
        severity: 'CRITICAL',
        category: 'WEB3',
        cwe: 'CWE-824',
        owasp: 'SWC-109: Uninitialized Storage Pointer',
        languages: ['sol'],
        pattern: /(?:struct\s+[a-zA-Z0-9_]+\s+|[A-Z][a-zA-Z0-9_]*\s+storage\s+[a-zA-Z0-9_]+\s*;)/,
        description: 'Uninitialized local storage pointer in Solidity points to storage slot 0 by default, overwriting critical state variables (e.g. contract owner).',
        remediationAdvice: 'Explicitly initialize local struct pointers with storage memory or use memory keyword.'
    },
    // ==================== 16. HEXORA INJECTION ENGINE: ADVANCED TEMPLATE & INJECTION EXPLOITS ====================
    {
        id: 'HEX-INJ-004',
        name: 'Advanced SSTI: Server-Side Template Injection (SSTI) to RCE',
        severity: 'CRITICAL',
        category: 'INJECTION',
        cwe: 'CWE-1336',
        owasp: 'A03:2021-Injection',
        languages: ['js', 'ts', 'py'],
        pattern: /(?:render_template_string\s*\(|nunjucks\.renderString\s*\(|ejs\.render\s*\(|Handlebars\.compile\s*\(\s*(?:req\.|user|input))/,
        description: 'Passing untrusted user input directly into template engine compilers enables Server-Side Template Injection, yielding instant Remote Code Execution (RCE).',
        remediationAdvice: 'Never render user input as a template string. Pass variables strictly as data context to pre-compiled static templates.'
    },
    {
        id: 'HEX-INJ-005',
        name: 'NoSQL Operator Injection ($where, $regex, $ne)',
        severity: 'HIGH',
        category: 'INJECTION',
        cwe: 'CWE-943',
        owasp: 'A03:2021-Injection',
        languages: ['js', 'ts', 'py'],
        pattern: /(?:\$where\s*:|\$regex\s*:|\$ne\s*:|\$gt\s*:)\s*req\.(?:body|query|params)/i,
        description: 'Accepting raw MongoDB/NoSQL query operators directly from client inputs enables authentication bypass and complete database extraction.',
        remediationAdvice: 'Sanitize query inputs using mongo-sanitize or validate types strictly with Zod to disallow object expressions where strings are expected.'
    },
    {
        id: 'HEX-INJ-006',
        name: 'XML Processing: XML External Entity (XXE) Injection',
        severity: 'HIGH',
        category: 'INJECTION',
        cwe: 'CWE-611',
        owasp: 'A05:2021-Security Misconfiguration',
        languages: ['js', 'ts', 'py'],
        pattern: /(?:noent\s*:\s*true|resolveExternalEntities\s*:\s*true|xml2js\.parseString|libxmljs\.parseXml)/i,
        description: 'XML parser configured with external entity resolution allows attackers to extract local server files and perform internal port scans.',
        remediationAdvice: 'Disable DTD processing and external entity resolution in all XML parsers (noent: false, resolveEntities: false).'
    },
    {
        id: 'HEX-INJ-007',
        name: 'Log Injection / JNDI Remote Code Execution (Log4Shell Pattern)',
        severity: 'CRITICAL',
        category: 'INJECTION',
        cwe: 'CWE-117',
        owasp: 'A03:2021-Injection',
        languages: ['js', 'ts', 'java', 'py'],
        pattern: /(?:logger|console|log)\.(?:info|warn|error|debug)\s*\(\s*(?:['"][^'"]*['"]\s*\+\s*|\`[^\`]*\$\{)[^)]*(?:req\.headers|req\.query|req\.body|req\.params|userAgent|user_input|payload)/i,
        description: 'Direct string concatenation of untrusted client headers/inputs into logger calls enables Log Injection and JNDI/LDAP lookup exploitation (CVE-2021-44228).',
        remediationAdvice: 'Use structured logging with format specifiers or JSON payload objects rather than string interpolation.'
    },
    // ==================== 17. HEXORA INFRASTRUCTURE-AS-CODE (IAC) SECURITY GATE ====================
    {
        id: 'HEX-IAC-001',
        name: 'IaC Cloud Storage: Terraform AWS S3 Bucket Public Access Allowed',
        severity: 'HIGH',
        category: 'CLOUD',
        cwe: 'CWE-732',
        owasp: 'A05:2021-Security Misconfiguration',
        languages: ['tf', 'hcl', 'json'],
        pattern: /block_public_acls\s*=\s*false|block_public_policy\s*=\s*false|acl\s*=\s*["']public-read["']/i,
        description: 'S3 bucket configuration permits public access policies or public read ACLs, risking sensitive data exposure.',
        remediationAdvice: 'Enforce aws_s3_account_public_access_block with block_public_acls = true and block_public_policy = true.'
    },
    {
        id: 'HEX-IAC-002',
        name: 'IaC Network Security: Permissive Ingress from 0.0.0.0/0 on Management Ports (22/3389)',
        severity: 'CRITICAL',
        category: 'CLOUD',
        cwe: 'CWE-284',
        owasp: 'A05:2021-Security Misconfiguration',
        languages: ['tf', 'hcl', 'json'],
        pattern: /cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']\s*\].*(?:from_port|to_port)\s*=\s*(?:22|3389)/s,
        description: 'Opening SSH (22) or RDP (3389) directly to the entire internet (0.0.0.0/0) exposes management interfaces to brute force and automated exploits.',
        remediationAdvice: 'Restrict management port ingress to specific corporate VPN CIDRs or use AWS Systems Manager (SSM) Session Manager.'
    },
    // ==================== 18. BANDIT: PYTHON SECURITY AUDITING (6.1k★ PyCQA/bandit) ====================
    {
        id: 'HEX-BANDIT-001',
        name: 'Bandit: Insecure Cryptographic Hash Algorithm (MD5 / SHA-1)',
        severity: 'MEDIUM',
        category: 'MISCONFIG',
        cwe: 'CWE-327',
        owasp: 'A02:2021-Cryptographic Failures',
        languages: ['py', 'js', 'ts'],
        pattern: /(?:hashlib\.md5|hashlib\.sha1|crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"]\))/i,
        description: 'Collision vulnerabilities in MD5 and SHA-1 make them insecure for cryptographic signatures, password verification, or token generation.',
        remediationAdvice: 'Use modern, secure hash functions such as SHA-256, SHA-3, or Argon2id/bcrypt for password hashing.'
    },
    {
        id: 'HEX-BANDIT-002',
        name: 'Bandit: Subprocess Shell=True Execution',
        severity: 'CRITICAL',
        category: 'INJECTION',
        cwe: 'CWE-78',
        owasp: 'A03:2021-Injection',
        languages: ['py'],
        pattern: /subprocess\.(?:Popen|call|check_call|check_output|run)\s*\([^)]*shell\s*=\s*True/i,
        description: 'Invoking subprocess with shell=True passes strings directly to the system shell interpreter, allowing command injection.',
        remediationAdvice: 'Pass shell=False and provide command arguments as an explicit array of strings: subprocess.run(["ls", "-la"]).'
    }
];
//# sourceMappingURL=ruleDatabase.js.map