import fs from 'node:fs';
import path from 'node:path';
import { BUILTIN_RULES } from '../rules/ruleDatabase.js';
import { ThreatKnowledgeBase } from '../intelligence/threatKnowledgeBase.js';
export class SastScanner {
    rules;
    ignoreDirs;
    maxFileSizeBytes;
    threatKb;
    constructor(options = {}) {
        this.rules = options.customRules || BUILTIN_RULES;
        this.ignoreDirs = new Set([
            'node_modules',
            '.git',
            'dist',
            'build',
            'coverage',
            '.next',
            '.turbo',
            'venv',
            '.venv',
            '__pycache__',
            '.benchmark_workspace',
            '.hexora-results',
            'reports',
            ...(options.ignoreDirs || [])
        ]);
        this.maxFileSizeBytes = (options.maxFileSizeKb || 1024) * 1024;
        this.threatKb = ThreatKnowledgeBase.getInstance();
    }
    async scan(targetDir) {
        const resolvedRoot = path.resolve(targetDir);
        const analyzedFiles = [];
        const skippedFiles = [];
        const attackSurfaces = [];
        const findings = [];
        const allFiles = this.collectFiles(resolvedRoot, this.ignoreDirs);
        for (const filePath of allFiles) {
            const relPath = path.relative(resolvedRoot, filePath).replace(/\\/g, '/');
            try {
                const stats = fs.statSync(filePath);
                if (stats.size > this.maxFileSizeBytes) {
                    skippedFiles.push({ path: relPath, reason: `File size (${Math.round(stats.size / 1024)} KB) exceeds limit` });
                    continue;
                }
                const content = fs.readFileSync(filePath, 'utf-8');
                analyzedFiles.push(relPath);
                // 1. Detect External Attack Surfaces
                this.detectAttackSurfaces(filePath, relPath, content, attackSurfaces);
                // 2. Evaluate Built-in & Custom SAST Rules
                const ext = path.extname(filePath).slice(1).toLowerCase();
                const isSourceFile = ['js', 'ts', 'jsx', 'tsx', 'py', 'sol', 'rs', 'go', 'php', 'java', 'c', 'cpp', 'html', 'vue', 'svelte', 'json', 'env'].includes(ext);
                if (!isSourceFile) {
                    continue;
                }
                for (const rule of this.rules) {
                    if (rule.languages.includes(ext) || rule.languages.includes('*')) {
                        this.evaluateRule(rule, filePath, relPath, content, findings);
                    }
                }
                // 3. Evaluate Direct Threat Report & Attack Variant Signatures
                this.evaluateThreatIntelCorrelations(filePath, relPath, content, findings);
            }
            catch (err) {
                skippedFiles.push({ path: relPath, reason: `Read error: ${err.message}` });
            }
        }
        const coverage = {
            targetRoot: resolvedRoot,
            timestamp: new Date().toISOString(),
            totalFiles: allFiles.length,
            analyzedFiles,
            skippedFiles,
            attackSurfaces,
            completionPercentage: allFiles.length === 0 ? 100 : Math.round((analyzedFiles.length / allFiles.length) * 100)
        };
        return { findings, coverage };
    }
    scanSingleFile(filePath, rootDir = path.dirname(filePath)) {
        const findings = [];
        try {
            const relPath = path.relative(rootDir, filePath).replace(/\\/g, '/');
            const ext = path.extname(filePath).slice(1).toLowerCase();
            const isSourceFile = ['js', 'ts', 'jsx', 'tsx', 'py', 'sol', 'rs', 'go', 'php', 'java', 'c', 'cpp', 'html', 'vue', 'svelte', 'json', 'env'].includes(ext);
            if (!isSourceFile)
                return [];
            const content = fs.readFileSync(filePath, 'utf-8');
            for (const rule of this.rules) {
                if (rule.languages.includes(ext) || rule.languages.includes('*')) {
                    this.evaluateRule(rule, filePath, relPath, content, findings);
                }
            }
            this.evaluateThreatIntelCorrelations(filePath, relPath, content, findings);
        }
        catch {
            // Ignore read errors
        }
        return findings;
    }
    evaluateRule(rule, absPath, relPath, content, findings) {
        const lines = content.split('\n');
        const regex = new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g');
        let match;
        while ((match = regex.exec(content)) !== null) {
            if (rule.validate && !rule.validate(match, content, absPath)) {
                continue;
            }
            // Calculate line number
            const index = match.index;
            let lineStart = 1;
            let lineStartIdx = 0;
            for (let i = 0; i < lines.length; i++) {
                const lineLen = lines[i].length + 1;
                if (lineStartIdx + lineLen > index) {
                    lineStart = i + 1;
                    break;
                }
                lineStartIdx += lineLen;
            }
            const lineEnd = lineStart + match[0].split('\n').length - 1;
            const snippet = lines.slice(Math.max(0, lineStart - 2), Math.min(lines.length, lineEnd + 2)).join('\n');
            // Cross-reference with learned threat intelligence & known reports
            const correlations = this.threatKb.matchThreats(snippet, relPath, rule.category);
            findings.push({
                id: `FIND-${rule.id}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
                ruleId: rule.id,
                title: rule.name,
                severity: rule.severity,
                category: rule.category,
                cwe: rule.cwe,
                owasp: rule.owasp,
                location: {
                    filePath: relPath,
                    lineStart,
                    lineEnd,
                    snippet
                },
                description: rule.description,
                status: 'CANDIDATE',
                correlatedReports: correlations.length > 0 ? correlations : undefined,
                remediation: {
                    explanation: rule.remediationAdvice
                },
                timestamp: new Date().toISOString()
            });
        }
    }
    /**
     * Scans for deep threat patterns directly learned from reports (Immunefi, CVEs, Cloudflare skills)
     */
    evaluateThreatIntelCorrelations(absPath, relPath, content, findings) {
        const reports = this.threatKb.getAllReports();
        const lines = content.split('\n');
        for (const report of reports) {
            for (let pIdx = 0; pIdx < report.triggerPatterns.length; pIdx++) {
                const patternStr = report.triggerPatterns[pIdx];
                let reg;
                try {
                    reg = new RegExp(patternStr, 'g');
                }
                catch {
                    continue;
                }
                let match;
                while ((match = reg.exec(content)) !== null) {
                    // Avoid duplicate findings if already caught by standard rule on same line
                    const index = match.index;
                    let lineStart = 1;
                    let lineStartIdx = 0;
                    for (let i = 0; i < lines.length; i++) {
                        const lineLen = lines[i].length + 1;
                        if (lineStartIdx + lineLen > index) {
                            lineStart = i + 1;
                            break;
                        }
                        lineStartIdx += lineLen;
                    }
                    const alreadyReported = findings.some((f) => f.location.filePath === relPath && Math.abs(f.location.lineStart - lineStart) <= 1);
                    if (alreadyReported) {
                        // Enrich existing finding with this threat report correlation
                        const existing = findings.find((f) => f.location.filePath === relPath && Math.abs(f.location.lineStart - lineStart) <= 1);
                        if (existing) {
                            if (!existing.correlatedReports)
                                existing.correlatedReports = [];
                            if (!existing.correlatedReports.some((c) => c.reportId === report.id)) {
                                existing.correlatedReports.push({
                                    reportId: report.id,
                                    title: report.title,
                                    source: report.source,
                                    similarityScore: 0.95,
                                    attackVariant: report.attackVariants[pIdx] || report.attackVariants[0],
                                    vulnerabilityClass: report.vulnerabilityClass,
                                    exploitMechanism: report.exploitMechanism,
                                    referenceUrl: report.referenceUrl
                                });
                            }
                        }
                        continue;
                    }
                    const lineEnd = lineStart + match[0].split('\n').length - 1;
                    const snippet = lines.slice(Math.max(0, lineStart - 2), Math.min(lines.length, lineEnd + 2)).join('\n');
                    const variant = report.attackVariants[pIdx] || report.attackVariants[0] || 'Known Attack Variant';
                    findings.push({
                        id: `FIND-INTEL-${report.id}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
                        ruleId: report.id,
                        title: `[Threat Intel Match] ${report.title} (${variant})`,
                        severity: report.severity,
                        category: report.category,
                        location: {
                            filePath: relPath,
                            lineStart,
                            lineEnd,
                            snippet
                        },
                        description: `Pattern strongly correlates with historical incident / CVE report ${report.id}. Attackers utilize technique: "${variant}".`,
                        status: 'CANDIDATE',
                        correlatedReports: [
                            {
                                reportId: report.id,
                                title: report.title,
                                source: report.source,
                                similarityScore: 0.95,
                                attackVariant: variant,
                                vulnerabilityClass: report.vulnerabilityClass,
                                exploitMechanism: report.exploitMechanism,
                                referenceUrl: report.referenceUrl
                            }
                        ],
                        remediation: {
                            explanation: report.mitigation
                        },
                        timestamp: new Date().toISOString()
                    });
                }
            }
        }
    }
    detectAttackSurfaces(absPath, relPath, content, surfaces) {
        // HTTP Endpoints (Express / Next.js / Fastify)
        const routeRegex = /(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]/g;
        let match;
        while ((match = routeRegex.exec(content)) !== null) {
            surfaces.push({
                type: 'HTTP_API',
                identifier: `${match[1].toUpperCase()} ${match[2]}`,
                location: {
                    filePath: relPath,
                    lineStart: 1,
                    lineEnd: 1,
                    snippet: match[0]
                },
                authRequired: /auth|protect|verify|jwt/i.test(match[0])
            });
        }
        // AI Prompt Handlers & Agents
        if (/(?:generateContent|chatCompletion|anthropic\.messages|openai\.chat|define_subagent|invoke_subagent)/i.test(content)) {
            surfaces.push({
                type: 'AI_PROMPT_INPUT',
                identifier: `LLM/Agent Interface in ${path.basename(relPath)}`,
                location: { filePath: relPath, lineStart: 1, lineEnd: 1, snippet: 'LLM Generation / Agent Invocation' },
                authRequired: false,
                notes: 'Processes external context through generative or autonomous agent models'
            });
        }
        // Solana & Smart Contract Entrypoints
        if (/#\[program\]|pub\s+fn\s+[a-z0-9_]+\s*\(ctx:\s*Context</i.test(content)) {
            surfaces.push({
                type: 'SMART_CONTRACT',
                identifier: `Solana Instruction Handler in ${path.basename(relPath)}`,
                location: { filePath: relPath, lineStart: 1, lineEnd: 1, snippet: 'Anchor Program Instruction' },
                authRequired: /is_signer|Signer/i.test(content),
                notes: 'Publicly reachable blockchain transaction instruction'
            });
        }
    }
    collectFiles(dir, ignoreSet) {
        const results = [];
        if (!fs.existsSync(dir))
            return results;
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
            if (ignoreSet.has(entry.name) || entry.name.startsWith('.')) {
                continue;
            }
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                results.push(...this.collectFiles(full, ignoreSet));
            }
            else if (entry.isFile()) {
                if (entry.name.endsWith('-report.html') || entry.name.endsWith('.log'))
                    continue;
                results.push(full);
            }
        }
        return results;
    }
}
//# sourceMappingURL=sastScanner.js.map