import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, } from '@modelcontextprotocol/sdk/types.js';
import { SastScanner } from '../analyzers/sastScanner.js';
import { AdversarialVerifier } from '../core/adversarialVerifier.js';
import { ReportGenerator } from '../core/reportGenerator.js';
import { ThreatKnowledgeBase } from '../intelligence/threatKnowledgeBase.js';
import { ReportIngester } from '../intelligence/reportIngester.js';
import { PatchEngine } from '../core/patchEngine.js';
import { VulnerabilityExplainer } from '../core/vulnerabilityExplainer.js';
import { SkillExporter } from '../core/skillExporter.js';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const auditRoot = path.resolve(__dirname, '../../');
const auditBin = path.join(auditRoot, 'bin', 'hexora.js');
export async function startMcpServer() {
    const server = new Server({
        name: 'hexora-mcp',
        version: '1.1.0',
    }, {
        capabilities: {
            tools: {},
        },
    });
    const kb = ThreatKnowledgeBase.getInstance();
    const ingester = new ReportIngester(kb);
    server.setRequestHandler(ListToolsRequestSchema, async () => {
        return {
            tools: [
                {
                    name: 'scan_project',
                    description: 'Universal security scan on a project directory. Analyzes secrets, vulnerabilities, and configs with adversarial verification.',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            targetPath: {
                                type: 'string',
                                description: 'Path to directory to scan (defaults to ".")',
                            },
                        },
                    },
                },
                {
                    name: 'audit_scan_directory',
                    description: 'Run full Hexora security scan on a codebase directory with Threat Intelligence and adversarial verification.',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            targetPath: {
                                type: 'string',
                                description: 'Absolute or relative path to the directory to audit',
                            },
                            outputDir: {
                                type: 'string',
                                description: 'Optional output directory for reports and ledgers',
                            },
                        },
                        required: ['targetPath'],
                    },
                },
                {
                    name: 'audit_scan_file',
                    description: 'Fast, targeted real-time security scan on a single file or in-memory code buffer (ideal when saving or reviewing code edits).',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            filePath: {
                                type: 'string',
                                description: 'Path to the target file to scan',
                            },
                            content: {
                                type: 'string',
                                description: 'Optional unsaved in-memory file content to audit without saving to disk',
                            },
                            targetRoot: {
                                type: 'string',
                                description: 'Optional repository or project root directory',
                            },
                        },
                        required: ['filePath'],
                    },
                },
                {
                    name: 'get_findings',
                    description: 'Query structured security findings with details, code snippets, safe PoCs, and unified patch fixes.',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            severity: {
                                type: 'string',
                                enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'ALL'],
                                description: 'Filter findings by severity level',
                            },
                            category: {
                                type: 'string',
                                description: 'Filter by category: SECRET, INJECTION, WEB3, AI_AGENT, AUTH, CONFIG, BUSINESS_LOGIC, SCA',
                            },
                            targetPath: {
                                type: 'string',
                                description: 'Directory path where audit results are stored (defaults to ".")',
                            },
                        },
                    },
                },
                {
                    name: 'apply_fix',
                    description: 'Safely apply an automated patch, unified diff, or string replacement to remediate confirmed security vulnerabilities.',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            filePath: {
                                type: 'string',
                                description: 'Target file path to modify',
                            },
                            target: {
                                type: 'string',
                                description: 'Exact original code snippet to replace',
                            },
                            replacement: {
                                type: 'string',
                                description: 'Hardened replacement code',
                            },
                            unifiedDiff: {
                                type: 'string',
                                description: 'Optional standard git unified diff string',
                            },
                            createBackup: {
                                type: 'boolean',
                                description: 'Whether to create a .bak backup file (defaults to true)',
                            },
                        },
                        required: ['filePath'],
                    },
                },
                {
                    name: 'audit_explain_vulnerability',
                    description: 'Retrieve deep architectural breakdown, root cause, real-world CVE case studies, CVSS v3.1 metrics, and secure patterns for an issue.',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            ruleId: {
                                type: 'string',
                                description: 'Vulnerability Rule ID (e.g., "SEC-001", "SOL-001", "AI-LLM-001")',
                            },
                            findingJson: {
                                type: 'string',
                                description: 'Optional JSON string of the VulnerabilityFinding object',
                            },
                        },
                        required: ['ruleId'],
                    },
                },
                {
                    name: 'audit_generate_poc',
                    description: 'Synthesize safe, non-destructive reproduction test harness (CURL, Node.js, Foundry, Anchor, or Python) to safely verify an issue.',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            findingJson: {
                                type: 'string',
                                description: 'JSON string of the VulnerabilityFinding candidate',
                            },
                            format: {
                                type: 'string',
                                enum: ['CURL', 'NODE', 'FOUNDRY', 'ANCHOR', 'PYTHON', 'AUTO'],
                                description: 'Target execution harness format (defaults to AUTO)',
                            },
                        },
                        required: ['findingJson'],
                    },
                },
                {
                    name: 'audit_get_workspace_posture',
                    description: 'Evaluate overall security health score (A+ to F), threat intelligence match coverage, and real-time posture of the workspace.',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            targetPath: {
                                type: 'string',
                                description: 'Workspace root directory (defaults to ".")',
                            },
                        },
                    },
                },
                {
                    name: 'validate_finding',
                    description: 'Adversarially challenge a candidate vulnerability to filter out false positives and synthesize verified PoC + patch.',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            findingJson: {
                                type: 'string',
                                description: 'JSON string of the VulnerabilityFinding candidate',
                            },
                        },
                        required: ['findingJson'],
                    },
                },
                {
                    name: 'audit_check_snippet',
                    description: 'Scan an isolated code snippet against Hexora SAST rules and cross-reference with historical CVEs / Threat Intelligence reports.',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            code: {
                                type: 'string',
                                description: 'Source code content to inspect',
                            },
                            filePath: {
                                type: 'string',
                                description: 'Optional file path context (e.g. "api/auth.ts")',
                            },
                            category: {
                                type: 'string',
                                description: 'Optional category (INJECTION, WEB3, AI_AGENT, SECRET, AUTH)',
                            },
                        },
                        required: ['code'],
                    },
                },
                {
                    name: 'audit_learn_report',
                    description: 'Dynamically ingest and learn a new security audit report, CVE, or incident writeup into the AI knowledge base.',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            title: {
                                type: 'string',
                                description: 'Title of the report or incident (e.g. "Wormhole Signature Bypass" or "CVE-2024-XXXX")',
                            },
                            contentOrPath: {
                                type: 'string',
                                description: 'File path to a markdown/json report, or the raw text writeup of the exploit and fix',
                            },
                            source: {
                                type: 'string',
                                enum: ['IMMUNEFI', 'CODE4RENA', 'SHERLOCK', 'NVD_CVE', 'GITHUB_ADVISORY', 'OWASP', 'CLOUDFLARE_RESEARCH', 'CUSTOM'],
                                description: 'Source of the audit report',
                            },
                            attackVariants: {
                                type: 'array',
                                items: { type: 'string' },
                                description: 'List of specific attack variants or evasion techniques used in the exploit',
                            },
                        },
                        required: ['title', 'contentOrPath'],
                    },
                },
                {
                    name: 'audit_search_knowledge',
                    description: 'Search the learned threat intelligence database for historical reports, CVEs, exploit mechanisms, and attack variants.',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            query: {
                                type: 'string',
                                description: 'Keywords to search (e.g. "reentrancy", "Solana signer", "prompt injection", "CVE-2024-34351")',
                            },
                        },
                        required: ['query'],
                    },
                },
                {
                    name: 'audit_get_threat_intel_stats',
                    description: 'Get statistics on all threat intelligence reports, attack variants, and vulnerability taxonomies learned by the engine.',
                    inputSchema: {
                        type: 'object',
                        properties: {},
                    },
                },
                {
                    name: 'audit_export_skill',
                    description: 'Export Hexora skills, guidelines, and MCP configurations directly to Antigravity, Cursor, Claude Code, Windsurf, or VS Code.',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            platform: {
                                type: 'string',
                                enum: ['ANTIGRAVITY', 'CURSOR', 'CLAUDE_CODE', 'WINDSURF', 'VSCODE', 'ALL'],
                                description: 'Target platform to integrate with',
                            },
                            workspaceDir: {
                                type: 'string',
                                description: 'Target workspace root (defaults to ".")',
                            },
                        },
                        required: ['platform'],
                    },
                },
            ],
        };
    });
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
        const { name, arguments: args } = request.params;
        if (name === 'scan_project' || name === 'audit_scan_directory') {
            const targetPath = args?.targetPath || '.';
            const resolvedTarget = path.resolve(targetPath);
            const scanner = new SastScanner();
            const verifier = new AdversarialVerifier();
            const { findings, coverage } = await scanner.scan(resolvedTarget);
            const verifiedFindings = findings.map((f) => verifier.verifyFinding(f));
            const report = ReportGenerator.buildReport(resolvedTarget, verifiedFindings, coverage);
            const outDir = path.resolve(args?.outputDir || path.join(process.cwd(), '.hexora-results'));
            if (!fs.existsSync(outDir))
                fs.mkdirSync(outDir, { recursive: true });
            const htmlContent = ReportGenerator.toHtml(report);
            const txtContent = ReportGenerator.toStructuredText(report);
            const pdfBuffer = ReportGenerator.toPdf(report);
            const mdContent = ReportGenerator.toMarkdown(report);
            fs.writeFileSync(path.join(outDir, 'audit-report.txt'), txtContent, 'utf-8');
            fs.writeFileSync(path.join(outDir, 'audit-report.pdf'), pdfBuffer);
            fs.writeFileSync(path.join(outDir, 'audit-report.md'), mdContent, 'utf-8');
            fs.writeFileSync(path.join(outDir, 'audit-report.sarif'), ReportGenerator.toSarif(report), 'utf-8');
            fs.writeFileSync(path.join(outDir, 'hexora-report.html'), htmlContent, 'utf-8');
            fs.writeFileSync(path.join(process.cwd(), 'hexora-report.txt'), txtContent, 'utf-8');
            fs.writeFileSync(path.join(process.cwd(), 'hexora-report.pdf'), pdfBuffer);
            fs.writeFileSync(path.join(process.cwd(), 'hexora-report.md'), mdContent, 'utf-8');
            fs.writeFileSync(path.join(process.cwd(), 'hexora-report.html'), htmlContent, 'utf-8');
            fs.writeFileSync(path.join(outDir, 'audit-findings.json'), JSON.stringify(verifiedFindings, null, 2), 'utf-8');
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify({
                            status: 'SCAN_COMPLETE',
                            summary: report.stats,
                            threatIntel: report.threatIntel,
                            confirmedVulnerabilities: report.stats.confirmed,
                            falsePositivesFiltered: report.stats.disproved,
                            textReport: './hexora-report.txt',
                            pdfReport: './hexora-report.pdf',
                            markdownReport: './hexora-report.md',
                            htmlReport: './hexora-report.html',
                            sarifReport: path.join(outDir, 'audit-report.sarif')
                        }, null, 2),
                    },
                ],
            };
        }
        if (name === 'audit_scan_file') {
            const filePath = args?.filePath;
            const content = args?.content;
            const targetRoot = args?.targetRoot || process.cwd();
            const absPath = path.isAbsolute(filePath) ? filePath : path.resolve(targetRoot, filePath);
            const scanner = new SastScanner();
            const verifier = new AdversarialVerifier();
            const findings = scanner.scanSingleFile(absPath, targetRoot, content);
            const verified = findings.map((f) => verifier.verifyFinding(f, content));
            const confirmed = verified.filter((f) => f.status === 'CONFIRMED');
            const disproved = verified.filter((f) => f.status === 'DISPROVED');
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify({
                            file: path.relative(targetRoot, absPath).replace(/\\/g, '/'),
                            status: confirmed.length === 0 ? 'CLEAN' : 'VULNERABILITIES_FOUND',
                            totalConfirmed: confirmed.length,
                            falsePositivesFiltered: disproved.length,
                            findings: confirmed.map((f) => ({
                                ruleId: f.ruleId,
                                title: f.title,
                                severity: f.severity,
                                category: f.category,
                                line: f.location.lineStart,
                                snippet: f.location.snippet,
                                remediation: f.remediation?.explanation || f.remediation?.unifiedDiff,
                                reproductionPoC: f.reproductionPoC,
                            })),
                        }, null, 2),
                    },
                ],
            };
        }
        if (name === 'apply_fix') {
            const filePath = args?.filePath;
            const target = args?.target;
            const replacement = args?.replacement;
            const unifiedDiff = args?.unifiedDiff;
            const createBackup = args?.createBackup !== false;
            const result = PatchEngine.apply({
                filePath,
                target,
                replacement,
                unifiedDiff,
                createBackup,
            });
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify(result, null, 2),
                    },
                ],
            };
        }
        if (name === 'audit_explain_vulnerability') {
            const ruleId = args?.ruleId;
            const findingRaw = args?.findingJson;
            let findingObj;
            if (findingRaw) {
                try {
                    findingObj = typeof findingRaw === 'string' ? JSON.parse(findingRaw) : findingRaw;
                }
                catch { }
            }
            const explanation = VulnerabilityExplainer.explain(ruleId, findingObj);
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify(explanation, null, 2),
                    },
                ],
            };
        }
        if (name === 'audit_generate_poc') {
            const findingRaw = args?.findingJson;
            const format = args?.format || 'AUTO';
            let findingObj = {};
            if (findingRaw) {
                try {
                    findingObj = typeof findingRaw === 'string' ? JSON.parse(findingRaw) : findingRaw;
                }
                catch { }
            }
            const poc = VulnerabilityExplainer.generatePoc(findingObj, format);
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify(poc, null, 2),
                    },
                ],
            };
        }
        if (name === 'audit_get_workspace_posture') {
            const targetPath = args?.targetPath || '.';
            const resolved = path.resolve(targetPath);
            const resultsDir = path.join(resolved, '.hexora-results');
            const findingsPath = path.join(resultsDir, 'audit-findings.json');
            let findingsList = [];
            if (fs.existsSync(findingsPath)) {
                try {
                    findingsList = JSON.parse(fs.readFileSync(findingsPath, 'utf-8'));
                }
                catch { }
            }
            const confirmed = findingsList.filter((f) => f.status === 'CONFIRMED');
            const critCount = confirmed.filter((f) => f.severity === 'CRITICAL').length;
            const highCount = confirmed.filter((f) => f.severity === 'HIGH').length;
            const medCount = confirmed.filter((f) => f.severity === 'MEDIUM').length;
            let score = 100 - (critCount * 30 + highCount * 15 + medCount * 5);
            if (score < 0)
                score = 0;
            let grade = 'A+';
            if (score < 60)
                grade = 'F';
            else if (score < 70)
                grade = 'D';
            else if (score < 80)
                grade = 'C';
            else if (score < 90)
                grade = 'B';
            else if (score < 98)
                grade = 'A';
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify({
                            workspace: resolved,
                            securityScore: `${score}/100`,
                            grade,
                            postureStatus: critCount > 0 ? 'CRITICAL_RISK' : highCount > 0 ? 'ELEVATED_RISK' : 'HEALTHY',
                            activeFindings: {
                                critical: critCount,
                                high: highCount,
                                medium: medCount,
                                low: confirmed.filter((f) => f.severity === 'LOW').length,
                                total: confirmed.length,
                            },
                            threatIntelStats: kb.getStats(),
                            lastScanTimestamp: fs.existsSync(findingsPath) ? fs.statSync(findingsPath).mtime.toISOString() : null,
                        }, null, 2),
                    },
                ],
            };
        }
        if (name === 'audit_export_skill') {
            const platform = (args?.platform || 'ANTIGRAVITY').toUpperCase();
            const wsDir = path.resolve(args?.workspaceDir || '.');
            const homeDir = os.homedir();
            let report;
            if (platform === 'ANTIGRAVITY') {
                report = SkillExporter.exportAntigravity(wsDir, homeDir, auditBin);
            }
            else if (platform === 'CURSOR') {
                report = SkillExporter.exportCursor(wsDir, homeDir, auditBin);
            }
            else if (platform === 'CLAUDE_CODE') {
                report = SkillExporter.exportClaudeCode(homeDir, auditBin);
            }
            else if (platform === 'WINDSURF') {
                report = SkillExporter.exportWindsurf(wsDir, homeDir, auditBin);
            }
            else if (platform === 'VSCODE') {
                report = SkillExporter.exportVsCode(wsDir, auditBin);
            }
            else {
                const agy = SkillExporter.exportAntigravity(wsDir, homeDir, auditBin);
                const cur = SkillExporter.exportCursor(wsDir, homeDir, auditBin);
                const cld = SkillExporter.exportClaudeCode(homeDir, auditBin);
                const wnd = SkillExporter.exportWindsurf(wsDir, homeDir, auditBin);
                const vsc = SkillExporter.exportVsCode(wsDir, auditBin);
                report = {
                    platform: 'ALL',
                    results: [agy, cur, cld, wnd, vsc],
                    success: true,
                };
            }
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify(report, null, 2),
                    },
                ],
            };
        }
        if (name === 'get_findings') {
            const targetPath = args?.targetPath || '.';
            const severityFilter = args?.severity;
            const categoryFilter = args?.category;
            let outDir = path.resolve(path.join(process.cwd(), '.hexora-results'));
            const findingsFile = path.join(outDir, 'audit-findings.json');
            let findingsList = [];
            if (fs.existsSync(findingsFile)) {
                try {
                    findingsList = JSON.parse(fs.readFileSync(findingsFile, 'utf-8'));
                }
                catch { }
            }
            let filtered = findingsList.filter((f) => f.status === 'CONFIRMED');
            if (severityFilter && severityFilter !== 'ALL') {
                filtered = filtered.filter((f) => f.severity === severityFilter);
            }
            if (categoryFilter) {
                filtered = filtered.filter((f) => f.category === categoryFilter);
            }
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify({
                            total: filtered.length,
                            findings: filtered.map((f) => ({
                                ruleId: f.ruleId,
                                title: f.title,
                                severity: f.severity,
                                category: f.category,
                                location: `${f.location.filePath}:${f.location.lineStart}`,
                                description: f.description,
                                snippet: f.location.snippet,
                                reproductionPoC: f.reproductionPoC,
                                suggestedFix: f.remediation?.unifiedDiff || f.remediation?.explanation,
                                adversarialVerdict: f.adversarialVerification?.verdict
                            }))
                        }, null, 2),
                    },
                ],
            };
        }
        if (name === 'validate_finding' || name === 'audit_verify_candidate') {
            const findingRaw = args?.findingJson;
            try {
                const findingObj = typeof findingRaw === 'string' ? JSON.parse(findingRaw) : findingRaw;
                const verifier = new AdversarialVerifier();
                const verified = verifier.verifyFinding(findingObj);
                return {
                    content: [
                        {
                            type: 'text',
                            text: JSON.stringify(verified, null, 2),
                        },
                    ],
                };
            }
            catch (err) {
                return {
                    content: [{ type: 'text', text: `Failed to parse or verify finding: ${err.message}` }],
                    isError: true,
                };
            }
        }
        if (name === 'audit_check_snippet') {
            const code = args?.code || '';
            const filePath = args?.filePath || 'snippet.ts';
            const category = args?.category;
            const threatMatches = kb.matchThreats(code, filePath, category);
            const isDangerous = threatMatches.length > 0;
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify({
                            analyzedSnippetLength: code.length,
                            hasThreatCorrelations: isDangerous,
                            matchedReports: threatMatches,
                            verdict: isDangerous ? 'SUSPICIOUS_OR_VULNERABLE' : 'CLEAN',
                            recommendedRemediation: threatMatches[0]?.exploitMechanism || 'Follow standard input validation.',
                        }, null, 2),
                    },
                ],
            };
        }
        if (name === 'audit_learn_report') {
            const title = args?.title;
            const contentOrPath = args?.contentOrPath;
            const source = args?.source || 'CUSTOM';
            const attackVariants = args?.attackVariants || [];
            let learnedReport;
            if (contentOrPath.endsWith('.md') || contentOrPath.endsWith('.json')) {
                learnedReport = await ingester.ingestFile(contentOrPath);
            }
            else {
                learnedReport = await ingester.ingestRawText(title, contentOrPath, {
                    source,
                    attackVariants,
                });
            }
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify({
                            status: 'SUCCESS_LEARNED',
                            reportId: learnedReport.id,
                            title: learnedReport.title,
                            category: learnedReport.category,
                            totalVariantsLearned: learnedReport.attackVariants.length,
                            variants: learnedReport.attackVariants,
                        }, null, 2),
                    },
                ],
            };
        }
        if (name === 'audit_search_knowledge') {
            const query = args?.query || '';
            const results = kb.searchReports(query);
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify({
                            query,
                            matchCount: results.length,
                            reports: results.map((r) => ({
                                id: r.id,
                                title: r.title,
                                source: r.source,
                                severity: r.severity,
                                vulnerabilityClass: r.vulnerabilityClass,
                                attackVariants: r.attackVariants,
                                mitigation: r.mitigation,
                                referenceUrl: r.referenceUrl,
                            })),
                        }, null, 2),
                    },
                ],
            };
        }
        if (name === 'audit_get_threat_intel_stats') {
            const stats = kb.getStats();
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify(stats, null, 2),
                    },
                ],
            };
        }
        throw new Error(`Unknown tool: ${name}`);
    });
    const transport = new StdioServerTransport();
    await server.connect(transport);
}
//# sourceMappingURL=server.js.map