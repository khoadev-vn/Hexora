import fs from 'node:fs';
import path from 'node:path';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, } from '@modelcontextprotocol/sdk/types.js';
import { SastScanner } from '../analyzers/sastScanner.js';
import { AdversarialVerifier } from '../core/adversarialVerifier.js';
import { ReportGenerator } from '../core/reportGenerator.js';
import { ThreatKnowledgeBase } from '../intelligence/threatKnowledgeBase.js';
import { ReportIngester } from '../intelligence/reportIngester.js';
export async function startMcpServer() {
    const server = new Server({
        name: 'hexora-mcp',
        version: '1.0.0',
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
                                description: 'Filter by category: SECRET, INJECTION, WEB3, AI_AGENT, AUTH, CONFIG',
                            },
                            targetPath: {
                                type: 'string',
                                description: 'Directory path where audit results are stored (defaults to ".")',
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
                    name: 'audit_verify_candidate',
                    description: 'Adversarially challenge a vulnerability candidate to filter out false positives and generate safe PoC + minimal diff fix.',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            findingJson: {
                                type: 'string',
                                description: 'JSON string of the VulnerabilityFinding object',
                            },
                        },
                        required: ['findingJson'],
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
        if (name === 'get_findings') {
            const targetPath = args?.targetPath || '.';
            const severityFilter = args?.severity;
            const categoryFilter = args?.category;
            let outDir = path.resolve(path.join(process.cwd(), '.hexora-results'));
            if (!fs.existsSync(outDir) && fs.existsSync(path.resolve(path.join(process.cwd(), '.hexora-results')))) {
                outDir = path.resolve(path.join(process.cwd(), '.hexora-results'));
            }
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