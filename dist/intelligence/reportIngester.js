import fs from 'node:fs';
import path from 'node:path';
import { ThreatKnowledgeBase } from './threatKnowledgeBase.js';
export class ReportIngester {
    kb;
    constructor(kb) {
        this.kb = kb || ThreatKnowledgeBase.getInstance();
    }
    /**
     * Ingests a report from a file path (Markdown or JSON)
     */
    async ingestFile(filePath) {
        const absPath = path.resolve(filePath);
        if (!fs.existsSync(absPath)) {
            throw new Error(`Report file not found: ${absPath}`);
        }
        const content = fs.readFileSync(absPath, 'utf-8');
        const ext = path.extname(absPath).toLowerCase();
        let report;
        if (ext === '.json') {
            report = this.parseJsonReport(content);
        }
        else {
            report = this.parseMarkdownReport(content, path.basename(absPath, ext));
        }
        await this.kb.learnReport(report);
        return report;
    }
    /**
     * Ingests all reports from a folder
     */
    async ingestDirectory(dirPath) {
        const absDir = path.resolve(dirPath);
        if (!fs.existsSync(absDir))
            return [];
        const files = fs.readdirSync(absDir);
        const learned = [];
        for (const f of files) {
            const full = path.join(absDir, f);
            const stat = fs.statSync(full);
            if (stat.isFile() && (f.endsWith('.md') || f.endsWith('.json'))) {
                try {
                    const rep = await this.ingestFile(full);
                    learned.push(rep);
                }
                catch (err) {
                    console.warn(`Skipping unparseable report ${f}: ${err.message}`);
                }
            }
        }
        return learned;
    }
    /**
     * Ingests an ad-hoc unstructured or structured writeup text
     */
    async ingestRawText(title, text, options = {}) {
        const report = this.parseMarkdownReport(text, title);
        if (options.source)
            report.source = options.source;
        if (options.severity)
            report.severity = options.severity;
        if (options.category)
            report.category = options.category;
        if (options.attackVariants && options.attackVariants.length > 0) {
            report.attackVariants = options.attackVariants;
        }
        await this.kb.learnReport(report);
        return report;
    }
    parseJsonReport(content) {
        const parsed = JSON.parse(content);
        if (!parsed.title || !parsed.id) {
            throw new Error('Invalid JSON report schema: "id" and "title" are required.');
        }
        return {
            id: parsed.id,
            title: parsed.title,
            source: parsed.source || 'CUSTOM',
            date: parsed.date || new Date().toISOString().split('T')[0],
            severity: (parsed.severity || 'HIGH').toUpperCase(),
            category: parsed.category || 'INJECTION',
            targetEcosystem: parsed.targetEcosystem || 'GENERAL',
            vulnerabilityClass: parsed.vulnerabilityClass || parsed.title,
            attackVariants: Array.isArray(parsed.attackVariants) ? parsed.attackVariants : [parsed.title],
            triggerPatterns: Array.isArray(parsed.triggerPatterns) ? parsed.triggerPatterns : [parsed.id],
            summary: parsed.summary || parsed.description || '',
            exploitMechanism: parsed.exploitMechanism || parsed.poc || 'See report details.',
            mitigation: parsed.mitigation || parsed.remediation || 'Apply input validation and least privilege.',
            referenceUrl: parsed.referenceUrl || parsed.url
        };
    }
    parseMarkdownReport(content, defaultTitle) {
        const lines = content.split('\n');
        let title = defaultTitle;
        let severity = 'HIGH';
        let id = `REP-${Date.now().toString(36).toUpperCase()}`;
        const variants = [];
        const triggerPatterns = [];
        let summary = '';
        let exploitMechanism = '';
        let mitigation = '';
        // Simple markdown heuristic parsing
        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('# ')) {
                title = trimmed.replace(/^#\s+/, '').trim();
            }
            else if (/cve-\d{4}-\d+/i.test(trimmed)) {
                const cveMatch = trimmed.match(/cve-\d{4}-\d+/i);
                if (cveMatch)
                    id = cveMatch[0].toUpperCase();
            }
            else if (/severity\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW)/i.test(trimmed)) {
                const m = trimmed.match(/severity\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW)/i);
                if (m)
                    severity = m[1].toUpperCase();
            }
            else if (trimmed.startsWith('- Variant:') || trimmed.startsWith('* Variant:') || trimmed.startsWith('- Biến thể:')) {
                variants.push(trimmed.replace(/^[-*]\s*(?:Variant|Biến thể):\s*/i, ''));
            }
            else if (trimmed.startsWith('```') && !trimmed.startsWith('```markdown')) {
                // Code block indicator, could be signature pattern
                const code = trimmed.replace(/```[a-z]*/i, '').trim();
                if (code.length > 5)
                    triggerPatterns.push(code);
            }
        }
        if (variants.length === 0) {
            variants.push(`Attack Vector from ${title}`);
        }
        // Extract basic summary if available
        summary = lines.slice(0, 10).join(' ').slice(0, 300);
        exploitMechanism = `Derived from writeup: ${title}`;
        mitigation = 'Sanitize inputs, implement defense-in-depth, and verify trust boundaries.';
        return {
            id,
            title,
            source: 'CUSTOM',
            date: new Date().toISOString().split('T')[0],
            severity,
            category: /sol|web3|contract|token|anchor/i.test(title) ? 'WEB3' : /llm|prompt|agent|ai/i.test(title) ? 'AI_AGENT' : 'INJECTION',
            targetEcosystem: /sol/i.test(title) ? 'WEB3_SOLANA' : /llm|agent/i.test(title) ? 'AI_AGENT' : 'WEB2',
            vulnerabilityClass: title,
            attackVariants: variants,
            triggerPatterns: triggerPatterns.length > 0 ? triggerPatterns : [title.split(' ')[0]],
            summary,
            exploitMechanism,
            mitigation
        };
    }
}
//# sourceMappingURL=reportIngester.js.map