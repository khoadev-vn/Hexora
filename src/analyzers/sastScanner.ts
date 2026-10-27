import fs from 'node:fs';
import path from 'node:path';
import { BUILTIN_RULES } from '../rules/ruleDatabase.js';
import { VulnerabilityFinding, CoverageLedger, SASTRule, AttackSurfaceEntry } from '../types/index.js';
import { ThreatKnowledgeBase } from '../intelligence/threatKnowledgeBase.js';
import { BusinessLogicAnalyzer } from './businessLogicAnalyzer.js';
import { ZeroDaySyncEngine } from '../intelligence/zeroDaySyncEngine.js';
import { ScaScanner } from './scaScanner.js';

export interface ScannerOptions {
  targetDir: string;
  customRules?: SASTRule[];
  ignoreDirs?: string[];
  maxFileSizeKb?: number;
}

export class SastScanner {
  private rules: SASTRule[];
  private ignoreDirs: Set<string>;
  private maxFileSizeBytes: number;
  private threatKb: ThreatKnowledgeBase;
  private businessLogicAnalyzer: BusinessLogicAnalyzer;
  private scaScanner: ScaScanner;

  constructor(options: Partial<ScannerOptions> = {}) {
    this.rules = options.customRules || BUILTIN_RULES;
    this.ignoreDirs = new Set([
      'node_modules',
      '.git',
      'dist',
      'build',
      'out',
      'coverage',
      '.next',
      '.nuxt',
      '.turbo',
      'venv',
      '.venv',
      'env',
      '__pycache__',
      '.benchmark_workspace',
      '.hexora-results',
      'reports',
      'AppData',
      '.cache',
      '.local',
      '.vscode',
      '.idea',
      'vendor',
      'target',
      '.cargo',
      '.rustup',
      '.gradle',
      ...(options.ignoreDirs || [])
    ]);
    this.maxFileSizeBytes = (options.maxFileSizeKb || 1024) * 1024;
    this.threatKb = ThreatKnowledgeBase.getInstance();
    this.businessLogicAnalyzer = new BusinessLogicAnalyzer();
    this.scaScanner = new ScaScanner();
  }

  public async scan(
    targetDir: string,
    onProgress?: (scannedFiles: number, totalFiles: number, currentFile: string) => void
  ): Promise<{ findings: VulnerabilityFinding[]; coverage: CoverageLedger }> {
    const resolvedRoot = path.resolve(targetDir);
    const analyzedFiles: string[] = [];
    const skippedFiles: { path: string; reason: string }[] = [];
    const attackSurfaces: AttackSurfaceEntry[] = [];
    const findings: VulnerabilityFinding[] = [];

    const allFiles = this.collectFiles(resolvedRoot, this.ignoreDirs);
    const totalFiles = allFiles.length;

    for (let i = 0; i < totalFiles; i++) {
      const filePath = allFiles[i];
      const relPath = path.relative(resolvedRoot, filePath).replace(/\\/g, '/');

      if (onProgress && (i % 5 === 0 || i === totalFiles - 1)) {
        onProgress(i + 1, totalFiles, relPath);
      }

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

        const dynamicRules = ZeroDaySyncEngine.getInstance().getDynamicRules();
        const activeRules = [...this.rules, ...dynamicRules];

        for (const rule of activeRules) {
          if (rule.languages.includes(ext) || rule.languages.includes('*')) {
            this.evaluateRule(rule, filePath, relPath, content, findings);
          }
        }

        // 3. Evaluate Direct Threat Report & Attack Variant Signatures
        this.evaluateThreatIntelCorrelations(filePath, relPath, content, findings);

        // 4. Semantic Business Logic & IDOR / BOLA Analysis
        if (['js', 'ts', 'jsx', 'tsx', 'py'].includes(ext)) {
          const bizFindings = this.businessLogicAnalyzer.analyze(relPath, content);
          for (const bf of bizFindings) {
            findings.push(bf);
          }
        }
      } catch (err: any) {
        skippedFiles.push({ path: relPath, reason: `Read error: ${err.message}` });
      }
    }

    // 5. Software Composition Analysis (SCA) - Manifest Dependency & Plugin Auditing
    try {
      const scaFindings = await this.scaScanner.scanProject(resolvedRoot);
      for (const sf of scaFindings) {
        findings.push(sf);
      }
    } catch {
      // Gracefully continue
    }

    const coverage: CoverageLedger = {
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

  public scanSingleFile(filePath: string, rootDir: string = path.dirname(filePath), contentOverride?: string): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];
    try {
      const relPath = path.relative(rootDir, filePath).replace(/\\/g, '/');
      const ext = path.extname(filePath).slice(1).toLowerCase();
      const isSourceFile = ['js', 'ts', 'jsx', 'tsx', 'py', 'sol', 'rs', 'go', 'php', 'java', 'c', 'cpp', 'html', 'vue', 'svelte', 'json', 'env'].includes(ext);
      if (!isSourceFile && !contentOverride) return [];

      const content = contentOverride !== undefined ? contentOverride : fs.readFileSync(filePath, 'utf-8');
      const dynamicRules = ZeroDaySyncEngine.getInstance().getDynamicRules();
      const activeRules = [...this.rules, ...dynamicRules];

      for (const rule of activeRules) {
        if (rule.languages.includes(ext) || rule.languages.includes('*')) {
          this.evaluateRule(rule, filePath, relPath, content, findings);
        }
      }
      this.evaluateThreatIntelCorrelations(filePath, relPath, content, findings);

      if (['js', 'ts', 'jsx', 'tsx', 'py'].includes(ext)) {
        const bizFindings = this.businessLogicAnalyzer.analyze(relPath, content);
        for (const bf of bizFindings) {
          findings.push(bf);
        }
      }

      // Manifest dependency check
      const baseName = path.basename(filePath).toLowerCase();
      const isManifest = ['package.json', 'package-lock.json', 'requirements.txt', 'cargo.toml', 'go.mod', 'pom.xml', 'composer.json'].includes(baseName);
      if (isManifest) {
        const scaFindings = this.scaScanner.scanManifestFileSync(filePath, relPath, content);
        for (const sf of scaFindings) {
          findings.push(sf);
        }
      }
    } catch {
      // Ignore read errors
    }
    return findings;
  }

  private evaluateRule(
    rule: SASTRule,
    absPath: string,
    relPath: string,
    content: string,
    findings: VulnerabilityFinding[]
  ): void {
    const lines = content.split('\n');
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g');

    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      if (rule.id !== 'HEX-DEBUG-001' && this.isIndexInsideComment(content, match.index)) {
        continue;
      }

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
  private evaluateThreatIntelCorrelations(
    absPath: string,
    relPath: string,
    content: string,
    findings: VulnerabilityFinding[]
  ): void {
    const reports = this.threatKb.getAllReports();
    const lines = content.split('\n');

    for (const report of reports) {
      for (let pIdx = 0; pIdx < report.triggerPatterns.length; pIdx++) {
        const patternStr = report.triggerPatterns[pIdx];
        let reg: RegExp;
        try {
          reg = new RegExp(patternStr, 'g');
        } catch {
          continue;
        }

        let match: RegExpExecArray | null;
        while ((match = reg.exec(content)) !== null) {
          if (this.isIndexInsideComment(content, match.index)) {
            continue;
          }

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

          const alreadyReported = findings.some(
            (f) => f.location.filePath === relPath && Math.abs(f.location.lineStart - lineStart) <= 1
          );

          if (alreadyReported) {
            // Enrich existing finding with this threat report correlation
            const existing = findings.find(
              (f) => f.location.filePath === relPath && Math.abs(f.location.lineStart - lineStart) <= 1
            );
            if (existing) {
              if (!existing.correlatedReports) existing.correlatedReports = [];
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

  private detectAttackSurfaces(absPath: string, relPath: string, content: string, surfaces: AttackSurfaceEntry[]): void {
    // HTTP Endpoints (Express / Next.js / Fastify)
    const routeRegex = /(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]/g;
    let match: RegExpExecArray | null;
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

  private collectFiles(dir: string, ignoreSet: Set<string>): string[] {
    const results: string[] = [];
    if (!fs.existsSync(dir)) return results;

    const visitedPaths = new Set<string>();
    const stack: { dirPath: string; depth: number }[] = [{ dirPath: path.resolve(dir), depth: 0 }];
    const maxDepth = 20;
    const maxFiles = 30000;

    visitedPaths.add(path.resolve(dir));

    while (stack.length > 0) {
      if (results.length >= maxFiles) break;

      const current = stack.pop()!;
      if (current.depth > maxDepth) continue;

      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(current.dirPath, { withFileTypes: true });
      } catch {
        continue;
      }

      for (const entry of entries) {
        const name = entry.name;
        if (ignoreSet.has(name) || name.startsWith('.') || name.startsWith('~')) {
          continue;
        }

        const full = path.join(current.dirPath, name);

        let isDir = false;
        let isFile = false;

        try {
          if (entry.isSymbolicLink()) {
            const real = fs.realpathSync(full);
            if (visitedPaths.has(real)) continue;
            visitedPaths.add(real);

            const stat = fs.statSync(full);
            isDir = stat.isDirectory();
            isFile = stat.isFile();
          } else {
            isDir = entry.isDirectory();
            isFile = entry.isFile();
          }
        } catch {
          continue;
        }

        if (isDir) {
          if (!visitedPaths.has(full)) {
            visitedPaths.add(full);
            stack.push({ dirPath: full, depth: current.depth + 1 });
          }
        } else if (isFile) {
          const dotIdx = name.lastIndexOf('.');
          if (dotIdx !== -1) {
            const ext = name.slice(dotIdx + 1).toLowerCase();
            const IGNORED_EXTS = new Set([
              'png', 'jpg', 'jpeg', 'gif', 'bmp', 'ico', 'svg', 'webp', 'mp4', 'webm', 'mov', 'mp3', 'wav',
              'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
              'zip', 'tar', 'gz', 'tgz', '7z', 'rar', 'iso',
              'woff', 'woff2', 'ttf', 'eot', 'otf',
              'exe', 'dll', 'so', 'dylib', 'bin', 'class', 'jar', 'pyc', 'wasm',
              'map', 'lock'
            ]);
            if (IGNORED_EXTS.has(ext)) continue;
          }
          if (
            name.endsWith('-report.html') ||
            name.endsWith('-report.txt') ||
            name.endsWith('-report.pdf') ||
            name.endsWith('.log') ||
            name.endsWith('.lock') ||
            name.endsWith('.min.js') ||
            name.endsWith('.bundle.js')
          ) {
            continue;
          }
          results.push(full);
          if (results.length >= maxFiles) break;
        }
      }
    }

    return results;
  }

  private isIndexInsideComment(content: string, index: number): boolean {
    const lastNewline = content.lastIndexOf('\n', index);
    const linePrefix = content.slice(lastNewline + 1, index);
    const trimmedPrefix = linePrefix.trimStart();

    // Single-line comment starts
    if (
      trimmedPrefix.startsWith('//') ||
      trimmedPrefix.startsWith('*') ||
      trimmedPrefix.startsWith('/*') ||
      trimmedPrefix.startsWith('#') ||
      trimmedPrefix.startsWith('<!--')
    ) {
      return true;
    }

    // Line has // before index and not inside string quotes
    const doubleSlash = linePrefix.indexOf('//');
    if (doubleSlash !== -1) {
      const beforeSlash = linePrefix.slice(0, doubleSlash);
      const singleQuotes = (beforeSlash.match(/'/g) || []).length;
      const doubleQuotes = (beforeSlash.match(/"/g) || []).length;
      const backticks = (beforeSlash.match(/`/g) || []).length;
      if (singleQuotes % 2 === 0 && doubleQuotes % 2 === 0 && backticks % 2 === 0) {
        return true;
      }
    }

    // Inside block comment /* ... */
    const lastBlockStart = content.lastIndexOf('/*', index);
    if (lastBlockStart !== -1) {
      const lastBlockEnd = content.lastIndexOf('*/', index);
      if (lastBlockEnd < lastBlockStart) {
        return true;
      }
    }

    // Inside HTML comment <!-- ... -->
    const lastHtmlStart = content.lastIndexOf('<!--', index);
    if (lastHtmlStart !== -1) {
      const lastHtmlEnd = content.lastIndexOf('-->', index);
      if (lastHtmlEnd < lastHtmlStart) {
        return true;
      }
    }

    return false;
  }
}
