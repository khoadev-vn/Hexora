import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { SastScanner } from '../analyzers/sastScanner.js';
import { AdversarialVerifier } from '../core/adversarialVerifier.js';
import { ReportGenerator } from '../core/reportGenerator.js';
import { ThreatKnowledgeBase } from '../intelligence/threatKnowledgeBase.js';
import { ReportIngester } from '../intelligence/reportIngester.js';

export interface ScanOptions {
  output?: string;
  format?: string;
  verbose?: boolean;
  noFail?: boolean;
}

export async function runScan(targetInput: string = '.', options: ScanOptions = {}) {
  let isTempRepo = false;
  let root = targetInput;

  // Check if targetInput is a GitHub repo owner/repo
  const githubRepoPattern = /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/;
  if (githubRepoPattern.test(targetInput) && !fs.existsSync(path.resolve(targetInput))) {
    const tempDir = path.join(os.tmpdir(), `hexora-${Date.now()}`);
    console.log(`\n📦 Cloning remote repository https://github.com/${targetInput}.git into sandbox...`);
    try {
      const cloneRes = spawnSync('git', ['clone', '--depth', '1', `https://github.com/${targetInput}.git`, tempDir], { stdio: 'ignore' });
      if (cloneRes.status !== 0) throw new Error(`Git clone failed with code ${cloneRes.status}`);
      root = tempDir;
      isTempRepo = true;
    } catch (err: any) {
      console.error(`❌ Failed to clone repository ${targetInput}: ${err.message}`);
      process.exit(1);
    }
  } else {
    root = path.resolve(targetInput || '.');
  }

  const outDir = path.resolve(options.output || path.join(process.cwd(), '.hexora-results'));
  const txtReportPath = path.resolve(process.cwd(), 'hexora-report.txt');
  const pdfReportPath = path.resolve(process.cwd(), 'hexora-report.pdf');
  const mdReportPath = path.resolve(process.cwd(), 'hexora-report.md');
  const htmlReportPath = path.resolve(process.cwd(), 'hexora-report.html');

  if (options.verbose) {
    console.log(`\n======================================================`);
    console.log(`🛡️  HEXORA UNIVERSAL SECURITY ENGINE v1.0.0`);
    console.log(`   Auditing target: ${root}`);
    console.log(`======================================================\n`);
  } else {
    console.log(`\nHexora\n`);
    console.log(`Scanning project...`);
  }

  const kb = ThreatKnowledgeBase.getInstance(outDir);
  const scanner = new SastScanner();
  const { findings, coverage } = await scanner.scan(root);

  const verifier = new AdversarialVerifier();
  const verifiedFindings = findings.map((f) => {
    let fullContent: string | undefined;
    try {
      const fullPath = path.resolve(root, f.location.filePath);
      if (fs.existsSync(fullPath)) {
        fullContent = fs.readFileSync(fullPath, 'utf-8');
      }
    } catch {}
    return verifier.verifyFinding(f, fullContent);
  });

  const confirmedFindings = verifiedFindings.filter((f) => f.status === 'CONFIRMED');
  const disprovedCount = verifiedFindings.filter((f) => f.status === 'DISPROVED').length;

  const report = ReportGenerator.buildReport(root, verifiedFindings, coverage);

  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  const txtReport = ReportGenerator.toStructuredText(report);
  const pdfBuffer = ReportGenerator.toPdf(report);
  const mdReport = ReportGenerator.toMarkdown(report);
  const sarifReport = ReportGenerator.toSarif(report);
  const htmlReport = ReportGenerator.toHtml(report);

  // Save to target results dir
  fs.writeFileSync(path.join(outDir, 'audit-report.txt'), txtReport, 'utf-8');
  fs.writeFileSync(path.join(outDir, 'audit-report.pdf'), pdfBuffer);
  fs.writeFileSync(path.join(outDir, 'audit-report.md'), mdReport, 'utf-8');
  fs.writeFileSync(path.join(outDir, 'audit-report.sarif'), sarifReport, 'utf-8');
  fs.writeFileSync(path.join(outDir, 'hexora-report.html'), htmlReport, 'utf-8');
  fs.writeFileSync(path.join(outDir, 'audit-coverage.json'), JSON.stringify(coverage, null, 2), 'utf-8');
  fs.writeFileSync(path.join(outDir, 'audit-findings.json'), JSON.stringify(verifiedFindings, null, 2), 'utf-8');

  // Also save key executive reports directly to workspace root for instant access
  fs.writeFileSync(txtReportPath, txtReport, 'utf-8');
  fs.writeFileSync(pdfReportPath, pdfBuffer);
  fs.writeFileSync(mdReportPath, mdReport, 'utf-8');
  fs.writeFileSync(htmlReportPath, htmlReport, 'utf-8');

  // Categorize findings for clear high-level display
  const secretsCount = confirmedFindings.filter((f) => f.category === 'SECRET').length;
  const secVulnsCount = confirmedFindings.filter((f) => ['INJECTION', 'WEB3', 'AI_AGENT', 'AUTH', 'BUSINESS_LOGIC'].includes(f.category)).length;
  const depVulnsCount = confirmedFindings.filter((f) => f.category === 'DEPENDENCY' || f.category === 'SCA').length;
  const configCount = confirmedFindings.filter((f) => !['SECRET', 'INJECTION', 'WEB3', 'AI_AGENT', 'AUTH', 'BUSINESS_LOGIC', 'DEPENDENCY', 'SCA'].includes(f.category)).length;

  const totalConfirmed = confirmedFindings.length;

  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
  console.log(`Secrets                  ${secretsCount} findings`);
  console.log(`Security vulnerabilities ${secVulnsCount} findings`);
  console.log(`Vulnerable dependencies  ${depVulnsCount} findings`);
  console.log(`Insecure configuration   ${configCount} findings\n`);
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(`${totalConfirmed} findings detected (Adversarial filtered ${disprovedCount} false positives)\n`);
  console.log(`Critical: ${report.stats.bySeverity.CRITICAL}`);
  console.log(`High:     ${report.stats.bySeverity.HIGH}`);
  console.log(`Medium:   ${report.stats.bySeverity.MEDIUM}`);
  console.log(`Low:      ${report.stats.bySeverity.LOW + report.stats.bySeverity.INFO}\n`);
  console.log(`Report:`);
  console.log(`  📄 Text (Structured): ./hexora-report.txt`);
  console.log(`  📑 PDF (Executive):   ./hexora-report.pdf`);
  console.log(`  📝 Markdown:          ./hexora-report.md`);
  console.log(`  🌐 HTML Dashboard:    ./hexora-report.html`);
  if (options.verbose) {
    console.log(`\nDetailed Archive: ${outDir}`);
    console.log(`SARIF:  ${path.join(outDir, 'audit-report.sarif')}`);
  }
  console.log(`\n`);

  // Clean up temp repo if needed
  if (isTempRepo) {
    try {
      fs.rmSync(root, { recursive: true, force: true });
    } catch {}
  }

  // Proper exit code for CI/CD automation
  const hasCriticalOrHigh = report.stats.bySeverity.CRITICAL > 0 || report.stats.bySeverity.HIGH > 0;
  return { report, hasCriticalOrHigh };
}

export async function learnReport(targetPath: string) {
  const ingester = new ReportIngester();
  console.log(`\n📚 [Hexora Threat Ingestion] Processing: ${targetPath}...`);

  const stat = fs.statSync(targetPath);
  if (stat.isDirectory()) {
    const learned = await ingester.ingestDirectory(targetPath);
    console.log(`✨ Successfully ingested ${learned.length} security reports into knowledge base!`);
  } else {
    const rep = await ingester.ingestFile(targetPath);
    console.log(`✨ Successfully ingested report: [${rep.id}] "${rep.title}"`);
    console.log(`   - Attack Variants learned: ${rep.attackVariants.join(', ')}`);
    console.log(`   - Mitigation: ${rep.mitigation}`);
  }
}

export function showThreatIntel() {
  const kb = ThreatKnowledgeBase.getInstance();
  const stats = kb.getStats();
  const reports = kb.getAllReports();

  console.log(`\n======================================================`);
  console.log(`🧠 HEXORA THREAT INTELLIGENCE KNOWLEDGE VAULT`);
  console.log(`======================================================`);
  console.log(`Total Reports Learned: ${stats.totalLearnedReports}`);
  console.log(`Total Attack Variants: ${stats.totalAttackVariants}\n`);

  for (const r of reports) {
    console.log(`📌 [${r.source}] ${r.id}: ${r.title} (${r.severity})`);
    console.log(`   - Ecosystem: ${r.targetEcosystem} | Class: ${r.vulnerabilityClass}`);
    console.log(`   - Attack Variants: ${r.attackVariants.slice(0, 2).join('; ')}`);
    console.log(``);
  }
}

export async function runBenchmark() {
  const { BenchmarkRunner } = await import('../benchmark/benchmarkRunner.js');
  const runner = new BenchmarkRunner();
  return await runner.runFullBenchmarkSuite();
}

export { startWatchMode } from './watch.js';
export { runUniversalSetup, installGitHook, runSkillCommand } from './setup.js';
export { openInteractiveMenu } from './menu.js';


