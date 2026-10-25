import fs from 'node:fs';
import path from 'node:path';
import { SastScanner } from '../analyzers/sastScanner.js';
import { AdversarialVerifier } from '../core/adversarialVerifier.js';

export function startWatchMode(targetDir: string = '.') {
  const resolvedDir = path.resolve(targetDir);
  const scanner = new SastScanner();
  const verifier = new AdversarialVerifier();

  console.log(`\n======================================================`);
  console.log(`👁️  HEXORA REAL-TIME WATCH ENGINE`);
  console.log(`   Monitoring: ${resolvedDir}`);
  console.log(`   Auto-scans and verifies code on every save (Ctrl+S)`);
  console.log(`======================================================\n`);
  console.log(`⚡ Watcher active! Listening for file changes... (Press Ctrl+C to stop)\n`);

  const ignoreList = ['node_modules', '.git', 'dist', 'build', '.hexora-results', '.next', '.turbo', 'coverage'];
  const debounceTimers = new Map<string, NodeJS.Timeout>();

  const supportedExts = new Set(['.ts', '.js', '.jsx', '.tsx', '.py', '.sol', '.rs', '.go', '.php', '.java', '.c', '.cpp', '.html', '.env']);

  try {
    fs.watch(resolvedDir, { recursive: true }, (eventType, filename) => {
      if (!filename) return;

      const fullPath = path.join(resolvedDir, filename);
      const ext = path.extname(filename).toLowerCase();

      // Check if ignored or unsupported
      for (const ign of ignoreList) {
        if (filename.includes(ign)) return;
      }

      if (!supportedExts.has(ext)) return;

      // Debounce to avoid multi-fire on save
      if (debounceTimers.has(fullPath)) {
        clearTimeout(debounceTimers.get(fullPath)!);
      }

      const timer = setTimeout(() => {
        debounceTimers.delete(fullPath);
        if (!fs.existsSync(fullPath)) return;

        const timeStr = new Date().toLocaleTimeString();
        const start = performance.now();
        const rawFindings = scanner.scanSingleFile(fullPath, resolvedDir);
        const verified = rawFindings.map((f) => verifier.verifyFinding(f));
        const confirmed = verified.filter((f) => f.status === 'CONFIRMED');
        const elapsed = (performance.now() - start).toFixed(1);

        if (confirmed.length === 0) {
          console.log(`[${timeStr}] 🟢 CLEAN: ${filename} (0 issues, ${elapsed}ms)`);
        } else {
          process.stdout.write('\x07'); // Console beep alert
          console.log(`\n------------------------------------------------------`);
          console.log(`[${timeStr}] 🚨 SECURITY ALERT: ${filename} (${elapsed}ms)`);
          console.log(`Found ${confirmed.length} genuine vulnerability(ies):`);
          for (const f of confirmed) {
            const sevBadge = f.severity === 'CRITICAL' ? '🔴 CRITICAL' : f.severity === 'HIGH' ? '🟠 HIGH' : '🟡 MEDIUM';
            console.log(`\n  ${sevBadge} | ${f.title} (Line ${f.location.lineStart}) [${f.cwe || 'CWE'}]`);
            console.log(`  Target: ${f.location.filePath}:${f.location.lineStart}`);
            if (f.remediation) {
              console.log(`  💡 Suggested Fix: ${f.remediation.explanation}`);
            }
          }
          console.log(`------------------------------------------------------\n`);
        }
      }, 250);

      debounceTimers.set(fullPath, timer);
    });
  } catch (err: any) {
    console.error(`❌ Watcher error: ${err.message}`);
  }
}
