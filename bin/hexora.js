#!/usr/bin/env node

import path from 'node:path';
import { runScan, learnReport, showThreatIntel, runBenchmark, startWatchMode, runUniversalSetup, installGitHook } from '../dist/cli/index.js';
import { startMcpServer } from '../dist/mcp/server.js';

const rawArgs = process.argv.slice(2);
const isVerbose = rawArgs.includes('--verbose') || rawArgs.includes('-v');
const isNoFail = rawArgs.includes('--no-fail');
const args = rawArgs.filter((a) => a !== '--verbose' && a !== '-v' && a !== '--no-fail');

const command = args[0] || '.';

async function main() {
  if (command === 'benchmark' || command === 'bench') {
    await runBenchmark();
  } else if (command === 'watch' || command === '-w' || command === '--watch') {
    const target = args[1] || '.';
    startWatchMode(target);
  } else if (command === 'setup' || command === 'init') {
    const target = args[1];
    await runUniversalSetup({ target });
  } else if (command === 'hook' || command === 'precommit') {
    const target = args[1] || '.';
    installGitHook(target);
  } else if (command === 'mcp') {
    await startMcpServer();
  } else if (command === 'scan') {
    const target = args[1] || '.';
    const res = await runScan(target, { verbose: isVerbose, noFail: isNoFail });
    if (res?.hasCriticalOrHigh && !isNoFail) {
      process.exit(1);
    }
  } else if (command === 'learn') {
    const target = args[1];
    if (!target) {
      console.error('Error: Please provide a file or directory path containing security reports to learn.');
      process.exit(1);
    }
    await learnReport(target);
  } else if (command === 'intel' || command === 'threats') {
    showThreatIntel();
  } else if (command === '--help' || command === '-h') {
    console.log(`
🛡️  HEXORA — NEXT-GEN UNIVERSAL SECURITY ENGINE
-----------------------------------------------------------------------
Zero-Config Usage:
  npx hexora .                         Scan current directory
  npx hexora ./my-project              Scan target project folder
  npx hexora owner/repo                Scan remote GitHub repository
  npx hexora init                      1-Click setup for Cursor, Claude, VS Code & Terminal

Short Commands (after global install / npx alias):
  audit                                Scan current directory
  audit watch                          Auto-rescan on file save (Ctrl+S)
  audit setup                          Configure AI Agents & IDEs

Advanced Commands:
  npx hexora watch                     Auto-rescan on file save (Ctrl+S)
  npx hexora hook                      Install Git pre-commit security gate
  npx hexora mcp                       Start Model Context Protocol (MCP) server
  npx hexora bench                     Run global vulnerability benchmark arena
  npx hexora intel                     View learned CVEs & attack variants
  npx hexora learn <path>              Ingest CVE report or security writeup

Flags:
  --verbose, -v                        Print detailed 4-phase audit execution
  --no-fail                            Do not exit with code 1 on critical findings
-----------------------------------------------------------------------
    `);
  } else {
    // Treat first arg directly as directory or GitHub owner/repo (e.g. npx hexora .)
    const res = await runScan(command, { verbose: isVerbose, noFail: isNoFail });
    if (res?.hasCriticalOrHigh && !isNoFail) {
      process.exit(1);
    }
  }
}

main().catch((err) => {
  console.error('Hexora execution error:', err);
  process.exit(1);
});
