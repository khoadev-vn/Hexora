#!/usr/bin/env node

import path from 'node:path';
import { runScan, learnReport, showThreatIntel, runBenchmark, startWatchMode, runUniversalSetup, installGitHook, runSkillCommand, openInteractiveMenu } from '../dist/cli/index.js';
import { startMcpServer } from '../dist/mcp/server.js';

const rawArgs = process.argv.slice(2);
const isVerbose = rawArgs.includes('--verbose') || rawArgs.includes('-v');
const isNoFail = rawArgs.includes('--no-fail');
const args = rawArgs.filter((a) => a !== '--verbose' && a !== '-v' && a !== '--no-fail');

const command = args[0];

async function main() {
  // If run with no arguments, or explicit 'menu'/'ui' command, open interactive menu
  if (!command || command === 'menu' || command === 'ui' || command === 'dashboard') {
    await openInteractiveMenu();
    return;
  }

  const effectiveCommand = command || '.';

  if (effectiveCommand === 'benchmark' || effectiveCommand === 'bench') {
    await runBenchmark();
  } else if (effectiveCommand === 'watch' || effectiveCommand === '-w' || effectiveCommand === '--watch') {
    const target = args[1] || '.';
    startWatchMode(target);
  } else if (effectiveCommand === 'setup' || effectiveCommand === 'init') {
    const target = args[1];
    await runUniversalSetup({ target });
  } else if (effectiveCommand === 'skill' || effectiveCommand === 'skills') {
    const platform = args[1] || 'all';
    const targetDir = args[2] || '.';
    await runSkillCommand(platform, targetDir);
  } else if (effectiveCommand === 'hook' || effectiveCommand === 'precommit') {
    const target = args[1] || '.';
    installGitHook(target);
  } else if (effectiveCommand === 'mcp') {
    await startMcpServer();
  } else if (effectiveCommand === 'scan') {
    const target = args[1] || '.';
    const res = await runScan(target, { verbose: isVerbose, noFail: isNoFail });
    if (res?.hasCriticalOrHigh && !isNoFail) {
      process.exit(1);
    }
  } else if (effectiveCommand === 'learn') {
    const target = args[1];
    if (!target) {
      console.error('Error: Please provide a file or directory path containing security reports to learn.');
      process.exit(1);
    }
    await learnReport(target);
  } else if (effectiveCommand === 'intel' || effectiveCommand === 'threats') {
    showThreatIntel();
  } else if (effectiveCommand === '--help' || effectiveCommand === '-h') {
    console.log(`
🛡️  HEXORA — NEXT-GEN UNIVERSAL SECURITY & AI AGENT ENGINE
-----------------------------------------------------------------------
Interactive Mode:
  npx hexora                           Open Interactive Command Center (Menu)
  npx hexora menu                      Open Interactive Command Center

Zero-Config Usage:
  npx hexora .                         Scan current directory
  npx hexora ./my-project              Scan target project folder
  npx hexora owner/repo                Scan remote GitHub repository
  npx hexora init                      1-Click setup for Antigravity, Cursor, Claude & VS Code
  npx hexora skill [platform]          Export skills to Antigravity, Cursor, Claude, Windsurf

Short Commands (after global install / npx alias):
  audit                                Interactive menu / Scan current dir
  audit watch                          Auto-rescan on file save (Ctrl+S)
  audit setup                          Configure AI Agents & IDEs
  audit skill antigravity              Install Antigravity Skill & MCP

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
    const res = await runScan(effectiveCommand, { verbose: isVerbose, noFail: isNoFail });
    if (res?.hasCriticalOrHigh && !isNoFail) {
      process.exit(1);
    }
  }
}

main().catch((err) => {
  console.error('Hexora execution error:', err);
  process.exit(1);
});
