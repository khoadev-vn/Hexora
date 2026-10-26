import readline from 'node:readline';
import path from 'node:path';
import fs from 'node:fs';
import chalk from 'chalk';
import { runScan, learnReport, showThreatIntel, runBenchmark, startWatchMode, runUniversalSetup, installGitHook, runSkillCommand } from './index.js';
import { startMcpServer } from '../mcp/server.js';

interface MenuItem {
  id: string;
  key: string;
  icon: string;
  title: string;
  desc: string;
  action: () => Promise<void>;
}

function clearScreen(): void {
  process.stdout.write('\x1B[2J\x1B[3J\x1B[H');
}

function askLine(question: string, defaultVal = ''): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    const promptText = defaultVal ? `${question} [${chalk.dim(defaultVal)}]: ` : `${question}: `;
    rl.question(promptText, (answer) => {
      rl.close();
      const trimmed = answer.trim();
      resolve(trimmed || defaultVal);
    });
  });
}

function waitForReturn(): Promise<void> {
  return new Promise((resolve) => {
    console.log(chalk.dim('\n  ─────────────────────────────────────────────────────────────'));
    console.log(chalk.cyanBright('  ⏎ Press [Enter] to return to Main Menu, or [Ctrl+C] to exit...'));

    const onKey = (_chunk: Buffer, key: readline.Key) => {
      if (key && (key.name === 'return' || key.name === 'enter' || key.name === 'escape' || (key.ctrl && key.name === 'c'))) {
        if (process.stdin.isTTY) {
          process.stdin.removeListener('keypress', onKey);
          if (process.stdin.setRawMode) process.stdin.setRawMode(false);
        }
        resolve();
      }
    };

    if (process.stdin.isTTY) {
      readline.emitKeypressEvents(process.stdin);
      if (process.stdin.setRawMode) process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.on('keypress', onKey);
    } else {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      rl.on('line', () => {
        rl.close();
        resolve();
      });
    }
  });
}

export async function openInteractiveMenu(): Promise<void> {
  let selectedIndex = 0;
  let isRunningAction = false;

  const menuItems: MenuItem[] = [
    {
      id: 'scan-cwd',
      key: '1',
      icon: '🛡️ ',
      title: 'Quick Scan Current Workspace',
      desc: 'Full SAST + Adversarial Verification with 0% false positives',
      action: async () => {
        clearScreen();
        console.log(chalk.bold.cyan('\n🚀 [Hexora] Launching security audit for current workspace...\n'));
        await runScan('.', { verbose: false, noFail: true });
      },
    },
    {
      id: 'scan-custom',
      key: '2',
      icon: '📁',
      title: 'Audit Custom Directory / File',
      desc: 'Scan any target local folder or specific file path',
      action: async () => {
        clearScreen();
        console.log(chalk.bold.cyan('\n📁 [Hexora] Audit Custom Directory / File\n'));
        const target = await askLine('👉 Enter path to scan', '.');
        if (!fs.existsSync(path.resolve(target))) {
          console.log(chalk.red(`\n❌ Path does not exist: ${target}`));
          return;
        }
        await runScan(target, { verbose: false, noFail: true });
      },
    },
    {
      id: 'scan-github',
      key: '3',
      icon: '🌐',
      title: 'Audit Remote GitHub Repository',
      desc: 'Auto-clones repo into sandbox & audits on-the-fly (e.g. expressjs/express)',
      action: async () => {
        clearScreen();
        console.log(chalk.bold.cyan('\n🌐 [Hexora] Audit Remote GitHub Repository\n'));
        const repo = await askLine('👉 Enter GitHub repository (owner/repo)', 'khoadev-vn/Hexora');
        await runScan(repo, { verbose: false, noFail: true });
      },
    },
    {
      id: 'watch',
      key: '4',
      icon: '⚡',
      title: 'Real-Time Live Watcher (Auto-audit on Save)',
      desc: 'Sub-20ms micro-scan triggered automatically on file save (Ctrl+S)',
      action: async () => {
        clearScreen();
        console.log(chalk.bold.yellow('\n⚡ [Hexora] Starting Live Watch Mode. Save files to auto-audit!\n'));
        startWatchMode('.');
        await new Promise(() => {}); // Keep alive in watch mode
      },
    },
    {
      id: 'setup-ai',
      key: '5',
      icon: '🛠️ ',
      title: '1-Click Setup AI Agents & IDEs',
      desc: 'Auto-configures MCP & Skills for Antigravity, Cursor, Claude, Windsurf, VS Code',
      action: async () => {
        clearScreen();
        console.log(chalk.bold.magenta('\n🛠️  [Hexora] Configuring AI IDEs & Agent Ecosystem\n'));
        await runUniversalSetup({});
      },
    },
    {
      id: 'threat-intel',
      key: '6',
      icon: '🧠',
      title: 'Threat Intel & CVE Knowledge Vault',
      desc: 'Inspect learned zero-days, attack variants, and vulnerability database',
      action: async () => {
        clearScreen();
        showThreatIntel();
      },
    },
    {
      id: 'learn-cve',
      key: '7',
      icon: '📚',
      title: 'Ingest New Threat Intelligence (CVE / Writeup)',
      desc: 'Learn attack patterns and mitigations from .md, .pdf, or .txt writeups',
      action: async () => {
        clearScreen();
        console.log(chalk.bold.cyan('\n📚 [Hexora Knowledge Ingestion] Ingest Security Report\n'));
        const target = await askLine('👉 Enter path to report file or directory');
        if (!target) {
          console.log(chalk.yellow('⚠️ Operation cancelled.'));
          return;
        }
        await learnReport(target);
      },
    },
    {
      id: 'benchmark',
      key: '8',
      icon: '📊',
      title: 'Vulnerability Benchmark Arena',
      desc: 'Run precision benchmarks across Web2, Web3, and AI agent targets',
      action: async () => {
        clearScreen();
        console.log(chalk.bold.green('\n📊 [Hexora] Launching Benchmark Arena Suite...\n'));
        await runBenchmark();
      },
    },
    {
      id: 'mcp-server',
      key: '9',
      icon: '🔌',
      title: 'Launch Hexora MCP Server (Model Context Protocol)',
      desc: 'Expose 14 native deterministic security tools for AI agents via stdio',
      action: async () => {
        clearScreen();
        console.log(chalk.bold.blue('\n🔌 [Hexora] MCP Server running via stdio...\n'));
        await startMcpServer();
      },
    },
    {
      id: 'git-hook',
      key: 'H',
      icon: '🔒',
      title: 'Install Git Pre-commit Security Hook',
      desc: 'Safeguard repo from secret leaks and critical vulnerabilities before commit',
      action: async () => {
        clearScreen();
        installGitHook('.');
      },
    },
    {
      id: 'exit',
      key: '0',
      icon: '❌',
      title: 'Exit Interactive Menu',
      desc: 'Exit Hexora command center',
      action: async () => {
        clearScreen();
        console.log(chalk.cyanBright('\n  Stay secure! Thank you for using Hexora. ✨🛡️\n'));
        process.exit(0);
      },
    },
  ];

  function renderMenu(): void {
    clearScreen();
    const width = 68;
    const line = '─'.repeat(width);

    console.log(chalk.cyanBright(`╭${line}╮`));
    console.log(
      chalk.cyanBright('│') +
        chalk.bold.white('  🛡️   HEXORA — NEXT-GEN INTERACTIVE SECURITY COMMAND CENTER  ') +
        chalk.cyanBright('│')
    );
    console.log(
      chalk.cyanBright('│') +
        chalk.dim('     Dual-Agent Verification • Zero-Config • 1-Click Execution     ') +
        chalk.cyanBright('│')
    );
    console.log(chalk.cyanBright(`├${line}┤`));

    menuItems.forEach((item, idx) => {
      const isSelected = idx === selectedIndex;
      const keyBadge = chalk.bold(`[${item.key}]`);
      const icon = item.icon;
      const title = item.title;

      if (isSelected) {
        const itemLine = `  ❯ ${keyBadge} ${icon} ${title}`;
        console.log(
          chalk.cyanBright('│') +
            chalk.bgCyan.black.bold(itemLine.padEnd(width)) +
            chalk.cyanBright('│')
        );
        const descLine = `      ↳ ${chalk.italic(item.desc)}`;
        console.log(
          chalk.cyanBright('│') +
            chalk.cyan(descLine.padEnd(width + 10)) +
            chalk.cyanBright('│')
        );
      } else {
        const itemLine = `    ${keyBadge} ${icon} ${title}`;
        console.log(
          chalk.cyanBright('│') +
            chalk.white(itemLine.padEnd(width)) +
            chalk.cyanBright('│')
        );
      }
    });

    console.log(chalk.cyanBright(`├${line}┤`));
    console.log(
      chalk.cyanBright('│') +
        chalk.dim('  Keys: [↑/↓] Select  •  [Enter] Run  •  [0-9] Quick Jump  •  [q] Exit  ') +
        chalk.cyanBright('│')
    );
    console.log(chalk.cyanBright(`╰${line}╯`));
  }

  return new Promise<void>((resolve) => {
    renderMenu();

    if (!process.stdin.isTTY) {
      console.log(chalk.yellow('\n(Non-interactive TTY mode detected. Running default quick scan...)\n'));
      menuItems[0].action().then(() => resolve());
      return;
    }

    readline.emitKeypressEvents(process.stdin);
    if (process.stdin.setRawMode) process.stdin.setRawMode(true);
    process.stdin.resume();

    const onKeypress = async (_str: string, key: readline.Key) => {
      if (isRunningAction) return;

      if (key.ctrl && key.name === 'c') {
        if (process.stdin.setRawMode) process.stdin.setRawMode(false);
        process.exit(0);
      }

      if (key.name === 'up' || key.name === 'k') {
        selectedIndex = (selectedIndex - 1 + menuItems.length) % menuItems.length;
        renderMenu();
        return;
      }

      if (key.name === 'down' || key.name === 'j') {
        selectedIndex = (selectedIndex + 1) % menuItems.length;
        renderMenu();
        return;
      }

      if (key.name === 'q' || (key.name === 'escape' && selectedIndex === menuItems.length - 1)) {
        if (process.stdin.setRawMode) process.stdin.setRawMode(false);
        process.exit(0);
      }

      // Direct key shortcuts: 0-9 or H
      const pressedKey = (key.sequence || key.name || '').toUpperCase();
      const directMatchIdx = menuItems.findIndex((m) => m.key.toUpperCase() === pressedKey);
      if (directMatchIdx !== -1) {
        selectedIndex = directMatchIdx;
        renderMenu();
        await triggerAction(menuItems[selectedIndex]);
        return;
      }

      if (key.name === 'return' || key.name === 'enter' || key.name === 'space') {
        await triggerAction(menuItems[selectedIndex]);
        return;
      }
    };

    async function triggerAction(item: MenuItem): Promise<void> {
      isRunningAction = true;
      if (process.stdin.setRawMode) process.stdin.setRawMode(false);
      process.stdin.removeListener('keypress', onKeypress);

      try {
        await item.action();
      } catch (err: any) {
        console.error(chalk.red(`\n❌ Error during execution: ${err?.message || err}`));
      }

      if (item.id !== 'exit' && item.id !== 'watch') {
        await waitForReturn();
        isRunningAction = false;
        renderMenu();
        readline.emitKeypressEvents(process.stdin);
        if (process.stdin.setRawMode) process.stdin.setRawMode(true);
        process.stdin.resume();
        process.stdin.on('keypress', onKeypress);
      } else {
        resolve();
      }
    }

    process.stdin.on('keypress', onKeypress);
  });
}
