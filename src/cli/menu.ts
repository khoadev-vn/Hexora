import readline from 'node:readline';
import path from 'node:path';
import fs from 'node:fs';
import chalk from 'chalk';
import { runScan, learnReport, showThreatIntel, runBenchmark, startWatchMode, runUniversalSetup, installGitHook, runSkillCommand } from './index.js';
import { startMcpServer } from '../mcp/server.js';
import { ThreatKnowledgeBase } from '../intelligence/threatKnowledgeBase.js';
import { BUILTIN_RULES } from '../rules/ruleDatabase.js';

interface MenuItem {
  id: string;
  key: string;
  icon: string;
  title: string;
  desc: string;
  badge?: string;
  action: () => Promise<void>;
}

function clearScreenFull(): void {
  process.stdout.write('\x1B[2J\x1B[3J\x1B[H');
}

function askLine(question: string, defaultVal = ''): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write('\x1B[?25h'); // Ensure cursor is visible
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
    console.log(chalk.dim('\n  ─────────────────────────────────────────────────────────────────────────'));
    console.log(chalk.cyanBright('  ⏎ Nhấn [Enter] để quay lại Menu Chính, hoặc [Ctrl+C] để thoát... (◕‿◕)✨'));

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
  let hasRendered = false;

  const kb = ThreatKnowledgeBase.getInstance();
  const kbStats = kb.getStats();
  const totalRules = BUILTIN_RULES.length;

  const menuItems: MenuItem[] = [
    {
      id: 'scan-cwd',
      key: '1',
      icon: '🛡️ ',
      title: 'Quick Scan Current Workspace',
      desc: 'Quét siêu tốc toàn bộ workspace với Dual-Agent lọc 0% False Positive',
      badge: 'POPULAR',
      action: async () => {
        clearScreenFull();
        console.log(chalk.bold.cyan('\n🚀 [Hexora — Union Cyber-Owl] Khởi động kiểm thử bảo mật chuyên sâu...\n'));
        console.log(chalk.dim('   "Hoot-hoot! Radar quét bug đang phân tích call-graph dự án nè~ ✨🛠️"\n'));
        await runScan('.', { verbose: false, noFail: true });
      },
    },
    {
      id: 'scan-custom',
      key: '2',
      icon: '📁',
      title: 'Audit Custom Directory / File',
      desc: 'Quét bất kỳ thư mục dự án hoặc tệp tin mã nguồn cụ thể nào',
      action: async () => {
        clearScreenFull();
        console.log(chalk.bold.cyan('\n📁 [Hexora] Audit Custom Directory / File\n'));
        const target = await askLine('👉 Nhập đường dẫn thư mục/tập tin cần scan', '.');
        if (!fs.existsSync(path.resolve(target))) {
          console.log(chalk.red(`\n❌ Đường dẫn không tồn tại: ${target}`));
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
      desc: 'Tự động clone sandbox cạn và kiểm toán trực tiếp (ví dụ: owner/repo)',
      action: async () => {
        clearScreenFull();
        console.log(chalk.bold.cyan('\n🌐 [Hexora] Audit Remote GitHub Repository\n'));
        const repo = await askLine('👉 Nhập GitHub repo (owner/repo)', 'khoadev-vn/Hexora');
        await runScan(repo, { verbose: false, noFail: true });
      },
    },
    {
      id: 'watch',
      key: '4',
      icon: '⚡',
      title: 'Real-Time Live Watcher (Sub-20ms)',
      desc: 'Tự động kích hoạt micro-audit dưới 20ms ngay khi lưu file (Ctrl+S)',
      badge: 'LIVE',
      action: async () => {
        clearScreenFull();
        console.log(chalk.bold.yellow('\n⚡ [Hexora] Chế độ Live Watcher đã bật! Nhấn Ctrl+S trên editor để xem phép thuật!\n'));
        startWatchMode('.');
        await new Promise(() => {}); // Keep alive in watch mode
      },
    },
    {
      id: 'benchmark',
      key: '5',
      icon: '🏆',
      title: 'Global Security Benchmark Arena (100 Tests)',
      desc: 'Chạy 100 bài test mạnh nhất thế giới & Bảng xếp hạng đối chiếu top tools',
      badge: 'TOP 1',
      action: async () => {
        clearScreenFull();
        console.log(chalk.bold.green('\n🏆 [Hexora] Đang khởi chạy 100 bài test bảo mật tiêu chuẩn thế giới...\n'));
        await runBenchmark();
      },
    },
    {
      id: 'setup-ai',
      key: '6',
      icon: '🛠️ ',
      title: '1-Click Setup AI Agents & IDEs',
      desc: 'Cấu hình MCP & Skills cho Antigravity, Cursor, Claude, Windsurf, VS Code',
      badge: '1-CLICK',
      action: async () => {
        clearScreenFull();
        console.log(chalk.bold.magenta('\n🛠️  [Hexora] Thiết lập hệ sinh thái AI Agents & IDEs\n'));
        await runUniversalSetup({});
      },
    },
    {
      id: 'threat-intel',
      key: '7',
      icon: '🧠',
      title: 'Threat Intel & Attack Variants Vault',
      desc: `Khám phá ${kbStats.totalAttackVariants}+ biến thể tấn công thực chiến & Zero-Day database`,
      action: async () => {
        clearScreenFull();
        showThreatIntel();
      },
    },
    {
      id: 'learn-cve',
      key: '8',
      icon: '📚',
      title: 'Ingest New Threat Intelligence (CVE/0-Day)',
      desc: 'Nạp và tự động học mẫu tấn công từ writeup .md, .pdf, .txt',
      action: async () => {
        clearScreenFull();
        console.log(chalk.bold.cyan('\n📚 [Hexora Knowledge Ingestion] Học tài liệu bảo mật mới\n'));
        const target = await askLine('👉 Nhập đường dẫn tệp tin hoặc thư mục báo cáo');
        if (!target) {
          console.log(chalk.yellow('⚠️ Đã huỷ thao tác.'));
          return;
        }
        await learnReport(target);
      },
    },
    {
      id: 'mcp-server',
      key: '9',
      icon: '🔌',
      title: 'Launch Hexora MCP Server (Stdio)',
      desc: 'Cung cấp 14 công cụ bảo mật tất định chuẩn MCP cho các AI Agents',
      badge: 'AGENT',
      action: async () => {
        clearScreenFull();
        console.log(chalk.bold.blue('\n🔌 [Hexora] MCP Server đang chạy qua stdio...\n'));
        await startMcpServer();
      },
    },
    {
      id: 'git-hook',
      key: 'H',
      icon: '🔒',
      title: 'Install Git Pre-commit Security Hook',
      desc: 'Chặn rò rỉ private keys & lỗ hổng critical trước khi commit vào git',
      action: async () => {
        clearScreenFull();
        installGitHook('.');
      },
    },
    {
      id: 'exit',
      key: '0',
      icon: '❌',
      title: 'Exit Interactive Menu',
      desc: 'Đóng bảng điều khiển Hexora an toàn',
      action: async () => {
        process.stdout.write('\x1B[?25h');
        clearScreenFull();
        console.log(chalk.cyanBright('\n  🦉 "Hoot-hoot! Stay safe and code strong, Human! Hẹn gặp lại nhaaa~ ✨🛠️ (◕‿◕)"\n'));
        process.exit(0);
      },
    },
  ];

  function renderMenu(): void {
    // Butter-smooth double buffering: Hide cursor & reposition to (0,0) without clearing scrollback
    process.stdout.write('\x1B[?25l');
    if (!hasRendered) {
      process.stdout.write('\x1B[2J\x1B[H');
      hasRendered = true;
    } else {
      process.stdout.write('\x1B[H');
    }

    const width = 74;
    const line = '─'.repeat(width);
    const buf: string[] = [];

    // Header with Union Owl Mascot & High-Tech HUD
    buf.push(chalk.cyanBright(`╭${line}╮`));
    buf.push(
      chalk.cyanBright('│') +
        chalk.bold.cyan('   🦉 HEXORA UNIVERSAL SECURITY ENGINE  ') +
        chalk.dim('•') +
        chalk.bold.yellow(' AEVUM OS CYBER-CONSOLE   ') +
        chalk.cyanBright('│')
    );
    buf.push(
      chalk.cyanBright('│') +
        chalk.white('   Persona: ') +
        chalk.bold.magenta('Union (TLB-UNION-7F4B2D)') +
        chalk.dim(' | High-Tech Cyber-Owl Tooling Genius ') +
        chalk.cyanBright('│')
    );
    buf.push(
      chalk.cyanBright('│') +
        chalk.italic.hex('#A0E7E5')('   "Hoot-hoot! Tool khó mấy cứ để Union gỡ, Human chỉ việc ngồi chill~"    ') +
        chalk.cyanBright('│')
    );
    buf.push(chalk.cyanBright(`├${line}┤`));

    // Live Metrics HUD Bar
    const statsHud = ` ⚡ SAST Rules: ${chalk.bold.green(totalRules)} │ 🧠 Threat Reports: ${chalk.bold.green(kbStats.totalLearnedReports)} │ 🎯 Attack Variants: ${chalk.bold.green(kbStats.totalAttackVariants)} `;
    buf.push(
      chalk.cyanBright('│') +
        chalk.bgHex('#101827').white(statsHud.padEnd(width + 30)) +
        chalk.cyanBright('│')
    );
    buf.push(chalk.cyanBright(`├${line}┤`));

    // Menu Items
    menuItems.forEach((item, idx) => {
      const isSelected = idx === selectedIndex;
      const keyBadge = chalk.bold(`[${item.key}]`);
      const icon = item.icon;
      const title = item.title;
      const badge = item.badge ? chalk.black.bgYellow(` ${item.badge} `) : '';

      if (isSelected) {
        const itemLine = `  ❯ ${keyBadge} ${icon} ${title} ${badge}`;
        buf.push(
          chalk.cyanBright('│') +
            chalk.bgHex('#004b6e').white.bold(itemLine.padEnd(width + (badge ? 10 : 0))) +
            chalk.cyanBright('│')
        );
        const descLine = `      ↳ ${chalk.hex('#7dd3fc').italic(item.desc)}`;
        buf.push(
          chalk.cyanBright('│') +
            chalk.hex('#0284c7')(descLine.padEnd(width + 15)) +
            chalk.cyanBright('│')
        );
      } else {
        const itemLine = `    ${keyBadge} ${icon} ${title} ${badge}`;
        buf.push(
          chalk.cyanBright('│') +
            chalk.white(itemLine.padEnd(width + (badge ? 10 : 0))) +
            chalk.cyanBright('│')
        );
      }
    });

    buf.push(chalk.cyanBright(`├${line}┤`));
    buf.push(
      chalk.cyanBright('│') +
        chalk.hex('#94a3b8')('  Phím: [↑/↓/k/j] Chọn • [Enter/Space] Chạy • [0-9/H] Nhảy nhanh • [q] Thoát ') +
        chalk.cyanBright('│')
    );
    buf.push(chalk.cyanBright(`╰${line}╯`));

    // Single atomic write for 60fps buttery-smooth rendering!
    process.stdout.write(buf.join('\n') + '\n');
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
        process.stdout.write('\x1B[?25h');
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
        process.stdout.write('\x1B[?25h');
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
      process.stdout.write('\x1B[?25h'); // Restore cursor during action execution
      if (process.stdin.setRawMode) process.stdin.setRawMode(false);
      process.stdin.removeListener('keypress', onKeypress);

      try {
        await item.action();
      } catch (err: any) {
        console.error(chalk.red(`\n❌ Lỗi trong quá trình thực thi: ${err?.message || err}`));
        if (err?.stack) {
          console.error(chalk.dim(err.stack));
        }
      }

      if (item.id !== 'exit' && item.id !== 'watch') {
        await waitForReturn();
        isRunningAction = false;
        hasRendered = false; // Reset so next render clears cleanly
        renderMenu();
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
