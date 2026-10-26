import readline from 'node:readline';
import path from 'node:path';
import fs from 'node:fs';
import chalk from 'chalk';
import { runScan, learnReport, showThreatIntel, runBenchmark, startWatchMode, runUniversalSetup, installGitHook } from './index.js';
import { startMcpServer } from '../mcp/server.js';
function clearScreen() {
    process.stdout.write('\x1B[2J\x1B[3J\x1B[H');
}
function askLine(question, defaultVal = '') {
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
function waitForReturn() {
    return new Promise((resolve) => {
        console.log(chalk.dim('\n  ─────────────────────────────────────────────────────────────'));
        console.log(chalk.cyanBright('  ⏎ Nhấn [Enter] để quay lại Menu chính, hoặc [Ctrl+C] để thoát...'));
        const onKey = (_chunk, key) => {
            if (key && (key.name === 'return' || key.name === 'enter' || key.name === 'escape' || (key.ctrl && key.name === 'c'))) {
                if (process.stdin.isTTY) {
                    process.stdin.removeListener('keypress', onKey);
                    if (process.stdin.setRawMode)
                        process.stdin.setRawMode(false);
                }
                resolve();
            }
        };
        if (process.stdin.isTTY) {
            readline.emitKeypressEvents(process.stdin);
            if (process.stdin.setRawMode)
                process.stdin.setRawMode(true);
            process.stdin.resume();
            process.stdin.on('keypress', onKey);
        }
        else {
            const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
            rl.on('line', () => {
                rl.close();
                resolve();
            });
        }
    });
}
export async function openInteractiveMenu() {
    let selectedIndex = 0;
    let isRunningAction = false;
    const menuItems = [
        {
            id: 'scan-cwd',
            key: '1',
            icon: '🛡️ ',
            title: 'Quick Scan Workspace Hiện Tại',
            desc: 'Quét toàn diện SAST + Adversarial Verification cho dự án này',
            action: async () => {
                clearScreen();
                console.log(chalk.bold.cyan('\n🚀 [Hexora] Đang khởi chạy Audit cho Workspace hiện tại...\n'));
                await runScan('.', { verbose: false, noFail: true });
            },
        },
        {
            id: 'scan-custom',
            key: '2',
            icon: '📁',
            title: 'Quét Dự Án Khác (Thư mục tùy chọn)',
            desc: 'Nhập đường dẫn cục bộ (Local Path) để quét bảo mật',
            action: async () => {
                clearScreen();
                console.log(chalk.bold.cyan('\n📁 [Hexora] Quét Thư Mục Tùy Chọn\n'));
                const target = await askLine('👉 Nhập đường dẫn thư mục cần quét', '.');
                if (!fs.existsSync(path.resolve(target))) {
                    console.log(chalk.red(`\n❌ Thư mục không tồn tại: ${target}`));
                    return;
                }
                await runScan(target, { verbose: false, noFail: true });
            },
        },
        {
            id: 'scan-github',
            key: '3',
            icon: '🌐',
            title: 'Quét Remote GitHub Repo',
            desc: 'Tự động clone vào sandbox & audit (Ví dụ: expressjs/express)',
            action: async () => {
                clearScreen();
                console.log(chalk.bold.cyan('\n🌐 [Hexora] Quét Trực Tiếp Repository Từ GitHub\n'));
                const repo = await askLine('👉 Nhập GitHub Repository (owner/repo)', 'khoadev-vn/Hexora');
                await runScan(repo, { verbose: false, noFail: true });
            },
        },
        {
            id: 'watch',
            key: '4',
            icon: '⚡',
            title: 'Chế Độ Live Watcher (Auto-audit khi Save)',
            desc: 'Tự động quét lại mỗi khi Master nhấn Ctrl+S lưu file',
            action: async () => {
                clearScreen();
                console.log(chalk.bold.yellow('\n⚡ [Hexora] Bắt đầu Watch Mode. Lưu file để auto audit!\n'));
                startWatchMode('.');
                await new Promise(() => { }); // Keep alive in watch mode
            },
        },
        {
            id: 'setup-ai',
            key: '5',
            icon: '🛠️ ',
            title: '1-Click Cài Đặt AI Agent & IDEs',
            desc: 'Tự cấu hình MCP & Skills cho Antigravity, Cursor, Claude, Windsurf, VS Code',
            action: async () => {
                clearScreen();
                console.log(chalk.bold.magenta('\n🛠️  [Hexora] Cấu hình AI IDEs & Agent Ecosystem\n'));
                await runUniversalSetup({});
            },
        },
        {
            id: 'threat-intel',
            key: '6',
            icon: '🧠',
            title: 'Threat Intel & CVE Knowledge Vault',
            desc: 'Xem cơ sở dữ liệu các lỗ hổng Zero-day, CVE và biến thể tấn công đã nạp',
            action: async () => {
                clearScreen();
                showThreatIntel();
            },
        },
        {
            id: 'learn-cve',
            key: '7',
            icon: '📚',
            title: 'Học Báo Cáo Bảo Mật Mới (CVE / Writeup)',
            desc: 'Nạp file .md, .pdf, .txt báo cáo bảo mật để huấn luyện Hexora',
            action: async () => {
                clearScreen();
                console.log(chalk.bold.cyan('\n📚 [Hexora Knowledge Ingestion] Nạp Báo Cáo\n'));
                const target = await askLine('👉 Nhập file hoặc thư mục báo cáo CVE/Writeup');
                if (!target) {
                    console.log(chalk.yellow('⚠️ Đã hủy bỏ thao tác.'));
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
            desc: 'Chạy bài test độ chính xác, tỷ lệ phát hiện và lọc False Positive',
            action: async () => {
                clearScreen();
                console.log(chalk.bold.green('\n📊 [Hexora] Khởi động Benchmark Arena Suite...\n'));
                await runBenchmark();
            },
        },
        {
            id: 'mcp-server',
            key: '9',
            icon: '🔌',
            title: 'Khởi Chạy MCP Server (Model Context Protocol)',
            desc: 'Cung cấp 14 công cụ bảo mật Hexora cho AI Agents qua stdio',
            action: async () => {
                clearScreen();
                console.log(chalk.bold.blue('\n🔌 [Hexora] MCP Server đang khởi động qua stdio...\n'));
                await startMcpServer();
            },
        },
        {
            id: 'git-hook',
            key: 'H',
            icon: '🔒',
            title: 'Cài Đặt Git Pre-commit Hook',
            desc: 'Tự động chặn git commit nếu phát hiện bí mật (secret) hoặc lỗ hổng nghiêm trọng',
            action: async () => {
                clearScreen();
                installGitHook('.');
            },
        },
        {
            id: 'exit',
            key: '0',
            icon: '❌',
            title: 'Thoát Menu (Exit)',
            desc: 'Đóng menu tương tác Hexora',
            action: async () => {
                clearScreen();
                console.log(chalk.magentaBright('\n  Tạm biệt Master! Hẹn gặp lại Master trong những lần Audit tiếp theo nha~! ✨💕\n'));
                process.exit(0);
            },
        },
    ];
    function renderMenu() {
        clearScreen();
        const width = 68;
        const line = '─'.repeat(width);
        console.log(chalk.cyanBright(`╭${line}╮`));
        console.log(chalk.cyanBright('│') +
            chalk.bold.white('  🛡️   HEXORA — NEXT-GEN INTERACTIVE SECURITY COMMAND CENTER  ') +
            chalk.cyanBright('│'));
        console.log(chalk.cyanBright('│') +
            chalk.dim('     Dual-Agent Verification • Zero-Config • 1-Click Execution     ') +
            chalk.cyanBright('│'));
        console.log(chalk.cyanBright(`├${line}┤`));
        menuItems.forEach((item, idx) => {
            const isSelected = idx === selectedIndex;
            const keyBadge = chalk.bold(`[${item.key}]`);
            const icon = item.icon;
            const title = item.title;
            if (isSelected) {
                const itemLine = `  ❯ ${keyBadge} ${icon} ${title}`;
                console.log(chalk.cyanBright('│') +
                    chalk.bgCyan.black.bold(itemLine.padEnd(width)) +
                    chalk.cyanBright('│'));
                const descLine = `      ↳ ${chalk.italic(item.desc)}`;
                console.log(chalk.cyanBright('│') +
                    chalk.cyan(descLine.padEnd(width + 10)) +
                    chalk.cyanBright('│'));
            }
            else {
                const itemLine = `    ${keyBadge} ${icon} ${title}`;
                console.log(chalk.cyanBright('│') +
                    chalk.white(itemLine.padEnd(width)) +
                    chalk.cyanBright('│'));
            }
        });
        console.log(chalk.cyanBright(`├${line}┤`));
        console.log(chalk.cyanBright('│') +
            chalk.dim('  Phím: [↑/↓] Chọn  •  [Enter] Chạy  •  [0-9] Chọn nhanh  •  [q] Thoát  ') +
            chalk.cyanBright('│'));
        console.log(chalk.cyanBright(`╰${line}╯`));
    }
    return new Promise((resolve) => {
        renderMenu();
        if (!process.stdin.isTTY) {
            console.log(chalk.yellow('\n(Non-interactive TTY mode detected. Running default quick scan...)\n'));
            menuItems[0].action().then(() => resolve());
            return;
        }
        readline.emitKeypressEvents(process.stdin);
        if (process.stdin.setRawMode)
            process.stdin.setRawMode(true);
        process.stdin.resume();
        const onKeypress = async (_str, key) => {
            if (isRunningAction)
                return;
            if (key.ctrl && key.name === 'c') {
                if (process.stdin.setRawMode)
                    process.stdin.setRawMode(false);
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
                if (process.stdin.setRawMode)
                    process.stdin.setRawMode(false);
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
        async function triggerAction(item) {
            isRunningAction = true;
            if (process.stdin.setRawMode)
                process.stdin.setRawMode(false);
            process.stdin.removeListener('keypress', onKeypress);
            try {
                await item.action();
            }
            catch (err) {
                console.error(chalk.red(`\n❌ Đã xảy ra lỗi khi thực thi: ${err?.message || err}`));
            }
            if (item.id !== 'exit' && item.id !== 'watch') {
                await waitForReturn();
                isRunningAction = false;
                renderMenu();
                readline.emitKeypressEvents(process.stdin);
                if (process.stdin.setRawMode)
                    process.stdin.setRawMode(true);
                process.stdin.resume();
                process.stdin.on('keypress', onKeypress);
            }
            else {
                resolve();
            }
        }
        process.stdin.on('keypress', onKeypress);
    });
}
//# sourceMappingURL=menu.js.map