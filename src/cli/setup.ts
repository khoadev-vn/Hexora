import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { SkillExporter } from '../core/skillExporter.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface SetupOptions {
  workspaceDir?: string;
  target?: string;
}

function promptUser(query: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(query, (ans) => {
      rl.close();
      resolve(ans.trim());
    });
  });
}

export async function runUniversalSetup(options: SetupOptions = {}) {
  let selected = options.target?.toLowerCase();

  if (!selected && process.stdin.isTTY) {
    console.log(`\n======================================================`);
    console.log(`🚀 HEXORA UNIVERSAL AI AGENT & SECURITY SETUP`);
    console.log(`======================================================\n`);
    console.log(`Where do you want to integrate Hexora?\n`);
    console.log(`  [1] Google Antigravity (IDE & CLI - MCP & Skills)`);
    console.log(`  [2] Cursor (MCP Server & .cursor/rules)`);
    console.log(`  [3] Claude Code (CLI ~/.claude.json)`);
    console.log(`  [4] Claude Desktop (claude_desktop_config.json)`);
    console.log(`  [5] VS Code (Workspace Tasks & Extension)`);
    console.log(`  [6] Windsurf (.windsurf & .windsurfrules)`);
    console.log(`  [7] OpenCode (opencode.json & ~/.config/opencode)`);
    console.log(`  [8] Terminal Global Shortcuts & Git Pre-commit Hook`);
    console.log(`  [9] All Integrations (Recommended for Full AI Stack)\n`);

    selected = await promptUser('Select an option (1-9): ');
  }

  // Default to 'all' if non-interactive or empty
  if (!selected) selected = 'all';

  const root = path.resolve(options.workspaceDir || '.');
  const auditRoot = path.resolve(__dirname, '../../');
  const auditBin = path.join(auditRoot, 'bin', 'hexora.js');

  console.log(`\n======================================================`);
  console.log(`⚡ INTEGRATING HEXORA SECURITY PROTOCOL`);
  console.log(`   Workspace: ${root}`);
  console.log(`======================================================\n`);

  let configuredCount = 0;
  const targetHomeDirs = Array.from(
    new Set([os.homedir(), process.env.USERPROFILE || '', process.env.HOME || ''].filter(Boolean))
  ).map((p) => path.resolve(p));

  const isWindows = process.platform === 'win32';
  const nodeExec = process.execPath;

  const isAll = selected === '8' || selected === '9' || selected === 'all';
  const doAntigravity = selected === '1' || selected === 'antigravity' || selected === 'agy' || isAll;
  const doCursor = selected === '2' || selected === 'cursor' || isAll;
  const doClaudeCode = selected === '3' || selected === 'claude-code' || selected === 'claude' || isAll;
  const doClaudeDesktop = selected === '4' || selected === 'claude-desktop' || isAll;
  const doVsCode = selected === '5' || selected === 'vscode' || isAll;
  const doWindsurf = selected === '6' || selected === 'windsurf' || isAll;
  const doOpenCode = selected === '7' || selected === 'opencode' || isAll;
  const doTerminal = selected === '8' || selected === 'terminal' || selected === 'git' || isAll;

  // 1. Google Antigravity Setup (MCP + Workspace Skill + Global Skill + Rules)
  if (doAntigravity) {
    for (const homeDir of targetHomeDirs) {
      try {
        const report = SkillExporter.exportAntigravity(root, homeDir, auditBin);
        if (report.success) {
          console.log(`✅ [Google Antigravity] Injected MCP server into: ${report.mcpConfigured}`);
          console.log(`✅ [Google Antigravity] Installed Workspace Skill: .agents/skills/hexora/SKILL.md`);
          console.log(`✅ [Google Antigravity] Installed Global Skill in ~/.gemini/config/skills/hexora/SKILL.md`);
          console.log(`✅ [Google Antigravity] Created Project Rules in .agents/rules/hexora-security.md & GEMINI.md`);
          configuredCount++;
        }
      } catch (err: any) {
        console.warn(`⚠️ [Google Antigravity] Integration failed: ${err.message}`);
      }
    }
  }

  // 2. Cursor IDE MCP & Rules
  if (doCursor) {
    for (const homeDir of targetHomeDirs) {
      try {
        const report = SkillExporter.exportCursor(root, homeDir, auditBin);
        if (report.success) {
          console.log(`✅ [Cursor] Configured MCP server at: ${report.mcpConfigured}`);
          console.log(`✅ [Cursor] Injected security rules into .cursor/rules/hexora.mdc`);
          configuredCount++;
        }
      } catch (err: any) {
        console.warn(`⚠️ [Cursor] Could not inject Cursor MCP: ${err.message}`);
      }
    }
  }

  // 3. Claude Code MCP
  if (doClaudeCode) {
    for (const homeDir of targetHomeDirs) {
      try {
        const report = SkillExporter.exportClaudeCode(homeDir, auditBin);
        if (report.success) {
          console.log(`✅ [Claude Code] Injected MCP server into: ${report.mcpConfigured}`);
          configuredCount++;
        }
      } catch (err: any) {
        console.warn(`⚠️ [Claude Code] Could not configure ~/.claude.json: ${err.message}`);
      }
    }
  }

  // 4. Claude Desktop MCP
  if (doClaudeDesktop) {
    for (const homeDir of targetHomeDirs) {
      const claudeConfigDir = isWindows
        ? path.join(homeDir, 'AppData', 'Roaming', 'Claude')
        : path.join(homeDir, '.config', 'Claude');
      const claudeConfigFile = path.join(claudeConfigDir, 'claude_desktop_config.json');
      try {
        fs.mkdirSync(claudeConfigDir, { recursive: true });
        let claudeJson: any = { mcpServers: {} };
        if (fs.existsSync(claudeConfigFile)) {
          try {
            claudeJson = JSON.parse(fs.readFileSync(claudeConfigFile, 'utf-8') || '{}');
          } catch {}
        }
        if (!claudeJson.mcpServers) claudeJson.mcpServers = {};
        claudeJson.mcpServers['hexora'] = {
          command: 'node',
          args: [auditBin.replace(/\\/g, '/'), 'mcp'],
        };
        fs.writeFileSync(claudeConfigFile, JSON.stringify(claudeJson, null, 2), 'utf-8');
        console.log(`✅ [Claude Desktop] Configured MCP server at: ${claudeConfigFile}`);
        configuredCount++;
      } catch (err: any) {
        console.warn(`⚠️ [Claude Desktop] Could not configure Claude Desktop: ${err.message}`);
      }
    }
  }

  // 5. VS Code
  if (doVsCode) {
    try {
      const report = SkillExporter.exportVsCode(root, auditBin);
      if (report.success) {
        console.log(`✅ [VS Code] Configured 1-click workspace tasks in .vscode/tasks.json`);
        configuredCount++;
      }
    } catch (err: any) {
      console.warn(`⚠️ [VS Code] Could not configure tasks: ${err.message}`);
    }
  }

  // 6. Windsurf
  if (doWindsurf) {
    for (const homeDir of targetHomeDirs) {
      try {
        const report = SkillExporter.exportWindsurf(root, homeDir, auditBin);
        if (report.success) {
          console.log(`✅ [Windsurf] Configured MCP server in: ${report.mcpConfigured}`);
          console.log(`✅ [Windsurf] Created workspace rules in .windsurfrules`);
          configuredCount++;
        }
      } catch (err: any) {
        console.warn(`⚠️ [Windsurf] Could not configure Windsurf: ${err.message}`);
      }
    }
  }

  // 7. OpenCode (Workspace opencode.json & ~/.config/opencode/config.json)
  if (doOpenCode) {
    for (const homeDir of targetHomeDirs) {
      try {
        const report = SkillExporter.exportOpenCode(root, homeDir, auditBin);
        if (report.success) {
          console.log(`✅ [OpenCode] Configured MCP server in: ${report.mcpConfigured}`);
          configuredCount++;
        }
      } catch (err: any) {
        console.warn(`⚠️ [OpenCode] Could not configure OpenCode: ${err.message}`);
      }
    }
  }

  // 8. Terminal & Git Hook Setup
  if (doTerminal) {
    for (const homeDir of targetHomeDirs) {
      const userBin = path.join(homeDir, 'bin');
      try {
        if (!fs.existsSync(userBin)) fs.mkdirSync(userBin, { recursive: true });
        if (isWindows) {
          const cmdContent = `@echo off\r\n"${nodeExec}" "${auditBin}" %*\r\n`;
          const ps1Content = `& "${nodeExec}" "${auditBin}" @args\r\n`;
          fs.writeFileSync(path.join(userBin, 'hexora.cmd'), cmdContent, 'utf-8');
          fs.writeFileSync(path.join(userBin, 'hexora.ps1'), ps1Content, 'utf-8');
          fs.writeFileSync(path.join(userBin, 'audit.cmd'), cmdContent, 'utf-8');
          fs.writeFileSync(path.join(userBin, 'audit.ps1'), ps1Content, 'utf-8');
        } else {
          const shContent = `#!/bin/sh\nexec "${nodeExec}" "${auditBin}" "$@"\n`;
          fs.writeFileSync(path.join(userBin, 'hexora'), shContent, { encoding: 'utf-8', mode: 0o755 });
          fs.writeFileSync(path.join(userBin, 'audit'), shContent, { encoding: 'utf-8', mode: 0o755 });
        }
        console.log(`✅ [Terminal] Created global CLI shortcuts 'hexora' and 'audit' in ${userBin}`);
        configuredCount++;
      } catch (err: any) {
        console.warn(`⚠️ [Terminal] Could not register in ~/bin: ${err.message}`);
      }
    }

    // Pre-commit git hook
    const gitDir = path.join(root, '.git');
    if (fs.existsSync(gitDir)) {
      try {
        const hooksDir = path.join(gitDir, 'hooks');
        if (!fs.existsSync(hooksDir)) fs.mkdirSync(hooksDir, { recursive: true });
        const hookPath = path.join(hooksDir, 'pre-commit');
        const hookContent = `#!/bin/sh\n# Hexora Pre-Commit Security Gate\necho "🛡️ [Hexora] Scanning staged files for vulnerabilities & leaked secrets..."\nif [ -f "./bin/hexora.js" ]; then\n  node ./bin/hexora.js .\nelif command -v hexora > /dev/null 2>&1; then\n  hexora .\nelif command -v audit > /dev/null 2>&1; then\n  audit .\nelse\n  npx --yes hexora .\nfi\nif [ $? -ne 0 ]; then\n  echo "❌ [Hexora] Commit aborted due to security vulnerabilities!"\n  exit 1\nfi\n`;
        fs.writeFileSync(hookPath, hookContent, 'utf-8');
        console.log(`✅ [Terminal/Git] Installed pre-commit hook in ${hookPath}`);
        configuredCount++;
      } catch (err: any) {
        console.warn(`⚠️ [Terminal/Git] Could not create git hook: ${err.message}`);
      }
    }
  }

  console.log(`\n🎉 Universal Setup complete! (${configuredCount} integration targets configured)`);
  console.log(`Your AI Agents (Antigravity, Cursor, Claude, Windsurf) can now autonomously run:`);
  console.log(`  - "Scan this project with Hexora and fix any critical vulnerabilities."`);
  console.log(`  - "Audit this file for injection bugs or leaked keys."`);
  console.log(`  - "Explain CVE-2024-34351 and verify if our codebase is vulnerable."\n`);
}

export function installGitHook(targetDir: string = '.') {
  const root = path.resolve(targetDir);
  const gitDir = path.join(root, '.git');
  if (!fs.existsSync(gitDir)) {
    console.error(`❌ Error: No .git directory found at ${root}`);
    return;
  }
  const hooksDir = path.join(gitDir, 'hooks');
  if (!fs.existsSync(hooksDir)) fs.mkdirSync(hooksDir, { recursive: true });
  const hookPath = path.join(hooksDir, 'pre-commit');
  const hookContent = `#!/bin/sh\necho "🛡️ [Hexora] Running pre-commit security check..."\nif [ -f "./bin/hexora.js" ]; then\n  node ./bin/hexora.js .\nelif command -v hexora > /dev/null 2>&1; then\n  hexora .\nelif command -v audit > /dev/null 2>&1; then\n  audit .\nelse\n  npx --yes hexora .\nfi\n`;
  fs.writeFileSync(hookPath, hookContent, 'utf-8');
  console.log(`✅ Installed pre-commit hook at ${hookPath}`);
}

export async function runSkillCommand(platform: string = 'all', targetDir: string = '.') {
  const root = path.resolve(targetDir);
  const auditRoot = path.resolve(__dirname, '../../');
  const auditBin = path.join(auditRoot, 'bin', 'hexora.js');
  const homeDir = os.homedir();

  console.log(`\n======================================================`);
  console.log(`📦 HEXORA AI AGENT SKILL & MCP INSTALLER`);
  console.log(`   Target: ${platform.toUpperCase()}`);
  console.log(`   Workspace: ${root}`);
  console.log(`======================================================\n`);

  const p = platform.toLowerCase();
  if (p === 'antigravity' || p === 'agy') {
    const report = SkillExporter.exportAntigravity(root, homeDir, auditBin);
    console.log(`✅ Installed Google Antigravity Skill & MCP server:`);
    report.filesCreated.forEach((f) => console.log(`   - ${f}`));
  } else if (p === 'cursor') {
    const report = SkillExporter.exportCursor(root, homeDir, auditBin);
    console.log(`✅ Installed Cursor Rules & MCP:`);
    report.filesCreated.forEach((f) => console.log(`   - ${f}`));
  } else if (p === 'claude') {
    const report = SkillExporter.exportClaudeCode(homeDir, auditBin);
    console.log(`✅ Installed Claude Code MCP:`);
    report.filesCreated.forEach((f) => console.log(`   - ${f}`));
  } else if (p === 'windsurf') {
    const report = SkillExporter.exportWindsurf(root, homeDir, auditBin);
    console.log(`✅ Installed Windsurf Rules & MCP:`);
    report.filesCreated.forEach((f) => console.log(`   - ${f}`));
  } else if (p === 'opencode') {
    const report = SkillExporter.exportOpenCode(root, homeDir, auditBin);
    console.log(`✅ Installed OpenCode MCP:`);
    report.filesCreated.forEach((f) => console.log(`   - ${f}`));
  } else {
    const agy = SkillExporter.exportAntigravity(root, homeDir, auditBin);
    const cur = SkillExporter.exportCursor(root, homeDir, auditBin);
    const cld = SkillExporter.exportClaudeCode(homeDir, auditBin);
    const wnd = SkillExporter.exportWindsurf(root, homeDir, auditBin);
    const opn = SkillExporter.exportOpenCode(root, homeDir, auditBin);
    const vsc = SkillExporter.exportVsCode(root, auditBin);

    console.log(`✅ Exported skills and MCP configs across all agent ecosystems:`);
    console.log(`   - Google Antigravity (${agy.filesCreated.length} files)`);
    console.log(`   - Cursor IDE (${cur.filesCreated.length} files)`);
    console.log(`   - Claude Code (${cld.filesCreated.length} files)`);
    console.log(`   - Windsurf (${wnd.filesCreated.length} files)`);
    console.log(`   - OpenCode (${opn.filesCreated.length} files)`);
    console.log(`   - VS Code (${vsc.filesCreated.length} files)`);
  }

  console.log(`\n✨ Installation complete! Your AI agents are ready to audit code.\n`);
}
