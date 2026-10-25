import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

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
  let selected = options.target;

  if (!selected && process.stdin.isTTY) {
    console.log(`\nHexora Setup\n`);
    console.log(`Where do you want to use Hexora?\n`);
    console.log(`  [1] Terminal`);
    console.log(`  [2] Cursor`);
    console.log(`  [3] Claude Code`);
    console.log(`  [4] Claude Desktop`);
    console.log(`  [5] VS Code`);
    console.log(`  [6] Other MCP-compatible agents`);
    console.log(`  [7] All supported integrations\n`);

    selected = await promptUser('Select an option (1-7): ');
  }

  // Default to 7 if non-interactive or empty
  if (!selected) selected = '7';

  const root = path.resolve(options.workspaceDir || '.');
  const auditRoot = path.resolve(__dirname, '../../');
  const auditBin = path.join(auditRoot, 'bin', 'hexora.js');

  console.log(`\n======================================================`);
  console.log(`🚀 HEXORA UNIVERSAL SETUP`);
  console.log(`======================================================\n`);

  let configuredCount = 0;
  const targetHomeDirs = Array.from(new Set([
    os.homedir(),
    process.env.USERPROFILE || '',
    process.env.HOME || ''
  ].filter(Boolean))).map((p) => path.resolve(p));

  const isWindows = process.platform === 'win32';
  const nodeExec = process.execPath;

  const doTerminal = selected === '1' || selected === '7';
  const doCursor = selected === '2' || selected === '7';
  const doClaudeCode = selected === '3' || selected === '7';
  const doClaudeDesktop = selected === '4' || selected === '7';
  const doVsCode = selected === '5' || selected === '7';
  const doOtherMcp = selected === '6' || selected === '7';

  // 1. Terminal Setup
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
        console.log(`✅ [Terminal] Created global shortcut 'hexora' and 'audit' in ${userBin}`);
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
        const hookContent = `#!/bin/sh\n# Hexora Pre-Commit Security Gate\necho "🛡️ [Hexora] Scanning staged files for vulnerabilities & leaked secrets..."\naudit\nif [ $? -ne 0 ]; then\n  echo "❌ [Hexora] Commit aborted due to security vulnerabilities!"\n  exit 1\nfi\n`;
        fs.writeFileSync(hookPath, hookContent, 'utf-8');
        console.log(`✅ [Terminal/Git] Installed pre-commit hook in ${hookPath}`);
        configuredCount++;
      } catch (err: any) {
        console.warn(`⚠️ [Terminal/Git] Could not create git hook: ${err.message}`);
      }
    }
  }

  // 2. Cursor IDE MCP
  if (doCursor) {
    for (const homeDir of targetHomeDirs) {
      const cursorMcpPath = path.join(homeDir, '.cursor', 'mcp.json');
      try {
        let cursorJson: any = { mcpServers: {} };
        if (fs.existsSync(cursorMcpPath)) {
          try {
            cursorJson = JSON.parse(fs.readFileSync(cursorMcpPath, 'utf-8') || '{}');
          } catch {}
        } else {
          fs.mkdirSync(path.dirname(cursorMcpPath), { recursive: true });
        }
        if (!cursorJson.mcpServers) cursorJson.mcpServers = {};
        cursorJson.mcpServers['hexora'] = {
          command: 'node',
          args: [auditBin.replace(/\\/g, '/'), 'mcp']
        };
        cursorJson.mcpServers['hexora'] = cursorJson.mcpServers['hexora'];
        fs.writeFileSync(cursorMcpPath, JSON.stringify(cursorJson, null, 2), 'utf-8');
        console.log(`✅ [Cursor] Injected MCP server into: ${cursorMcpPath}`);
        configuredCount++;
      } catch (err: any) {
        console.warn(`⚠️ [Cursor] Could not inject Cursor MCP: ${err.message}`);
      }
    }
  }

  // 3. Claude Code MCP
  if (doClaudeCode) {
    for (const homeDir of targetHomeDirs) {
      const claudeCodeConfig = path.join(homeDir, '.claude.json');
      try {
        let configJson: any = { mcpServers: {} };
        if (fs.existsSync(claudeCodeConfig)) {
          try {
            configJson = JSON.parse(fs.readFileSync(claudeCodeConfig, 'utf-8') || '{}');
          } catch {}
        }
        if (!configJson.mcpServers) configJson.mcpServers = {};
        configJson.mcpServers['hexora'] = {
          command: 'node',
          args: [auditBin.replace(/\\/g, '/'), 'mcp']
        };
        configJson.mcpServers['hexora'] = configJson.mcpServers['hexora'];
        fs.writeFileSync(claudeCodeConfig, JSON.stringify(configJson, null, 2), 'utf-8');
        console.log(`✅ [Claude Code] Injected MCP server into: ${claudeCodeConfig}`);
        configuredCount++;
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
          args: [auditBin.replace(/\\/g, '/'), 'mcp']
        };
        claudeJson.mcpServers['hexora'] = claudeJson.mcpServers['hexora'];
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
      const vscodeDir = path.join(root, '.vscode');
      if (!fs.existsSync(vscodeDir)) fs.mkdirSync(vscodeDir, { recursive: true });
      const tasksPath = path.join(vscodeDir, 'tasks.json');
      const tasksConfig = {
        version: '2.0.0',
        tasks: [
          {
            label: '🛡️ Hexora: Quick Scan Workspace',
            type: 'shell',
            command: 'node',
            args: [auditBin.replace(/\\/g, '/'), '.'],
            group: { kind: 'test', isDefault: true },
            presentation: { reveal: 'always', panel: 'shared' },
            problemMatcher: []
          },
          {
            label: '👁️ Hexora: Real-time Watcher (Auto on Save)',
            type: 'shell',
            command: 'node',
            args: [auditBin.replace(/\\/g, '/'), 'watch'],
            isBackground: true,
            problemMatcher: []
          }
        ]
      };
      fs.writeFileSync(tasksPath, JSON.stringify(tasksConfig, null, 2), 'utf-8');
      console.log(`✅ [VS Code] Configured 1-click workspace tasks in: ${tasksPath}`);
      configuredCount++;
    } catch (err: any) {
      console.warn(`⚠️ [VS Code] Could not configure tasks: ${err.message}`);
    }
  }

  // 6. Other MCP-compatible agents snippet
  if (doOtherMcp) {
    console.log(`\n📋 [MCP Agent Config Snippet] Add this to your agent's MCP settings:`);
    console.log(JSON.stringify({
      "mcpServers": {
        "hexora": {
          "command": "node",
          "args": [auditBin.replace(/\\/g, '/'), "mcp"]
        }
      }
    }, null, 2));
    configuredCount++;
  }

  console.log(`\n🎉 Setup complete! (${configuredCount} integrations configured)`);
  console.log(`You can now ask your AI Agent:`);
  console.log(`  "Scan this project with Hexora and explain critical vulnerabilities."\n`);
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
