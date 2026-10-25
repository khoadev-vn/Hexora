import fs from 'node:fs';
import path from 'node:path';
import {
  ANTIGRAVITY_SKILL_MD,
  ANTIGRAVITY_RULES_MD,
  CURSOR_RULE_MDC,
  CLAUDE_CODE_MD,
  WINDSURF_RULES_MD,
} from './skillTemplates.js';

export interface ExportReport {
  platform: string;
  filesCreated: string[];
  mcpConfigured?: string;
  success: boolean;
}

export class SkillExporter {
  public static exportAntigravity(workspaceDir: string, homeDir: string, auditBinPath: string): ExportReport {
    const filesCreated: string[] = [];
    const normalizedBin = auditBinPath.replace(/\\/g, '/');

    // 1. Configure MCP Server in ~/.gemini/config/mcp_config.json
    const geminiConfigDir = path.join(homeDir, '.gemini', 'config');
    const mcpConfigPath = path.join(geminiConfigDir, 'mcp_config.json');
    let mcpConfigured: string | undefined;

    try {
      if (!fs.existsSync(geminiConfigDir)) fs.mkdirSync(geminiConfigDir, { recursive: true });
      let mcpJson: any = { mcpServers: {} };
      if (fs.existsSync(mcpConfigPath)) {
        try {
          mcpJson = JSON.parse(fs.readFileSync(mcpConfigPath, 'utf-8') || '{}');
        } catch {}
      }
      if (!mcpJson.mcpServers) mcpJson.mcpServers = {};
      mcpJson.mcpServers['hexora'] = {
        command: 'node',
        args: [normalizedBin, 'mcp'],
      };
      fs.writeFileSync(mcpConfigPath, JSON.stringify(mcpJson, null, 2), 'utf-8');
      mcpConfigured = mcpConfigPath;
      filesCreated.push(mcpConfigPath);
    } catch (err: any) {
      console.warn(`[Antigravity] Could not update mcp_config.json: ${err.message}`);
    }

    // 2. Export Workspace Skill to .agents/skills/hexora/SKILL.md
    const wsSkillDir = path.join(workspaceDir, '.agents', 'skills', 'hexora');
    const wsSkillFile = path.join(wsSkillDir, 'SKILL.md');
    try {
      if (!fs.existsSync(wsSkillDir)) fs.mkdirSync(wsSkillDir, { recursive: true });
      fs.writeFileSync(wsSkillFile, ANTIGRAVITY_SKILL_MD, 'utf-8');
      filesCreated.push(wsSkillFile);
    } catch (err: any) {
      console.warn(`[Antigravity] Could not write workspace skill: ${err.message}`);
    }

    // 3. Export Global Skill to ~/.gemini/config/skills/hexora/SKILL.md
    const globalSkillDir = path.join(geminiConfigDir, 'skills', 'hexora');
    const globalSkillFile = path.join(globalSkillDir, 'SKILL.md');
    try {
      if (!fs.existsSync(globalSkillDir)) fs.mkdirSync(globalSkillDir, { recursive: true });
      fs.writeFileSync(globalSkillFile, ANTIGRAVITY_SKILL_MD, 'utf-8');
      filesCreated.push(globalSkillFile);
    } catch {}

    // 4. Export Workspace Rule to .agents/rules/hexora-security.md and GEMINI.md
    const wsRulesDir = path.join(workspaceDir, '.agents', 'rules');
    const wsRuleFile = path.join(wsRulesDir, 'hexora-security.md');
    const geminiMdFile = path.join(workspaceDir, 'GEMINI.md');
    try {
      if (!fs.existsSync(wsRulesDir)) fs.mkdirSync(wsRulesDir, { recursive: true });
      fs.writeFileSync(wsRuleFile, ANTIGRAVITY_RULES_MD, 'utf-8');
      filesCreated.push(wsRuleFile);

      if (!fs.existsSync(geminiMdFile)) {
        fs.writeFileSync(geminiMdFile, ANTIGRAVITY_RULES_MD, 'utf-8');
        filesCreated.push(geminiMdFile);
      }
    } catch {}

    return {
      platform: 'Google Antigravity',
      filesCreated,
      mcpConfigured,
      success: true,
    };
  }

  public static exportCursor(workspaceDir: string, homeDir: string, auditBinPath: string): ExportReport {
    const filesCreated: string[] = [];
    const normalizedBin = auditBinPath.replace(/\\/g, '/');

    // 1. Cursor Global MCP (~/.cursor/mcp.json)
    const cursorMcpPath = path.join(homeDir, '.cursor', 'mcp.json');
    try {
      const dir = path.dirname(cursorMcpPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      let json: any = { mcpServers: {} };
      if (fs.existsSync(cursorMcpPath)) {
        try {
          json = JSON.parse(fs.readFileSync(cursorMcpPath, 'utf-8') || '{}');
        } catch {}
      }
      if (!json.mcpServers) json.mcpServers = {};
      json.mcpServers['hexora'] = { command: 'node', args: [normalizedBin, 'mcp'] };
      fs.writeFileSync(cursorMcpPath, JSON.stringify(json, null, 2), 'utf-8');
      filesCreated.push(cursorMcpPath);
    } catch {}

    // 2. Workspace Cursor Rules (.cursor/rules/hexora.mdc)
    const cursorRulesDir = path.join(workspaceDir, '.cursor', 'rules');
    const cursorRuleFile = path.join(cursorRulesDir, 'hexora.mdc');
    try {
      if (!fs.existsSync(cursorRulesDir)) fs.mkdirSync(cursorRulesDir, { recursive: true });
      fs.writeFileSync(cursorRuleFile, CURSOR_RULE_MDC, 'utf-8');
      filesCreated.push(cursorRuleFile);
    } catch {}

    return {
      platform: 'Cursor',
      filesCreated,
      mcpConfigured: cursorMcpPath,
      success: true,
    };
  }

  public static exportClaudeCode(homeDir: string, auditBinPath: string): ExportReport {
    const filesCreated: string[] = [];
    const normalizedBin = auditBinPath.replace(/\\/g, '/');
    const claudePath = path.join(homeDir, '.claude.json');

    try {
      let json: any = { mcpServers: {} };
      if (fs.existsSync(claudePath)) {
        try {
          json = JSON.parse(fs.readFileSync(claudePath, 'utf-8') || '{}');
        } catch {}
      }
      if (!json.mcpServers) json.mcpServers = {};
      json.mcpServers['hexora'] = { command: 'node', args: [normalizedBin, 'mcp'] };
      fs.writeFileSync(claudePath, JSON.stringify(json, null, 2), 'utf-8');
      filesCreated.push(claudePath);
    } catch {}

    return {
      platform: 'Claude Code',
      filesCreated,
      mcpConfigured: claudePath,
      success: true,
    };
  }

  public static exportWindsurf(workspaceDir: string, homeDir: string, auditBinPath: string): ExportReport {
    const filesCreated: string[] = [];
    const normalizedBin = auditBinPath.replace(/\\/g, '/');

    const windsurfConfigDir = path.join(homeDir, '.codeium', 'windsurf');
    const mcpPath = path.join(windsurfConfigDir, 'mcp_config.json');
    try {
      if (!fs.existsSync(windsurfConfigDir)) fs.mkdirSync(windsurfConfigDir, { recursive: true });
      let json: any = { mcpServers: {} };
      if (fs.existsSync(mcpPath)) {
        try {
          json = JSON.parse(fs.readFileSync(mcpPath, 'utf-8') || '{}');
        } catch {}
      }
      if (!json.mcpServers) json.mcpServers = {};
      json.mcpServers['hexora'] = { command: 'node', args: [normalizedBin, 'mcp'] };
      fs.writeFileSync(mcpPath, JSON.stringify(json, null, 2), 'utf-8');
      filesCreated.push(mcpPath);
    } catch {}

    const wsRule = path.join(workspaceDir, '.windsurfrules');
    try {
      fs.writeFileSync(wsRule, WINDSURF_RULES_MD, 'utf-8');
      filesCreated.push(wsRule);
    } catch {}

    return {
      platform: 'Windsurf',
      filesCreated,
      mcpConfigured: mcpPath,
      success: true,
    };
  }

  public static exportVsCode(workspaceDir: string, auditBinPath: string): ExportReport {
    const filesCreated: string[] = [];
    const normalizedBin = auditBinPath.replace(/\\/g, '/');
    const vscodeDir = path.join(workspaceDir, '.vscode');
    const tasksPath = path.join(vscodeDir, 'tasks.json');

    try {
      if (!fs.existsSync(vscodeDir)) fs.mkdirSync(vscodeDir, { recursive: true });
      const tasksConfig = {
        version: '2.0.0',
        tasks: [
          {
            label: '🛡️ Hexora: Quick Scan Workspace',
            type: 'shell',
            command: 'node',
            args: [normalizedBin, '.'],
            group: { kind: 'test', isDefault: true },
            presentation: { reveal: 'always', panel: 'shared' },
          },
          {
            label: '👁️ Hexora: Real-time Watcher (Auto on Save)',
            type: 'shell',
            command: 'node',
            args: [normalizedBin, 'watch'],
            isBackground: true,
          },
        ],
      };
      fs.writeFileSync(tasksPath, JSON.stringify(tasksConfig, null, 2), 'utf-8');
      filesCreated.push(tasksPath);
    } catch {}

    return {
      platform: 'VS Code',
      filesCreated,
      success: true,
    };
  }
}
