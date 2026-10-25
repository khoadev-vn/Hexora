export interface ExportReport {
    platform: string;
    filesCreated: string[];
    mcpConfigured?: string;
    success: boolean;
}
export declare class SkillExporter {
    static exportAntigravity(workspaceDir: string, homeDir: string, auditBinPath: string): ExportReport;
    static exportCursor(workspaceDir: string, homeDir: string, auditBinPath: string): ExportReport;
    static exportClaudeCode(homeDir: string, auditBinPath: string): ExportReport;
    static exportWindsurf(workspaceDir: string, homeDir: string, auditBinPath: string): ExportReport;
    static exportVsCode(workspaceDir: string, auditBinPath: string): ExportReport;
}
//# sourceMappingURL=skillExporter.d.ts.map