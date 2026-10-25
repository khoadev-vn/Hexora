export interface ApplyFixOptions {
    filePath: string;
    target?: string;
    replacement?: string;
    unifiedDiff?: string;
    createBackup?: boolean;
    rootPath?: string;
}
export interface ApplyFixResult {
    success: boolean;
    message: string;
    filePath: string;
    backupPath?: string;
    remainingFindings: number;
    diffSummary?: string;
}
export declare class PatchEngine {
    static apply(options: ApplyFixOptions): ApplyFixResult;
    private static applyUnifiedDiff;
}
//# sourceMappingURL=patchEngine.d.ts.map