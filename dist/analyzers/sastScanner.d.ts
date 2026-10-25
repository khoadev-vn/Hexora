import { VulnerabilityFinding, CoverageLedger, SASTRule } from '../types/index.js';
export interface ScannerOptions {
    targetDir: string;
    customRules?: SASTRule[];
    ignoreDirs?: string[];
    maxFileSizeKb?: number;
}
export declare class SastScanner {
    private rules;
    private ignoreDirs;
    private maxFileSizeBytes;
    private threatKb;
    private businessLogicAnalyzer;
    private scaScanner;
    constructor(options?: Partial<ScannerOptions>);
    scan(targetDir: string): Promise<{
        findings: VulnerabilityFinding[];
        coverage: CoverageLedger;
    }>;
    scanSingleFile(filePath: string, rootDir?: string, contentOverride?: string): VulnerabilityFinding[];
    private evaluateRule;
    /**
     * Scans for deep threat patterns directly learned from reports (Immunefi, CVEs, Cloudflare skills)
     */
    private evaluateThreatIntelCorrelations;
    private detectAttackSurfaces;
    private collectFiles;
    private isIndexInsideComment;
}
//# sourceMappingURL=sastScanner.d.ts.map