export interface ScanOptions {
    output?: string;
    format?: string;
    verbose?: boolean;
    noFail?: boolean;
}
export declare function runScan(targetInput?: string, options?: ScanOptions): Promise<{
    report: import("../index.js").AuditReport;
    hasCriticalOrHigh: boolean;
}>;
export declare function learnReport(targetPath: string): Promise<void>;
export declare function showThreatIntel(): void;
export declare function runBenchmark(): Promise<{
    suiteResults: Record<string, import("../index.js").SuiteMetrics>;
    aggregate: import("../index.js").SuiteMetrics;
    competitorComparison: import("../index.js").CompetitorBenchmarkRecord[];
    durationMs: number;
    reportPath: string;
}>;
export { startWatchMode } from './watch.js';
export { runUniversalSetup, installGitHook, runSkillCommand } from './setup.js';
//# sourceMappingURL=index.d.ts.map