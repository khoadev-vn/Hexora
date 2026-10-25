import { SuiteMetrics, CompetitorBenchmarkRecord } from '../types/index.js';
export declare class BenchmarkRunner {
    private tempWorkspaceDir;
    constructor();
    runFullBenchmarkSuite(): Promise<{
        suiteResults: Record<string, SuiteMetrics>;
        aggregate: SuiteMetrics;
        competitorComparison: CompetitorBenchmarkRecord[];
        durationMs: number;
        reportPath: string;
    }>;
    private generateMarkdownReport;
}
//# sourceMappingURL=benchmarkRunner.d.ts.map