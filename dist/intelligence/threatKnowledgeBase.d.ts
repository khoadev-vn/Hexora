import { ThreatReport, ThreatCorrelation, ThreatIntelSummary } from '../types/index.js';
export declare const BUILTIN_THREAT_REPORTS: ThreatReport[];
export declare class ThreatKnowledgeBase {
    private static instance;
    private reports;
    private storagePath;
    constructor(customStorageDir?: string);
    static getInstance(storageDir?: string): ThreatKnowledgeBase;
    private initDefaultReports;
    /**
     * Synchronously registers an in-memory threat report (e.g. from Zero-Day live stream)
     */
    registerReport(report: ThreatReport): void;
    /**
     * Adds or updates a learned threat report in the knowledge base
     */
    learnReport(report: ThreatReport): Promise<void>;
    /**
     * Matches code snippets or file content against known threat reports and attack variants
     */
    matchThreats(content: string, filePath: string, category?: string): ThreatCorrelation[];
    /**
     * Search threat reports by query keyword (CVE, class, technology, attack type)
     */
    searchReports(query: string): ThreatReport[];
    getAllReports(): ThreatReport[];
    getStats(): ThreatIntelSummary;
    private loadPersistedReports;
    private savePersistedReports;
}
//# sourceMappingURL=threatKnowledgeBase.d.ts.map