import { ThreatReport, SASTRule, Severity } from '../types/index.js';
export interface ZeroDayAdvisoryPayload {
    cveId: string;
    title: string;
    source: 'GITHUB_ADVISORY' | 'NVD_CVE' | 'IMMUNEFI' | 'COMMUNITY' | 'CUSTOM';
    publishedDate: string;
    severity: Severity;
    targetEcosystem: 'WEB2' | 'WEB3_EVM' | 'WEB3_SOLANA' | 'AI_AGENT' | 'CLOUD' | 'GENERAL';
    vulnerabilityClass: string;
    cwe: string;
    affectedPackages?: string[];
    sinkPatternRegex: string;
    attackVariants: string[];
    exploitMechanism: string;
    mitigation: string;
    referenceUrl?: string;
}
export declare class ZeroDaySyncEngine {
    private static instance;
    private threatKb;
    private dynamicRules;
    private constructor();
    static getInstance(): ZeroDaySyncEngine;
    /**
     * Ingests a live Zero-Day security advisory (published minutes or hours ago on GitHub / NVD)
     * and immediately synthesizes dynamic SAST detection rules and Threat KB correlations in real-time.
     */
    ingestZeroDayAdvisory(advisory: ZeroDayAdvisoryPayload): {
        synthesizedRule: SASTRule;
        threatReport: ThreatReport;
    };
    /**
     * Bulk synchronizes zero-day advisories from a remote feed or local threat feed directory.
     */
    syncLiveFeeds(feedPathOrJson: string): number;
    getDynamicRules(): SASTRule[];
    clearDynamicRules(): void;
}
//# sourceMappingURL=zeroDaySyncEngine.d.ts.map