export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingStatus = 'CANDIDATE' | 'CONFIRMED' | 'DISPROVED' | 'NEEDS_HUMAN';
export interface CodeLocation {
    filePath: string;
    lineStart: number;
    lineEnd: number;
    columnStart?: number;
    columnEnd?: number;
    snippet: string;
}
export interface TaintFlow {
    source: string;
    sink: string;
    sanitizerCheck?: string;
    isTainted: boolean;
    flowPath: string[];
}
export type ThreatIntelSource = 'IMMUNEFI' | 'CODE4RENA' | 'SHERLOCK' | 'NVD_CVE' | 'GITHUB_ADVISORY' | 'OWASP' | 'CLOUDFLARE_RESEARCH' | 'TRAIL_OF_BITS' | 'COMMUNITY' | 'CUSTOM';
export interface ThreatCorrelation {
    reportId: string;
    title: string;
    source: ThreatIntelSource;
    similarityScore: number;
    attackVariant: string;
    vulnerabilityClass: string;
    exploitMechanism: string;
    referenceUrl?: string;
}
export interface VulnerabilityFinding {
    id: string;
    ruleId: string;
    title: string;
    severity: Severity;
    category: string;
    cwe?: string;
    owasp?: string;
    location: CodeLocation;
    description: string;
    status: FindingStatus;
    taintFlow?: TaintFlow;
    correlatedReports?: ThreatCorrelation[];
    adversarialVerification?: {
        verifier: string;
        verdict: 'CONFIRMED' | 'FALSE_POSITIVE' | 'NEEDS_CONTEXT';
        argument: string;
        counterEvidence?: string;
        confidence: number;
    };
    reproductionPoC?: string;
    remediation?: {
        explanation: string;
        unifiedDiff?: string;
        replacementCode?: string;
    };
    timestamp: string;
}
export interface AttackSurfaceEntry {
    type: 'HTTP_API' | 'WEBSOCKET' | 'RPC' | 'SMART_CONTRACT' | 'CLI_ARG' | 'FILE_IO' | 'ENV_VAR' | 'AI_PROMPT_INPUT';
    identifier: string;
    location: CodeLocation;
    authRequired: boolean;
    notes?: string;
}
export interface CoverageLedger {
    targetRoot: string;
    timestamp: string;
    totalFiles: number;
    analyzedFiles: string[];
    skippedFiles: {
        path: string;
        reason: string;
    }[];
    attackSurfaces: AttackSurfaceEntry[];
    completionPercentage: number;
}
export interface ThreatReport {
    id: string;
    title: string;
    source: ThreatIntelSource;
    date: string;
    severity: Severity;
    category: string;
    targetEcosystem: 'WEB2' | 'WEB3_EVM' | 'WEB3_SOLANA' | 'AI_AGENT' | 'CLOUD' | 'GENERAL';
    vulnerabilityClass: string;
    attackVariants: string[];
    triggerPatterns: string[];
    summary: string;
    exploitMechanism: string;
    mitigation: string;
    referenceUrl?: string;
}
export interface ThreatIntelSummary {
    totalLearnedReports: number;
    totalAttackVariants: number;
    matchedReportsCount: number;
    detectedVariants: string[];
}
export interface AuditReport {
    title: string;
    generatedBy: string;
    targetRoot: string;
    createdAt: string;
    stats: {
        totalFindings: number;
        confirmed: number;
        candidates: number;
        disproved: number;
        bySeverity: Record<Severity, number>;
    };
    threatIntel?: ThreatIntelSummary;
    coverage: CoverageLedger;
    findings: VulnerabilityFinding[];
}
export interface SASTRule {
    id: string;
    name: string;
    severity: Severity;
    category: 'INJECTION' | 'AUTH' | 'CRYPTO' | 'WEB3' | 'AI_AGENT' | 'SECRET' | 'RACE_CONDITION' | 'DESERIALIZATION' | 'MISCONFIG' | 'DOS' | 'CLOUD' | 'BUSINESS_LOGIC' | 'DEPENDENCY';
    cwe: string;
    owasp: string;
    languages: string[];
    pattern: RegExp;
    validate?: (match: RegExpExecArray, fileContent: string, filePath: string) => boolean;
    description: string;
    remediationAdvice: string;
}
export interface BenchmarkCase {
    id: string;
    suite: 'OWASP_BENCHMARK' | 'NIST_JULIET' | 'CYBERSEC_EVAL' | 'WEB3_DEFENSE' | 'REAL_WORLD_CVE' | 'BUSINESS_LOGIC_IDOR' | 'ZERO_DAY_LIVE_INGEST' | 'DEPENDENCY_SCA';
    category: string;
    cwe: string;
    name: string;
    isVulnerable: boolean;
    language: string;
    filename: string;
    code: string;
    deceptiveTrap: string;
}
export interface SuiteMetrics {
    suiteName: string;
    totalCases: number;
    truePositives: number;
    falsePositives: number;
    trueNegatives: number;
    falseNegatives: number;
    precision: number;
    recall: number;
    falsePositiveRate: number;
    f1Score: number;
    owaspBenchmarkScore: number;
}
export interface CompetitorBenchmarkRecord {
    engineName: string;
    type: string;
    owaspBenchmarkScore: number;
    tpr: number;
    fpr: number;
    f1Score: number;
    executionTimeSec: number;
    adversarialFilterRate: number;
    pocGenerationRate: number;
    automatedFixRate: number;
}
//# sourceMappingURL=index.d.ts.map