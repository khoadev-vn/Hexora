import { AuditReport, VulnerabilityFinding, CoverageLedger } from '../types/index.js';
export declare class ReportGenerator {
    static buildReport(targetRoot: string, findings: VulnerabilityFinding[], coverage: CoverageLedger): AuditReport;
    static toMarkdown(report: AuditReport): string;
    static toSarif(report: AuditReport): string;
    static toHtml(report: AuditReport): string;
    static toStructuredText(report: AuditReport): string;
    static toPdf(report: AuditReport): Buffer;
}
//# sourceMappingURL=reportGenerator.d.ts.map