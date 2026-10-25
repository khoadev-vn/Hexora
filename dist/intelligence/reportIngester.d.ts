import { ThreatReport } from '../types/index.js';
import { ThreatKnowledgeBase } from './threatKnowledgeBase.js';
export declare class ReportIngester {
    private kb;
    constructor(kb?: ThreatKnowledgeBase);
    /**
     * Ingests a report from a file path (Markdown or JSON)
     */
    ingestFile(filePath: string): Promise<ThreatReport>;
    /**
     * Ingests all reports from a folder
     */
    ingestDirectory(dirPath: string): Promise<ThreatReport[]>;
    /**
     * Ingests an ad-hoc unstructured or structured writeup text
     */
    ingestRawText(title: string, text: string, options?: Partial<ThreatReport>): Promise<ThreatReport>;
    private parseJsonReport;
    private parseMarkdownReport;
}
//# sourceMappingURL=reportIngester.d.ts.map