import { VulnerabilityFinding } from '../types/index.js';
export interface BusinessLogicViolation {
    type: 'IDOR_BOLA' | 'PRICE_TAMPERING' | 'NEGATIVE_AMOUNT_TAMPERING' | 'FINANCIAL_TOCTOU_RACE';
    severity: 'CRITICAL' | 'HIGH';
    title: string;
    description: string;
    remediationAdvice: string;
    cwe: string;
    owasp: string;
    lineStart: number;
    lineEnd: number;
    snippet: string;
    pocScenario: string;
}
export declare class BusinessLogicAnalyzer {
    /**
     * Performs Semantic AI Reasoning across function scopes to detect business logic vulnerabilities
     * that evade conventional regex / AST scanners (such as IDOR, price tampering, negative balance exploits).
     */
    analyze(filePath: string, content: string): VulnerabilityFinding[];
    /**
     * Detects Broken Object Level Authorization (BOLA/IDOR) in sensitive financial or mutation endpoints.
     */
    private detectIdorBola;
    /**
     * Detects Client-Side Price Tampering (e-commerce logic vulnerability).
     */
    private detectPriceTampering;
    /**
     * Detects Negative Amount Transfer Glitch (allowing reversal of balance deduction into addition).
     */
    private detectNegativeAmountFlaw;
    /**
     * Detects TOCTOU (Time-of-Check to Time-of-Use) race condition in financial balance checks.
     */
    private detectFinancialToctou;
}
//# sourceMappingURL=businessLogicAnalyzer.d.ts.map