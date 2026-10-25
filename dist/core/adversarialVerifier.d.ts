import { VulnerabilityFinding } from '../types/index.js';
export declare class AdversarialVerifier {
    /**
     * Evaluates findings with skeptical adversarial checks to eliminate false positives
     * and enriches confirmed findings with threat intelligence PoCs and fixes.
     */
    verifyFinding(finding: VulnerabilityFinding, fileContent?: string): VulnerabilityFinding;
    private generatePoC;
    private generateFixDiff;
}
//# sourceMappingURL=adversarialVerifier.d.ts.map