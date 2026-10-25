import { VulnerabilityFinding, Severity } from '../types/index.js';
export interface DependencyVulnerability {
    id: string;
    packageName: string;
    ecosystem: 'npm' | 'pypi' | 'crates' | 'golang' | 'maven' | 'packagist';
    vulnerableRange: string;
    fixedVersion: string;
    severity: Severity;
    cwe: string;
    title: string;
    description: string;
    exploitPoC?: string;
    referenceUrl?: string;
}
export interface ParsedDependency {
    name: string;
    rawVersion: string;
    cleanVersion: string;
    line: number;
    filePath: string;
    ecosystem: 'npm' | 'pypi' | 'crates' | 'golang' | 'maven' | 'packagist';
}
/**
 * Embedded Knowledge Base of Critical & High Severity CVEs across Ecosystems
 */
export declare const KNOWN_DEPENDENCY_CVES: DependencyVulnerability[];
export declare class ScaScanner {
    /**
     * Scans a target project for all manifest files and identifies vulnerable dependencies and plugins.
     */
    scanProject(targetDir: string): Promise<VulnerabilityFinding[]>;
    /**
     * Scans a single manifest file content synchronously against local database.
     */
    scanManifestFileSync(fullPath: string, relPath: string, content: string): VulnerabilityFinding[];
    /**
     * Scans a single manifest file content.
     */
    scanManifestFile(fullPath: string, relPath: string, content: string): Promise<VulnerabilityFinding[]>;
    /**
     * Parses package.json dependencies
     */
    private parsePackageJson;
    /**
     * Parses package-lock.json packages
     */
    private parsePackageLockJson;
    /**
     * Parses requirements.txt for Python
     */
    private parseRequirementsTxt;
    /**
     * Parses Cargo.toml for Rust
     */
    private parseCargoToml;
    /**
     * Parses go.mod for Golang
     */
    private parseGoMod;
    /**
     * Parses pom.xml for Java Maven
     */
    private parsePomXml;
    /**
     * Parses composer.json for PHP
     */
    private parseComposerJson;
    /**
     * Cleans versions like ^1.2.3, ~2.3.4, >=1.0.0 to pure numeric semver (e.g. 1.2.3)
     */
    cleanVersionString(ver: string): string;
    /**
     * Evaluates if a version falls within a vulnerable range (e.g. "< 4.17.21")
     */
    isVersionVulnerable(currentVer: string, vulnerableRange: string): boolean;
    /**
     * Semver numeric comparison (returns -1 if v1 < v2, 0 if v1 === v2, 1 if v1 > v2)
     */
    compareVersions(v1: string, v2: string): number;
    /**
     * Constructs a full confirmed VulnerabilityFinding
     */
    private createFinding;
    /**
     * Fast query to Google's Open Source Vulnerabilities (OSV) API for Zero-Day CVEs
     */
    private queryOsvApi;
    /**
     * Discovers all supported manifest files in the directory
     */
    private findManifestFiles;
}
//# sourceMappingURL=scaScanner.d.ts.map