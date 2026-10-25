import fs from 'node:fs';
import path from 'node:path';
import { ThreatReport, SASTRule, Severity } from '../types/index.js';
import { ThreatKnowledgeBase } from './threatKnowledgeBase.js';

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
  sinkPatternRegex: string; // Dynamic sink regex extracted from advisory
  attackVariants: string[];
  exploitMechanism: string;
  mitigation: string;
  referenceUrl?: string;
}

export class ZeroDaySyncEngine {
  private static instance: ZeroDaySyncEngine;
  private threatKb: ThreatKnowledgeBase;
  private dynamicRules: SASTRule[] = [];

  private constructor() {
    this.threatKb = ThreatKnowledgeBase.getInstance();
  }

  public static getInstance(): ZeroDaySyncEngine {
    if (!ZeroDaySyncEngine.instance) {
      ZeroDaySyncEngine.instance = new ZeroDaySyncEngine();
    }
    return ZeroDaySyncEngine.instance;
  }

  /**
   * Ingests a live Zero-Day security advisory (published minutes or hours ago on GitHub / NVD)
   * and immediately synthesizes dynamic SAST detection rules and Threat KB correlations in real-time.
   */
  public ingestZeroDayAdvisory(advisory: ZeroDayAdvisoryPayload): { synthesizedRule: SASTRule; threatReport: ThreatReport } {
    // 1. Synthesize Dynamic Threat Report
    const threatReport: ThreatReport = {
      id: `0DAY-${advisory.cveId}`,
      title: `[LIVE 0-DAY] ${advisory.title}`,
      source: advisory.source,
      date: advisory.publishedDate || new Date().toISOString().split('T')[0],
      severity: advisory.severity,
      category: advisory.targetEcosystem === 'WEB3_EVM' || advisory.targetEcosystem === 'WEB3_SOLANA' ? 'WEB3' : advisory.targetEcosystem === 'AI_AGENT' ? 'AI_AGENT' : 'INJECTION',
      targetEcosystem: advisory.targetEcosystem,
      vulnerabilityClass: advisory.vulnerabilityClass,
      attackVariants: advisory.attackVariants,
      triggerPatterns: [advisory.sinkPatternRegex],
      summary: `Autonomous live threat ingestion for ${advisory.cveId}: ${advisory.exploitMechanism}`,
      exploitMechanism: advisory.exploitMechanism,
      mitigation: advisory.mitigation,
      referenceUrl: advisory.referenceUrl || `https://github.com/advisories/${advisory.cveId}`
    };

    // Register into Threat Knowledge Base
    this.threatKb.registerReport(threatReport);

    // 2. Synthesize High-Precision Dynamic SAST Rule
    let patternReg: RegExp;
    try {
      patternReg = new RegExp(advisory.sinkPatternRegex, 'i');
    } catch {
      patternReg = new RegExp(advisory.sinkPatternRegex.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    }

    const synthesizedRule: SASTRule = {
      id: `HEX-0DAY-${advisory.cveId.replace(/[^a-zA-Z0-9_-]/g, '_')}`,
      name: `Zero-Day Threat: ${advisory.title}`,
      severity: advisory.severity,
      category: threatReport.category as any,
      cwe: advisory.cwe,
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      languages: ['js', 'ts', 'py', 'sol', 'rs', 'go'],
      pattern: patternReg,
      description: `Discovered in real-time threat feed. ${advisory.exploitMechanism}`,
      remediationAdvice: advisory.mitigation
    };

    this.dynamicRules.push(synthesizedRule);

    return { synthesizedRule, threatReport };
  }

  /**
   * Bulk synchronizes zero-day advisories from a remote feed or local threat feed directory.
   */
  public syncLiveFeeds(feedPathOrJson: string): number {
    let count = 0;
    try {
      let data: ZeroDayAdvisoryPayload[] = [];
      if (fs.existsSync(feedPathOrJson)) {
        const raw = fs.readFileSync(feedPathOrJson, 'utf-8');
        data = JSON.parse(raw);
      } else {
        data = JSON.parse(feedPathOrJson);
      }

      if (Array.isArray(data)) {
        for (const adv of data) {
          this.ingestZeroDayAdvisory(adv);
          count++;
        }
      }
    } catch {
      // Ignore parse errors on corrupt feeds
    }
    return count;
  }

  public getDynamicRules(): SASTRule[] {
    return [...this.dynamicRules];
  }

  public clearDynamicRules(): void {
    this.dynamicRules = [];
  }
}
