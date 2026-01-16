const parser = require('@solidity-parser/parser');
const fs = require('fs').promises;
const path = require('path');

// Import enhanced analyzers
const ControlFlowAnalyzer = require('./analyzers/control-flow');
const DataFlowAnalyzer = require('./analyzers/data-flow');

// Import enhanced detectors only
const ReentrancyEnhancedDetector = require('./detectors/reentrancy-enhanced');
const AccessControlEnhancedDetector = require('./detectors/access-control-enhanced');

// Keep critical detectors that don't need enhancement
const UncheckedCallDetector = require('./detectors/unchecked-call');
const DelegateCallDetector = require('./detectors/delegatecall');
const UnprotectedSelfdestruct = require('./detectors/selfdestruct');

// Advanced Web3 vulnerability detectors
const IntegerOverflowDetector = require('./detectors/integer-overflow');
const FlashLoanDetector = require('./detectors/flash-loan');
const FrontRunningDetector = require('./detectors/frontrunning');
const TimestampDependenceDetector = require('./detectors/timestamp-dependence');
const GasGriefingDetector = require('./detectors/gas-griefing');
const DeprecatedFunctionsDetector = require('./detectors/deprecated-functions');

// High-value TVL contract detectors (NEW)
const ProxyVulnerabilitiesDetector = require('./detectors/proxy-vulnerabilities');
const SignatureReplayDetector = require('./detectors/signature-replay');
const CrossContractReentrancyDetector = require('./detectors/cross-contract-reentrancy');
const TokenStandardComplianceDetector = require('./detectors/token-standard-compliance');
const TOCTOUDetector = require('./detectors/toctou');

/**
 * Enhanced Web3CRIT Scanner
 * Uses control flow and data flow analysis instead of pattern matching
 */
class Web3CRITScannerEnhanced {
  constructor(options = {}) {
    this.options = {
      verbose: options.verbose || false,
      severity: options.severity || 'all',
      outputFormat: options.outputFormat || 'json',
      onProgress: options.onProgress || null,
      ...options
    };

    // Initialize enhanced detectors
    this.detectors = [
      // Enhanced detectors with CFG/dataflow analysis
      new ReentrancyEnhancedDetector(),
      new AccessControlEnhancedDetector(),

      // Keep simple detectors for operations that don't need deep analysis
      new UncheckedCallDetector(),
      new DelegateCallDetector(),
      new UnprotectedSelfdestruct(),

      // Advanced Web3 vulnerability detectors
      new IntegerOverflowDetector(),
      new FlashLoanDetector(),
      new FrontRunningDetector(),
      new TimestampDependenceDetector(),
      new GasGriefingDetector(),
      new DeprecatedFunctionsDetector(),

      // High-value TVL contract detectors (NEW - Priority Order)
      new ProxyVulnerabilitiesDetector(),        // CRITICAL: Proxy vulnerabilities
      new CrossContractReentrancyDetector(),     // CRITICAL: Cross-contract reentrancy
      new SignatureReplayDetector(),            // HIGH: Signature replay
      new TokenStandardComplianceDetector(),    // HIGH: ERC standard compliance
      new TOCTOUDetector()                      // HIGH: Time-of-check to time-of-use
    ];

    this.findings = [];
    this.stats = {
      filesScanned: 0,
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      exploitable: 0
    };
  }

  async scanFile(filePath) {
    try {
      const content = await fs.readFile(filePath, 'utf8');
      return await this.scanSource(content, filePath);
    } catch (error) {
      throw new Error(`Failed to read file ${filePath}: ${error.message}`);
    }
  }

  async scanSource(sourceCode, fileName = 'contract.sol') {
    this.stats.filesScanned++;

    // Progress: Parsing
    if (this.options.onProgress) {
      this.options.onProgress({
        stage: 'parsing',
        message: 'Parsing Solidity code...',
        fileName
      });
    }

    let ast;
    try {
      ast = parser.parse(sourceCode, {
        loc: true,
        range: true,
        tolerant: true
      });
    } catch (error) {
      throw new Error(`Failed to parse Solidity code: ${error.message}`);
    }

    // Progress: Building control flow graph
    if (this.options.onProgress) {
      this.options.onProgress({
        stage: 'analyzing',
        message: 'Building control flow graph...',
        fileName
      });
    }

    // Build control flow graph
    const cfgAnalyzer = new ControlFlowAnalyzer();
    const cfg = cfgAnalyzer.analyze(ast, sourceCode);

    // Progress: Data flow analysis
    if (this.options.onProgress) {
      this.options.onProgress({
        stage: 'analyzing',
        message: 'Performing data flow analysis...',
        fileName
      });
    }

    // Perform data flow analysis
    const dataFlowAnalyzer = new DataFlowAnalyzer(cfg);
    const dataFlow = dataFlowAnalyzer.analyze();

    const contractFindings = [];
    const totalDetectors = this.detectors.length;

    // Run enhanced detectors with CFG and data flow info
    for (let i = 0; i < this.detectors.length; i++) {
      const detector = this.detectors[i];

      // Progress: Running detector
      if (this.options.onProgress) {
        this.options.onProgress({
          stage: 'detecting',
          message: `Running detector: ${detector.name}`,
          detector: detector.name,
          current: i + 1,
          total: totalDetectors,
          fileName
        });
      }

      try {
        // Pass CFG and data flow to enhanced detectors
        const detectorFindings = await detector.detect(ast, sourceCode, fileName, cfg, dataFlow);
        contractFindings.push(...detectorFindings);
      } catch (error) {
        if (this.options.verbose) {
          console.error(`Detector ${detector.name} failed: ${error.message}`);
        }
      }
    }

    // Progress: Analyzing results
    if (this.options.onProgress) {
      this.options.onProgress({
        stage: 'filtering',
        message: 'Filtering exploitable issues...',
        fileName
      });
    }

    // Filter by severity and exploitability
    const filteredFindings = this.filterFindings(contractFindings);

    // Update statistics
    this.updateStats(filteredFindings);
    this.findings.push(...filteredFindings);

    return filteredFindings;
  }

  async sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async scanDirectory(dirPath) {
    const files = await this.getSolidityFiles(dirPath);
    const allFindings = [];
    const totalFiles = files.length;

    // Progress: Found files
    if (this.options.onProgress) {
      this.options.onProgress({
        stage: 'discovery',
        message: `Found ${totalFiles} Solidity file(s)`,
        totalFiles
      });
    }

    for (let i = 0; i < files.length; i++) {
      const file = files[i];

      // Progress: Scanning file
      if (this.options.onProgress) {
        this.options.onProgress({
          stage: 'file-scan',
          message: `Scanning file ${i + 1}/${totalFiles}`,
          fileName: file,
          currentFile: i + 1,
          totalFiles
        });
      }

      try {
        const findings = await this.scanFile(file);
        allFindings.push(...findings);
      } catch (error) {
        if (this.options.verbose) {
          console.error(`Error scanning ${file}: ${error.message}`);
        }
      }
    }

    return allFindings;
  }

  async getSolidityFiles(dirPath) {
    const files = [];

    async function traverse(currentPath) {
      const entries = await fs.readdir(currentPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(currentPath, entry.name);

        if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
          await traverse(fullPath);
        } else if (entry.isFile() && entry.name.endsWith('.sol')) {
          files.push(fullPath);
        }
      }
    }

    await traverse(dirPath);
    return files;
  }

  /**
   * Filter findings by severity, exploitability, and confidence
   * Only report issues that are realistically exploitable with high confidence
   */
  filterFindings(findings) {
    // Filter by severity level
    let filtered = this.filterBySeverity(findings);

    // Apply exploitability-based filtering
    filtered = filtered.filter(finding => {
      // Always report high-confidence findings
      if (finding.isHighConfidence === true) {
        return true;
      }

      // Always report CRITICAL severity with exploitable flag
      if (finding.severity === 'CRITICAL' && finding.exploitable === true) {
        return true;
      }

      // Report HIGH severity with high/medium confidence
      if (finding.severity === 'HIGH') {
        if (finding.confidence === 'HIGH') return true;
        if (finding.confidence === 'MEDIUM' && finding.exploitable === true) return true;
      }

      // Report MEDIUM severity only with high confidence AND exploitable
      if (finding.severity === 'MEDIUM') {
        if (finding.confidence === 'HIGH' && finding.exploitable === true) return true;
        // Also include medium confidence if exploitability score is high
        if (finding.exploitabilityScore >= 60) return true;
      }

      // Filter out low confidence, non-exploitable findings
      if (finding.confidence === 'LOW' && finding.exploitable === false) {
        return false;
      }

      // Filter out low severity with low confidence
      if (finding.severity === 'LOW' && finding.confidence === 'LOW') {
        return false;
      }

      // Filter out INFO level unless high confidence
      if (finding.severity === 'INFO' && finding.confidence !== 'HIGH') {
        return false;
      }

      // Default: include if exploitability score >= 50
      return finding.exploitabilityScore >= 50;
    });

    // Sort by exploitability score (highest first)
    filtered.sort((a, b) => {
      // First by severity
      const severityOrder = { 'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1 };
      const severityDiff = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
      if (severityDiff !== 0) return severityDiff;

      // Then by exploitability score
      return (b.exploitabilityScore || 0) - (a.exploitabilityScore || 0);
    });

    return filtered;
  }

  filterBySeverity(findings) {
    if (this.options.severity === 'all') {
      return findings;
    }

    const severityLevels = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      info: 1
    };

    const minLevel = severityLevels[this.options.severity] || 0;

    return findings.filter(f =>
      severityLevels[f.severity.toLowerCase()] >= minLevel
    );
  }

  updateStats(findings) {
    findings.forEach(finding => {
      this.stats.totalFindings++;
      const severity = finding.severity.toLowerCase();
      if (this.stats[severity] !== undefined) {
        this.stats[severity]++;
      }
      if (finding.exploitable === true) {
        this.stats.exploitable++;
      }
    });
  }

  getFindings() {
    // Separate high-confidence findings
    const highConfidenceFindings = this.findings.filter(f => f.isHighConfidence);
    const otherFindings = this.findings.filter(f => !f.isHighConfidence);

    return {
      findings: this.findings,
      highConfidenceFindings: highConfidenceFindings,
      stats: {
        ...this.stats,
        highConfidence: highConfidenceFindings.length,
        withPoC: this.findings.filter(f => f.foundryPoC).length
      },
        analysis: {
        engine: 'enhanced',
        version: '5.2.0',
        features: [
          'Control Flow Analysis',
          'Data Flow Analysis',
          'Cross-Function Reentrancy Detection',
          'Cross-Contract Reentrancy Detection',
          'Modifier Logic Validation',
          'Exploitability Scoring (0-100)',
          'Attack Vector Classification',
          'Context-Aware Detection',
          'False Positive Reduction',
          'Foundry PoC Generation',
          'Integer Overflow/Underflow Detection',
          'Flash Loan Attack Detection',
          'Front-Running/MEV Protection',
          'Timestamp Manipulation Detection',
          'Gas Griefing/DoS Prevention',
          'Proxy Contract Vulnerabilities (UUPS, Transparent)',
          'Signature Replay Protection',
          'Token Standard Compliance (ERC20/721/1155)',
          'TOCTOU (Time-of-Check to Time-of-Use) Detection'
        ]
      }
    };
  }

  /**
   * Get high-confidence findings with Foundry PoC templates
   * Only returns findings that meet the high-confidence threshold
   */
  getHighConfidenceFindings() {
    return this.findings.filter(f => f.isHighConfidence && f.foundryPoC);
  }

  /**
   * Generate Foundry test file with all high-confidence PoCs
   * @param {string} contractName - Name for the test file
   * @returns {string} Complete Foundry test file content
   */
  generateFoundryTestFile(contractName = 'VulnerabilityExploits') {
    const pocFindings = this.getHighConfidenceFindings();

    if (pocFindings.length === 0) {
      return null;
    }

    const header = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Foundry Proof of Concept Tests
 * Generated by Web3CRIT Scanner v5.1.0
 *
 * High-Confidence Findings: ${pocFindings.length}
 *
 * To run: forge test --match-contract ${contractName} -vvv
 */
`;

    const contracts = pocFindings.map((finding, index) => {
      const testName = this.sanitizeTestName(finding.title);
      const attackVector = finding.attackVector || 'unknown';

      return `
/**
 * Finding #${index + 1}: ${finding.title}
 * Severity: ${finding.severity}
 * Confidence: ${finding.confidence}
 * Exploitability Score: ${finding.exploitabilityScore}/100
 * Attack Vector: ${attackVector}
 * File: ${finding.fileName}:${finding.line}
 *
 * Description: ${finding.description}
 */
${finding.foundryPoC}
`;
    }).join('\n');

    return header + contracts;
  }

  /**
   * Sanitize a title into a valid Solidity test function name
   */
  sanitizeTestName(title) {
    return title
      .replace(/[^a-zA-Z0-9\s]/g, '')
      .split(/\s+/)
      .map((word, i) => i === 0 ? word.toLowerCase() : word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join('');
  }

  /**
   * Get summary of findings by attack vector
   */
  getFindingsSummary() {
    const byVector = {};
    const bySeverity = {};

    for (const finding of this.findings) {
      // By attack vector
      const vector = finding.attackVector || 'unknown';
      if (!byVector[vector]) {
        byVector[vector] = { count: 0, highConfidence: 0, findings: [] };
      }
      byVector[vector].count++;
      if (finding.isHighConfidence) {
        byVector[vector].highConfidence++;
      }
      byVector[vector].findings.push({
        title: finding.title,
        severity: finding.severity,
        exploitabilityScore: finding.exploitabilityScore
      });

      // By severity
      const severity = finding.severity;
      if (!bySeverity[severity]) {
        bySeverity[severity] = 0;
      }
      bySeverity[severity]++;
    }

    return {
      total: this.findings.length,
      highConfidence: this.findings.filter(f => f.isHighConfidence).length,
      withPoC: this.findings.filter(f => f.foundryPoC).length,
      byAttackVector: byVector,
      bySeverity: bySeverity,
      topExploitable: this.findings
        .filter(f => f.exploitabilityScore >= 70)
        .sort((a, b) => b.exploitabilityScore - a.exploitabilityScore)
        .slice(0, 5)
        .map(f => ({
          title: f.title,
          severity: f.severity,
          score: f.exploitabilityScore,
          vector: f.attackVector
        }))
    };
  }

  reset() {
    this.findings = [];
    this.stats = {
      filesScanned: 0,
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      exploitable: 0
    };
  }
}

module.exports = Web3CRITScannerEnhanced;
