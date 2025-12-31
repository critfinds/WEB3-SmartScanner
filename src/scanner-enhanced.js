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
      new UnprotectedSelfdestruct()
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

    await this.sleep(200);

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

    await this.sleep(200);

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

    await this.sleep(200);

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

        await this.sleep(150);
      } catch (error) {
        if (this.options.verbose) {
          console.error(`Detector ${detector.name} failed: ${error.message}`);
        }
      }
    }

    // Progress: Analyzing results
    if (this.options.onProgress) {
      this.options.onProgress({
        stage: 'analyzing',
        message: 'Filtering exploitable issues...',
        fileName
      });
    }

    await this.sleep(200);

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

    await this.sleep(200);

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
   * Filter findings by severity and exploitability
   * Only report issues that are realistically exploitable
   */
  filterFindings(findings) {
    // Filter by severity level
    let filtered = this.filterBySeverity(findings);

    // Only report exploitable issues (or high confidence non-exploitable warnings)
    filtered = filtered.filter(finding => {
      // Always report CRITICAL and HIGH severity with exploitable flag
      if (finding.exploitable === true) {
        return true;
      }

      // Report high confidence findings even if not marked exploitable
      if (finding.confidence === 'HIGH' && finding.severity === 'CRITICAL') {
        return true;
      }

      // Filter out low confidence, non-exploitable findings
      if (finding.confidence === 'LOW' && finding.exploitable === false) {
        return false;
      }

      return true;
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
    return {
      findings: this.findings,
      stats: this.stats,
      analysis: {
        engine: 'enhanced',
        version: '4.0.0',
        features: [
          'Control Flow Analysis',
          'Data Flow Analysis',
          'Cross-Function Reentrancy Detection',
          'Modifier Logic Validation',
          'Exploitability Verification'
        ]
      }
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
