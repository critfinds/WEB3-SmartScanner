const parser = require('@solidity-parser/parser');
const fs = require('fs').promises;
const path = require('path');

// Import all detectors
const ReentrancyDetector = require('./detectors/reentrancy');
const IntegerOverflowDetector = require('./detectors/integer-overflow');
const AccessControlDetector = require('./detectors/access-control');
const UncheckedCallDetector = require('./detectors/unchecked-call');
const DelegateCallDetector = require('./detectors/delegatecall');
const FrontRunningDetector = require('./detectors/frontrunning');
const TimestampDependenceDetector = require('./detectors/timestamp');
const LogicBugDetector = require('./detectors/logic-bugs');
const UnprotectedSelfdestruct = require('./detectors/selfdestruct');
const PriceFeedManipulation = require('./detectors/price-feed');

// Advanced detectors (Slither-like capabilities)
const ShadowingDetector = require('./detectors/shadowing');
const TxOriginDetector = require('./detectors/tx-origin');
const UninitializedStorageDetector = require('./detectors/uninitialized-storage');
const MissingEventsDetector = require('./detectors/missing-events');
const AssemblyUsageDetector = require('./detectors/assembly-usage');
const DeadCodeDetector = require('./detectors/dead-code');
const StateMutabilityDetector = require('./detectors/state-mutability');
const InheritanceOrderDetector = require('./detectors/inheritance-order');
const TaintAnalysisDetector = require('./detectors/taint-analysis');

// Production-grade detectors (for high-value contracts)
const FlashLoanAttackDetector = require('./detectors/flashloan-attacks');
const SignatureReplayDetector = require('./detectors/signature-replay');
const PrecisionLossDetector = require('./detectors/precision-loss');
const GasGriefingDetector = require('./detectors/gas-griefing');

class Web3CRITScanner {
  constructor(options = {}) {
    this.options = {
      verbose: options.verbose || false,
      severity: options.severity || 'all', // all, critical, high, medium, low
      outputFormat: options.outputFormat || 'table', // table, json, detailed
      onProgress: options.onProgress || null, // Progress callback
      ...options
    };

    // Initialize all detectors
    this.detectors = [
      // CRITICAL: Production-grade detectors for high-value contracts
      new FlashLoanAttackDetector(),
      new SignatureReplayDetector(),
      new ReentrancyDetector(),
      new TaintAnalysisDetector(),
      new UninitializedStorageDetector(),
      new AccessControlDetector(),
      new DelegateCallDetector(),
      new UnprotectedSelfdestruct(),
      new PriceFeedManipulation(),

      // HIGH: Advanced vulnerability detection
      new PrecisionLossDetector(),
      new GasGriefingDetector(),
      new IntegerOverflowDetector(),
      new UncheckedCallDetector(),
      new FrontRunningDetector(),
      new TxOriginDetector(),
      new ShadowingDetector(),
      new LogicBugDetector(),

      // MEDIUM: Code quality and security best practices
      new TimestampDependenceDetector(),
      new AssemblyUsageDetector(),
      new InheritanceOrderDetector(),

      // LOW/INFO: Optimization and maintainability
      new MissingEventsDetector(),
      new DeadCodeDetector(),
      new StateMutabilityDetector()
    ];

    this.findings = [];
    this.stats = {
      filesScanned: 0,
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
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

    // Small delay to show parsing step
    await this.sleep(300);

    const contractFindings = [];
    const totalDetectors = this.detectors.length;

    // Run all detectors with progress
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
        const detectorFindings = await detector.detect(ast, sourceCode, fileName);
        contractFindings.push(...detectorFindings);

        // Delay to make progress visible (slower for critical detectors)
        const delay = detector.severity === 'CRITICAL' ? 150 : 80;
        await this.sleep(delay);
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
        message: 'Analyzing findings...',
        fileName
      });
    }

    await this.sleep(300);

    // Filter by severity if specified
    const filteredFindings = this.filterBySeverity(contractFindings);

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
    });
  }

  getFindings() {
    return {
      findings: this.findings,
      stats: this.stats
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
      info: 0
    };
  }
}

module.exports = Web3CRITScanner;
