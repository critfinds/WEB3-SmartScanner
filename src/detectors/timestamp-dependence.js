const BaseDetector = require('./base-detector');

/**
 * Timestamp Dependence Detector (Enhanced)
 * Detects dangerous reliance on block.timestamp with time-scale awareness
 * to reduce false positives for legitimate long-term calculations.
 */
class TimestampDependenceDetector extends BaseDetector {
  constructor() {
    super(
      'Timestamp Dependence',
      'Detects dangerous reliance on block.timestamp',
      'MEDIUM'
    );
    this.currentContract = null;
    this.currentFunction = null;
    this.currentFunctionNode = null;
    this.timestampUsages = [];

    // Miner manipulation window in seconds (~15 seconds)
    this.MANIPULATION_WINDOW = 15;
    // Safe threshold - windows longer than this have minimal manipulation impact
    this.SAFE_WINDOW_THRESHOLD = 3600; // 1 hour in seconds
    // Very safe threshold - negligible impact
    this.VERY_SAFE_THRESHOLD = 86400; // 1 day in seconds
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.timestampUsages = [];

    this.traverse(ast);

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'constructor';
    this.currentFunctionNode = node;
  }

  visitMemberAccess(node) {
    // Check for block.timestamp usage
    if (node.expression &&
        node.expression.type === 'Identifier' &&
        node.expression.name === 'block') {

      if (node.memberName === 'timestamp' || node.memberName === 'number') {
        this.analyzeTimestampUsage(node);
      }
    }

    // Also check for 'now' keyword (deprecated but still used)
    if (node.memberName === 'now') {
      this.reportNowUsage(node);
    }
  }

  visitIdentifier(node) {
    // Check for direct 'now' usage (deprecated)
    if (node.name === 'now') {
      this.reportNowUsage(node);
    }
  }

  analyzeTimestampUsage(node) {
    // Get surrounding context
    const parentContext = this.getParentContext(node);
    const code = this.getCodeSnippet(node.loc);

    // 1. CRITICAL: Randomness based on timestamp - always dangerous
    if (this.isUsedForRandomness(parentContext)) {
      this.reportTimestampRandomness(node);
      return;
    }

    // 2. HIGH: Equality comparison with timestamp - usually a bug
    if (this.isEqualityComparison(parentContext)) {
      this.reportTimestampEquality(node);
      return;
    }

    // 3. Analyze time windows with scale awareness
    const timeWindowAnalysis = this.analyzeTimeWindow(parentContext);

    if (timeWindowAnalysis.hasTimeWindow) {
      if (timeWindowAnalysis.isCritical) {
        this.reportCriticalTimeWindow(node, timeWindowAnalysis);
        return;
      } else if (timeWindowAnalysis.isRisky) {
        this.reportShortTimeWindow(node, timeWindowAnalysis);
        return;
      }
      // Safe time windows (>1 hour) are not reported
    }

    // 4. Financial calculations - analyze impact scale
    if (this.isFinancialCalculation(parentContext)) {
      const financialRisk = this.analyzeFinancialImpact(parentContext);
      if (financialRisk.isSignificant) {
        this.reportTimestampFinancial(node, financialRisk);
      }
      // Don't report low-impact financial calculations
      return;
    }

    // 5. Access control - analyze the lock duration
    if (this.isAccessControl(parentContext)) {
      const accessRisk = this.analyzeAccessControlRisk(parentContext);
      if (accessRisk.isExploitable) {
        this.reportTimestampAccessControl(node, accessRisk);
      }
      return;
    }
  }

  getParentContext(node) {
    // Get lines around the timestamp usage
    if (!node.loc) return '';
    const startLine = Math.max(0, node.loc.start.line - 5);
    const endLine = Math.min(this.sourceLines.length, node.loc.start.line + 5);
    return this.sourceLines.slice(startLine, endLine).join('\n');
  }

  isUsedForRandomness(context) {
    const randomKeywords = ['random', 'seed', 'entropy'];
    const contextLower = context.toLowerCase();

    // Must be in a randomness context AND use hashing
    const hasRandomContext = randomKeywords.some(kw => contextLower.includes(kw));
    const hasHashing = /keccak256|sha3|hash/i.test(context);

    return hasRandomContext || (hasHashing && /timestamp|block\.number/i.test(context));
  }

  isEqualityComparison(context) {
    // Check for exact equality with timestamp (common bug)
    // Look for patterns like: timestamp == value or value == timestamp
    const exactEquality = /block\.timestamp\s*==|==\s*block\.timestamp/i.test(context);
    return exactEquality;
  }

  /**
   * Analyze time window with awareness of manipulation impact
   */
  analyzeTimeWindow(context) {
    const result = {
      hasTimeWindow: false,
      windowSize: 0,
      isCritical: false,
      isRisky: false,
      reason: ''
    };

    // Extract time constants - handle Solidity time units
    const timeUnits = {
      'seconds': 1,
      'second': 1,
      'minutes': 60,
      'minute': 60,
      'hours': 3600,
      'hour': 3600,
      'days': 86400,
      'day': 86400,
      'weeks': 604800,
      'week': 604800
    };

    // Pattern: number followed by optional time unit
    const timePattern = /(\d+)\s*(seconds?|minutes?|hours?|days?|weeks?)?/gi;
    let match;
    let smallestWindow = Infinity;

    while ((match = timePattern.exec(context)) !== null) {
      const value = parseInt(match[1]);
      const unit = match[2] ? match[2].toLowerCase() : 'seconds';
      const multiplier = timeUnits[unit] || 1;
      const windowInSeconds = value * multiplier;

      if (windowInSeconds > 0 && windowInSeconds < smallestWindow) {
        smallestWindow = windowInSeconds;
      }
    }

    if (smallestWindow !== Infinity) {
      result.hasTimeWindow = true;
      result.windowSize = smallestWindow;

      // Calculate manipulation impact
      const manipulationPercent = (this.MANIPULATION_WINDOW / smallestWindow) * 100;

      if (smallestWindow < 60) {
        // Less than 1 minute - critical
        result.isCritical = true;
        result.reason = `Time window of ${smallestWindow}s can be significantly manipulated (${manipulationPercent.toFixed(1)}% of window)`;
      } else if (smallestWindow < this.SAFE_WINDOW_THRESHOLD) {
        // Between 1 minute and 1 hour - risky
        result.isRisky = true;
        result.reason = `Time window of ${this.formatDuration(smallestWindow)} has ${manipulationPercent.toFixed(1)}% manipulation risk`;
      }
      // >= 1 hour is considered safe (less than 0.4% manipulation)
    }

    return result;
  }

  /**
   * Analyze if financial calculation has meaningful impact from timestamp manipulation
   */
  analyzeFinancialImpact(context) {
    const result = {
      isSignificant: false,
      impactReason: '',
      confidence: 'LOW'
    };

    const contextLower = context.toLowerCase();

    // Check if this is a long-term calculation (days/weeks/years)
    const longTermPatterns = /days?|weeks?|years?|annual|monthly/i;
    const isLongTerm = longTermPatterns.test(context);

    // Check for high-value operations
    const highValueOps = /liquidat|collateral|borrow|lend|stake|unstake/i;
    const isHighValue = highValueOps.test(context);

    // Short-term, high-frequency rewards are risky
    const shortTermRewards = /reward|claim|harvest/i.test(context) &&
                            /block|second|minute/i.test(context);

    if (shortTermRewards) {
      result.isSignificant = true;
      result.impactReason = 'Short-term reward calculation where 15s manipulation could affect immediate payouts';
      result.confidence = 'MEDIUM';
    } else if (isHighValue && !isLongTerm) {
      result.isSignificant = true;
      result.impactReason = 'High-value financial operation without long-term averaging';
      result.confidence = 'MEDIUM';
    }
    // Long-term APY/interest calculations are not significant
    // 15 seconds out of 365 days = 0.0000005% impact

    return result;
  }

  /**
   * Analyze access control timestamp risk
   */
  analyzeAccessControlRisk(context) {
    const result = {
      isExploitable: false,
      reason: '',
      severity: 'MEDIUM'
    };

    // Check for timelock patterns
    const timelockPatterns = /unlock|lock|delay|cliff|vesting/i;
    const hasTimelock = timelockPatterns.test(context);

    // Extract the timelock duration if possible
    const timeAnalysis = this.analyzeTimeWindow(context);

    if (hasTimelock && timeAnalysis.hasTimeWindow) {
      if (timeAnalysis.windowSize < 3600) {
        // Less than 1 hour timelock - exploitable
        result.isExploitable = true;
        result.reason = `Timelock of ${this.formatDuration(timeAnalysis.windowSize)} can be bypassed via ~15s timestamp manipulation`;
        result.severity = 'HIGH';
      } else if (timeAnalysis.windowSize < 86400) {
        // 1-24 hour timelock - minor risk
        result.isExploitable = true;
        result.reason = `Timelock could be slightly shortened via timestamp manipulation (minor impact)`;
        result.severity = 'LOW';
      }
      // Timelocks >= 1 day are effectively safe
    } else if (!hasTimelock) {
      // Generic timestamp access control without clear timelock
      // Only flag if it appears to be a short window check
      if (timeAnalysis.isCritical || timeAnalysis.isRisky) {
        result.isExploitable = true;
        result.reason = 'Short-duration timestamp check can be manipulated';
        result.severity = 'MEDIUM';
      }
    }

    return result;
  }

  isFinancialCalculation(context) {
    const financialKeywords = ['interest', 'rate', 'reward', 'yield', 'apr', 'apy', 'compound', 'stake', 'earn'];
    const contextLower = context.toLowerCase();
    return financialKeywords.some(kw => contextLower.includes(kw));
  }

  isAccessControl(context) {
    // More specific: must be in a require/if with comparison
    const hasCondition = /require\s*\(|if\s*\(/i.test(context);
    const hasComparison = /[<>=]/.test(context);
    return hasCondition && hasComparison;
  }

  formatDuration(seconds) {
    if (seconds < 60) return `${seconds} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    return `${Math.round(seconds / 86400)} days`;
  }

  reportNowUsage(node) {
    this.addFinding({
      title: 'Deprecated "now" Keyword Usage',
      description: `Using deprecated 'now' keyword which is alias for block.timestamp. This should be replaced with block.timestamp for clarity.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'INFO',
      confidence: 'HIGH',
      exploitable: false,
      recommendation: 'Replace "now" with "block.timestamp" for Solidity 0.7+ compatibility.',
      references: [
        'https://docs.soliditylang.org/en/latest/units-and-global-variables.html'
      ]
    });
  }

  reportTimestampRandomness(node) {
    this.addFinding({
      title: 'Timestamp Used for Randomness',
      description: `Block timestamp or block number used in randomness generation. Miners/validators can manipulate block.timestamp within ~15 seconds to influence outcomes.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'CRITICAL',
      confidence: 'HIGH',
      exploitable: true,
      exploitabilityScore: 90,
      attackVector: 'miner-timestamp-manipulation',
      recommendation: 'Use Chainlink VRF for verifiable randomness. Never use block.timestamp, block.number, or blockhash for randomness in applications with economic value.',
      references: [
        'https://swcregistry.io/docs/SWC-120',
        'https://docs.chain.link/vrf'
      ],
      foundryPoC: this.generateRandomnessPoC()
    });
  }

  reportTimestampEquality(node) {
    this.addFinding({
      title: 'Timestamp Equality Comparison',
      description: `Exact equality comparison (==) with block.timestamp. This condition is unreliable - the exact timestamp value is unpredictable and may never match.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'HIGH',
      confidence: 'HIGH',
      exploitable: false,
      exploitabilityScore: 0,
      recommendation: 'Use range comparisons (>=, <=) instead of equality. Example: require(block.timestamp >= deadline) instead of require(block.timestamp == deadline).',
      references: [
        'https://swcregistry.io/docs/SWC-116'
      ]
    });
  }

  reportCriticalTimeWindow(node, analysis) {
    this.addFinding({
      title: 'Critical: Very Short Time Window',
      description: `${analysis.reason}. A miner can manipulate timestamps by ~15 seconds, which is a significant portion of this window.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'HIGH',
      confidence: 'HIGH',
      exploitable: true,
      exploitabilityScore: 75,
      attackVector: 'timestamp-manipulation',
      recommendation: 'Increase the time window to at least 15 minutes (900 seconds) for security-critical operations. Consider using block.number with average block time for more predictable timing.',
      references: [
        'https://swcregistry.io/docs/SWC-116'
      ]
    });
  }

  reportShortTimeWindow(node, analysis) {
    this.addFinding({
      title: 'Short Timestamp-Based Time Window',
      description: `${analysis.reason}. While not critical, this window is short enough that timestamp manipulation could have measurable impact.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      exploitable: true,
      exploitabilityScore: 40,
      recommendation: `Consider increasing the time window if this controls high-value operations. Current window: ${this.formatDuration(analysis.windowSize)}.`,
      references: [
        'https://swcregistry.io/docs/SWC-116'
      ]
    });
  }

  reportTimestampFinancial(node, financialRisk) {
    this.addFinding({
      title: 'Timestamp in Short-Term Financial Calculation',
      description: `${financialRisk.impactReason}. Long-term calculations (APY over months/years) are generally safe as 15s manipulation is negligible.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'MEDIUM',
      confidence: financialRisk.confidence,
      exploitable: true,
      exploitabilityScore: 35,
      recommendation: 'For short-term reward calculations, consider using block numbers or adding minimum time thresholds. Long-term interest/APY calculations using timestamps are acceptable.',
      references: [
        'https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/timestamp-dependence/'
      ]
    });
  }

  reportTimestampAccessControl(node, accessRisk) {
    this.addFinding({
      title: 'Timestamp-Based Access Control',
      description: `${accessRisk.reason}. This could allow early access or bypass of time-restricted functionality.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: accessRisk.severity,
      confidence: 'MEDIUM',
      exploitable: true,
      exploitabilityScore: accessRisk.severity === 'HIGH' ? 60 : 25,
      recommendation: 'Use timelocks of at least 1 day for critical operations. Add buffer time (e.g., 1 hour) to account for timestamp manipulation.',
      references: [
        'https://swcregistry.io/docs/SWC-116'
      ]
    });
  }

  generateRandomnessPoC() {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: Timestamp-Based Randomness Manipulation
 * Demonstrates how miners can manipulate block.timestamp for favorable outcomes
 */
contract TimestampRandomnessExploit is Test {
    // Target contract using timestamp for randomness
    address constant TARGET = address(0);

    function testExploit() public {
        // Simulate miner ability to set timestamp within valid range
        // Miners can adjust timestamp up to ~15 seconds from previous block

        uint256 desiredOutcome = 1; // The outcome we want
        uint256 baseTimestamp = block.timestamp;

        // Try different timestamps within manipulation window
        for (uint256 delta = 0; delta <= 15; delta++) {
            vm.warp(baseTimestamp + delta);

            // Calculate what the "random" result would be
            // uint256 result = uint256(keccak256(abi.encodePacked(block.timestamp))) % N;

            // if (result == desiredOutcome) {
            //     // Found favorable timestamp, proceed with attack
            //     break;
            // }
        }

        // Call target contract at manipulated timestamp
        // TARGET.randomFunction();
    }
}`;
  }
}

module.exports = TimestampDependenceDetector;
