const BaseDetector = require('./base-detector');

/**
 * Precision Loss Detector
 * Detects mathematical operations that cause precision loss:
 * - Division before multiplication (truncation)
 * - Rounding errors in financial calculations
 * - Loss of precision in decimal conversions
 *
 * Classification:
 * - CRITICAL: Division before multiplication in token/price calculations
 * - HIGH: Rounding errors affecting user balances
 * - MEDIUM: Precision loss in non-financial contexts
 */
class PrecisionLossDetector extends BaseDetector {
  constructor() {
    super(
      'Precision Loss',
      'Detects mathematical operations causing precision loss',
      'HIGH'
    );
    this.currentContract = null;
    this.currentFunction = null;
    this.currentFunctionNode = null;
    this.variableTypes = new Map();
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;

    this.traverse(ast);

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
    this.variableTypes.clear();

    // Track state variable types
    if (node.subNodes) {
      for (const subNode of node.subNodes) {
        if (subNode.type === 'StateVariableDeclaration') {
          this.trackVariableType(subNode);
        }
      }
    }
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'constructor';
    this.currentFunctionNode = node;

    // Skip view/pure functions for critical financial issues (they don't modify state)
    // but still check for precision issues
    if (node.body) {
      this.analyzeFunction(node);
    }
  }

  trackVariableType(node) {
    if (node.variables) {
      for (const variable of node.variables) {
        if (variable.name && variable.typeName) {
          this.variableTypes.set(variable.name, this.getTypeName(variable.typeName));
        }
      }
    }
  }

  getTypeName(typeNode) {
    if (!typeNode) return 'unknown';
    if (typeNode.type === 'ElementaryTypeName') {
      return typeNode.name;
    }
    if (typeNode.type === 'UserDefinedTypeName') {
      return typeNode.namePath;
    }
    if (typeNode.type === 'ArrayTypeName') {
      return this.getTypeName(typeNode.baseTypeName) + '[]';
    }
    return 'unknown';
  }

  analyzeFunction(funcNode) {
    const funcCode = this.getCodeSnippet(funcNode.loc);

    // Pattern 1: Division before multiplication (most common precision loss)
    this.detectDivisionBeforeMultiplication(funcNode, funcCode);

    // Pattern 2: Direct division without scaling
    this.detectUnscaledDivision(funcNode, funcCode);

    // Pattern 3: Decimal conversion issues
    this.detectDecimalConversionIssues(funcNode, funcCode);

    // Pattern 4: Percentage calculations losing precision
    this.detectPercentageIssues(funcNode, funcCode);
  }

  /**
   * Detect division before multiplication pattern
   * Example: a / b * c should be a * c / b
   */
  detectDivisionBeforeMultiplication(funcNode, funcCode) {
    // Pattern: expression / value * anotherValue
    // This truncates the intermediate result before multiplication
    const divBeforeMulPattern = /(\w+)\s*\/\s*(\w+)\s*\*\s*(\w+)/g;
    let match;

    while ((match = divBeforeMulPattern.exec(funcCode)) !== null) {
      const [fullMatch, dividend, divisor, multiplier] = match;

      // Check if this is in a financial context
      const isFinancial = this.isFinancialContext(funcCode, match.index);

      // Skip if using safe multiplication patterns
      if (this.usesSafeMathPattern(funcCode)) {
        continue;
      }

      // Calculate the line number
      const linesBefore = funcCode.substring(0, match.index).split('\n').length;
      const line = (funcNode.loc?.start?.line || 0) + linesBefore - 1;

      this.addFinding({
        title: 'Division Before Multiplication',
        description: `Expression '${fullMatch}' performs division before multiplication, causing precision loss due to integer truncation. In Solidity, (a/b)*c loses precision compared to (a*c)/b.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: line,
        column: 0,
        code: this.extractContext(funcCode, match.index),
        severity: isFinancial ? 'CRITICAL' : 'HIGH',
        confidence: 'HIGH',
        exploitable: isFinancial,
        exploitabilityScore: isFinancial ? 85 : 65,
        attackVector: 'precision-loss',
        recommendation: `Reorder to multiply before dividing: (${dividend} * ${multiplier}) / ${divisor}. For percentage calculations, multiply by the percentage first, then divide by 100 or the base.`,
        references: [
          'https://github.com/crytic/slither/wiki/Detector-Documentation#divide-before-multiply',
          'https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/integer-division/'
        ],
        foundryPoC: isFinancial ? this.generateDivBeforeMulPoC(dividend, divisor, multiplier) : undefined
      });
    }
  }

  /**
   * Detect division without proper scaling
   * Example: amount / totalSupply without WAD/RAY scaling
   */
  detectUnscaledDivision(funcNode, funcCode) {
    // Look for ratio calculations without scaling
    const ratioPatterns = [
      { pattern: /(\w+)\s*\/\s*totalSupply/gi, context: 'share calculation' },
      { pattern: /(\w+)\s*\/\s*(\w+Supply)/gi, context: 'supply ratio' },
      { pattern: /amount\s*\/\s*(\w+)/gi, context: 'amount division' },
      { pattern: /balance\s*\/\s*(\w+)/gi, context: 'balance division' },
    ];

    for (const { pattern, context } of ratioPatterns) {
      let match;
      pattern.lastIndex = 0; // Reset regex state

      while ((match = pattern.exec(funcCode)) !== null) {
        // Check if there's scaling (WAD, RAY, 1e18, etc.)
        const hasScaling = this.hasProperScaling(funcCode, match.index);

        if (!hasScaling && !this.isSafeContext(funcCode, match.index)) {
          const linesBefore = funcCode.substring(0, match.index).split('\n').length;
          const line = (funcNode.loc?.start?.line || 0) + linesBefore - 1;

          this.addFinding({
            title: 'Unscaled Division May Lose Precision',
            description: `Division in ${context} without precision scaling. When dividing integers, small amounts may round to zero. Consider using WAD (1e18) or RAY (1e27) scaling.`,
            location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
            line: line,
            column: 0,
            code: this.extractContext(funcCode, match.index),
            severity: 'MEDIUM',
            confidence: 'MEDIUM',
            exploitable: true,
            exploitabilityScore: 55,
            attackVector: 'precision-loss',
            recommendation: 'Scale the numerator before division: (amount * 1e18) / totalSupply. Use fixed-point math libraries like DSMath or PRBMath for precise calculations.',
            references: [
              'https://github.com/dapphub/ds-math',
              'https://github.com/PaulRBerg/prb-math'
            ]
          });
        }
      }
    }
  }

  /**
   * Detect decimal conversion issues between tokens with different decimals
   */
  detectDecimalConversionIssues(funcNode, funcCode) {
    // Check for operations mixing decimals
    const decimalPatterns = [
      /decimals\s*\(\s*\)/gi,
      /10\s*\*\*\s*(\w+)/gi,
      /1e(\d+)/gi,
    ];

    const hasDecimalHandling = decimalPatterns.some(p => p.test(funcCode));

    // If function deals with multiple tokens and doesn't handle decimals properly
    if (funcCode.includes('token') && funcCode.includes('/')) {
      const multiTokenPattern = /token[A-Z0-9]?\.balanceOf|IERC20\([^)]+\)\.balanceOf/gi;
      const tokenMatches = funcCode.match(multiTokenPattern);

      if (tokenMatches && tokenMatches.length > 1 && !hasDecimalHandling) {
        this.addFinding({
          title: 'Missing Decimal Normalization',
          description: `Function operates on multiple tokens without decimal normalization. Tokens with different decimals (e.g., USDC=6, DAI=18) will produce incorrect calculations.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: funcNode.loc?.start?.line || 0,
          column: 0,
          code: this.extractContext(funcCode, 0),
          severity: 'HIGH',
          confidence: 'MEDIUM',
          exploitable: true,
          exploitabilityScore: 70,
          attackVector: 'precision-loss',
          recommendation: 'Normalize all token amounts to a common decimal base (typically 18 decimals) before performing calculations. Use: normalizedAmount = amount * (10 ** (18 - tokenDecimals)).',
          references: [
            'https://consensys.github.io/smart-contract-best-practices/development-recommendations/token-specific/token-normalization/'
          ]
        });
      }
    }
  }

  /**
   * Detect percentage calculation issues
   */
  detectPercentageIssues(funcNode, funcCode) {
    // Common problematic percentage patterns
    const percentPatterns = [
      // amount * percentage / 100 where percentage might be small
      { pattern: /(\w+)\s*\*\s*(\w+)\s*\/\s*100\b/gi, risk: 'low percentage precision' },
      // Basis points without proper handling
      { pattern: /(\w+)\s*\*\s*(\w+)\s*\/\s*10000\b/gi, risk: 'basis points precision' },
      // Fee calculation that might round to zero
      { pattern: /fee\s*=\s*(\w+)\s*\*\s*(\w+)\s*\/\s*(\w+)/gi, risk: 'fee rounding' },
    ];

    for (const { pattern, risk } of percentPatterns) {
      pattern.lastIndex = 0;
      let match;

      while ((match = pattern.exec(funcCode)) !== null) {
        // Check if there's a minimum check or rounding protection
        const hasMinCheck = /require\s*\([^)]*>\s*0|Math\.max/i.test(funcCode);

        if (!hasMinCheck) {
          const linesBefore = funcCode.substring(0, match.index).split('\n').length;
          const line = (funcNode.loc?.start?.line || 0) + linesBefore - 1;

          this.addFinding({
            title: 'Percentage Calculation May Round to Zero',
            description: `Percentage calculation (${risk}) may produce zero for small amounts. Without minimum value protection, users could receive zero fees/rewards or bypass fee payments.`,
            location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
            line: line,
            column: 0,
            code: this.extractContext(funcCode, match.index),
            severity: 'MEDIUM',
            confidence: 'MEDIUM',
            exploitable: true,
            exploitabilityScore: 50,
            attackVector: 'precision-loss',
            recommendation: 'Add minimum value check: require(result > 0) or use Math.max(1, result). For fees, consider a minimum fee constant.',
            references: [
              'https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/integer-division/'
            ]
          });
        }
      }
    }
  }

  /**
   * Check if context involves financial calculations
   */
  isFinancialContext(code, position) {
    const context = code.substring(Math.max(0, position - 100), position + 100).toLowerCase();
    const financialKeywords = [
      'balance', 'amount', 'price', 'rate', 'fee', 'reward', 'stake',
      'yield', 'interest', 'collateral', 'debt', 'liquidity', 'share',
      'token', 'mint', 'burn', 'transfer', 'swap', 'exchange'
    ];
    return financialKeywords.some(kw => context.includes(kw));
  }

  /**
   * Check if code uses SafeMath or similar patterns
   */
  usesSafeMathPattern(code) {
    return /\.mul\(|\.div\(|mulDiv|FullMath|PRBMath|DSMath/i.test(code);
  }

  /**
   * Check if division has proper scaling
   */
  hasProperScaling(code, position) {
    const context = code.substring(Math.max(0, position - 50), Math.min(code.length, position + 100));
    return /1e18|1e27|WAD|RAY|PRECISION|SCALE|10\s*\*\*\s*(18|27)/i.test(context);
  }

  /**
   * Check if context is safe (e.g., already validated)
   */
  isSafeContext(code, position) {
    const context = code.substring(Math.max(0, position - 100), position);
    // Check for prior validation
    return /require\s*\([^)]*>\s*0|if\s*\([^)]*>\s*0/i.test(context);
  }

  /**
   * Extract relevant code context around a position
   */
  extractContext(code, position) {
    const lines = code.split('\n');
    const linesBefore = code.substring(0, position).split('\n').length - 1;

    const start = Math.max(0, linesBefore - 1);
    const end = Math.min(lines.length, linesBefore + 3);

    return lines.slice(start, end).join('\n');
  }

  /**
   * Generate Foundry PoC for division before multiplication
   */
  generateDivBeforeMulPoC(dividend, divisor, multiplier) {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: Division Before Multiplication Precision Loss
 * Demonstrates how (a/b)*c loses precision vs (a*c)/b
 */
contract PrecisionLossExploit is Test {
    function testDivisionBeforeMultiplication() public {
        // Example values that demonstrate precision loss
        uint256 ${dividend} = 1000;
        uint256 ${divisor} = 3;
        uint256 ${multiplier} = 7;

        // Vulnerable calculation (division first - loses precision)
        uint256 vulnerable = (${dividend} / ${divisor}) * ${multiplier};
        // 1000 / 3 = 333 (truncated)
        // 333 * 7 = 2331

        // Correct calculation (multiplication first)
        uint256 correct = (${dividend} * ${multiplier}) / ${divisor};
        // 1000 * 7 = 7000
        // 7000 / 3 = 2333

        console.log("Vulnerable result:", vulnerable);
        console.log("Correct result:", correct);
        console.log("Precision lost:", correct - vulnerable);

        // The difference of 2 units may seem small, but:
        // - At scale (millions of tokens), this becomes significant
        // - Repeated operations compound the error
        // - Attackers can exploit small amounts to always round in their favor

        assertGt(correct, vulnerable, "Precision loss demonstrated");
    }

    function testExploitSmallAmounts() public {
        // Exploit: Process many small amounts that round to zero
        uint256 amount = 99;
        uint256 feePercent = 1;
        uint256 base = 100;

        // Vulnerable: fee rounds to zero
        uint256 fee = (amount / base) * feePercent; // 0
        assertEq(fee, 0, "Fee is zero - attacker pays no fees");

        // Correct: fee is calculated properly
        uint256 correctFee = (amount * feePercent) / base; // 0 still, but...

        // With slightly larger amount
        amount = 100;
        fee = (amount / base) * feePercent; // 1
        correctFee = (amount * feePercent) / base; // 1

        // Attacker processes 100 transactions of 99 each: 0 total fees
        // vs 1 transaction of 9900: 99 fees
        console.log("Exploit: Split to avoid fees");
    }
}`;
  }
}

module.exports = PrecisionLossDetector;
