const BaseDetector = require('./base-detector');

/**
 * Precision Loss Detector
 * Detects division before multiplication and other rounding issues
 * Critical for DeFi protocols where precision loss can be exploited
 */
class PrecisionLossDetector extends BaseDetector {
  constructor() {
    super(
      'Precision Loss in Calculations',
      'Detects division before multiplication, rounding errors, and precision loss that can be exploited',
      'HIGH'
    );
    this.currentFunction = null;
    this.currentContract = null;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'fallback';

    if (node.body && node.body.statements) {
      this.analyzeStatements(node.body.statements, node);
    }
  }

  analyzeStatements(statements, functionNode) {
    if (!statements) return;

    statements.forEach(stmt => {
      const code = this.getCodeSnippet(stmt.loc);

      // Pattern 1: Division before multiplication (CRITICAL)
      const divBeforeMul = this.detectDivisionBeforeMultiplication(code, stmt);
      if (divBeforeMul) {
        this.addFinding({
          title: 'Critical Precision Loss: Division Before Multiplication',
          description: `Function '${this.currentFunction}' performs division before multiplication. This causes precision loss due to Solidity's integer division truncating remainders. In DeFi protocols, this can be exploited: attackers can manipulate inputs to maximize rounding errors, potentially stealing funds through accumulated dust or causing unfair distributions.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: stmt.loc ? stmt.loc.start.line : 0,
          column: stmt.loc ? stmt.loc.start.column : 0,
          code: code,
          severity: 'HIGH',
          confidence: 'HIGH',
          recommendation: 'Always multiply before dividing. Example: Instead of (a / b) * c, use (a * c) / b. For complex calculations, use a fixed-point library or increase precision with scaling factors.',
          references: [
            'https://github.com/crytic/slither/wiki/Detector-Documentation#divide-before-multiply',
            'https://dacian.me/precision-loss-errors',
            'https://github.com/code-423n4/2022-10-inverse-findings/issues/537'
          ]
        });
      }

      // Pattern 2: Small multiplication result divided
      const smallMulDivided = this.detectSmallMultiplicationDivided(code, stmt);
      if (smallMulDivided) {
        this.addFinding({
          title: 'Precision Loss: Small Values in Division',
          description: `Function '${this.currentFunction}' multiplies small values then divides, which may result in zero due to rounding. This can cause users to receive 0 tokens/rewards even when they should receive small amounts.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: stmt.loc ? stmt.loc.start.line : 0,
          column: stmt.loc ? stmt.loc.start.column : 0,
          code: code,
          severity: 'MEDIUM',
          confidence: 'MEDIUM',
          recommendation: 'Use higher precision scaling (e.g., 1e18) before division, or implement minimum thresholds. Consider accumulating small amounts until they reach a claimable threshold.',
          references: [
            'https://github.com/code-423n4/2021-11-bootfinance-findings/issues/211'
          ]
        });
      }

      // Pattern 3: Percentage calculations without scaling
      const percentageNoScaling = this.detectPercentageWithoutScaling(code, stmt);
      if (percentageNoScaling) {
        this.addFinding({
          title: 'Precision Loss: Percentage Calculation Without Scaling',
          description: `Function '${this.currentFunction}' performs percentage calculations that may lose precision. Dividing by 100 before multiplying causes significant rounding errors for small amounts.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: stmt.loc ? stmt.loc.start.line : 0,
          column: stmt.loc ? stmt.loc.start.column : 0,
          code: code,
          severity: 'MEDIUM',
          confidence: 'HIGH',
          recommendation: 'Use basis points (10000) instead of percentages (100) for better precision. Example: (amount * feeBps) / 10000. Consider using 1e18 scaling for even higher precision.',
          references: [
            'https://docs.openzeppelin.com/contracts/4.x/api/utils#Math'
          ]
        });
      }

      // Pattern 4: Unsafe downcasting
      const unsafeDowncast = this.detectUnsafeDowncasting(code, stmt);
      if (unsafeDowncast) {
        this.addFinding({
          title: 'Precision Loss: Unsafe Type Downcasting',
          description: `Function '${this.currentFunction}' downcasts from larger to smaller integer types without checking for overflow. This can silently truncate values, leading to incorrect calculations.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: stmt.loc ? stmt.loc.start.line : 0,
          column: stmt.loc ? stmt.loc.start.column : 0,
          code: code,
          severity: 'HIGH',
          confidence: 'MEDIUM',
          recommendation: 'Use OpenZeppelin\'s SafeCast library which reverts on overflow. Example: value.toUint128() instead of uint128(value).',
          references: [
            'https://docs.openzeppelin.com/contracts/4.x/api/utils#SafeCast',
            'https://github.com/code-423n4/2022-12-forgeries-findings/issues/98'
          ]
        });
      }

      // Pattern 5: Loss of precision in token conversions
      const tokenConversionLoss = this.detectTokenConversionPrecisionLoss(code, stmt);
      if (tokenConversionLoss) {
        this.addFinding({
          title: 'Precision Loss: Token Decimal Conversion',
          description: `Function '${this.currentFunction}' performs token amount conversions that may lose precision when converting between tokens with different decimals.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: stmt.loc ? stmt.loc.start.line : 0,
          column: stmt.loc ? stmt.loc.start.column : 0,
          code: code,
          severity: 'MEDIUM',
          confidence: 'LOW',
          recommendation: 'When converting between token decimals, always multiply first if scaling up, divide last if scaling down. Validate that no precision is lost in critical conversions.',
          references: [
            'https://github.com/d-xo/weird-erc20#low-decimals'
          ]
        });
      }

      // Recurse into nested blocks
      if (stmt.trueBody) {
        this.analyzeStatements([stmt.trueBody], functionNode);
      }
      if (stmt.falseBody) {
        this.analyzeStatements([stmt.falseBody], functionNode);
      }
      if (stmt.body && stmt.body.statements) {
        this.analyzeStatements(stmt.body.statements, functionNode);
      }
    });
  }

  detectDivisionBeforeMultiplication(code, stmt) {
    // Match patterns like: (a / b) * c or a / b * c
    const patterns = [
      /\([^)]*\/[^)]*\)\s*\*/,  // (a / b) * c
      /\/\s*[^;]*\s*\*/,         // a / b * c (without parens)
      /\.div\([^)]*\)\.mul\(/,   // SafeMath: .div().mul()
    ];

    // Exclude cases where there's a comment explaining this is intentional
    if (code.match(/\/\*.*precision.*\*\/|\/\/.*precision/i)) {
      return false;
    }

    return patterns.some(p => p.test(code));
  }

  detectSmallMultiplicationDivided(code, stmt) {
    // Check for patterns where small numbers are multiplied then divided
    // Example: amount * 1 / 1000 or similar patterns with small numerators
    const pattern = /(\w+\s*\*\s*\d{1,2}|\d{1,2}\s*\*\s*\w+)\s*\/\s*\d{3,}/;
    return pattern.test(code);
  }

  detectPercentageWithoutScaling(code, stmt) {
    // Check for division by 100 (percentage) without proper scaling
    // Patterns: x / 100, x * fee / 100
    const patterns = [
      /\/\s*100[^\d]/,           // / 100
      /\*\s*\w+\s*\/\s*100/,     // * fee / 100
    ];

    // Exclude if already using basis points (10000) or higher precision
    if (code.match(/10000|1e18|WAD|RAY/)) {
      return false;
    }

    return patterns.some(p => p.test(code));
  }

  detectUnsafeDowncasting(code, stmt) {
    // Check for explicit type conversions to smaller types
    const patterns = [
      /uint8\s*\(/,
      /uint16\s*\(/,
      /uint32\s*\(/,
      /uint64\s*\(/,
      /uint128\s*\(/,
      /int8\s*\(/,
      /int16\s*\(/,
      /int32\s*\(/,
      /int64\s*\(/,
      /int128\s*\(/,
    ];

    // Exclude if using SafeCast
    if (code.match(/SafeCast|toUint\d+|toInt\d+/)) {
      return false;
    }

    return patterns.some(p => p.test(code));
  }

  detectTokenConversionPrecisionLoss(code, stmt) {
    // Check for token decimal conversions
    const hasDecimalConversion = code.match(/decimals|1e\d+|10\s*\*\*\s*\d+/i);
    const hasDivision = code.match(/\/|\.div\(/);

    if (hasDecimalConversion && hasDivision) {
      // Check if multiplication happens before division
      const mulIndex = code.search(/\*|\.mul\(/);
      const divIndex = code.search(/\/|\.div\(/);

      if (divIndex >= 0 && mulIndex >= 0 && divIndex < mulIndex) {
        return true;
      }
    }

    return false;
  }
}

module.exports = PrecisionLossDetector;
