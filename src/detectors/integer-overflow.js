const BaseDetector = require('./base-detector');

/**
 * Integer Overflow/Underflow Detector (Enhanced)
 * Detects arithmetic operations that may overflow or underflow
 * with context awareness to reduce false positives for safe patterns.
 *
 * Note: Solidity 0.8.0+ has built-in overflow checks except in unchecked blocks
 */
class IntegerOverflowDetector extends BaseDetector {
  constructor() {
    super(
      'Integer Overflow/Underflow',
      'Detects arithmetic operations vulnerable to overflow or underflow',
      'HIGH'
    );
    this.solidityVersion = null;
    this.inUncheckedBlock = false;
    this.uncheckedDepth = 0;
    this.currentContract = null;
    this.currentFunction = null;
    this.currentFunctionNode = null;
    this.functionParameters = new Set();
    this.hasSafeMath = false;
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;

    // Extract Solidity version from pragma
    this.extractSolidityVersion(ast);

    // Check for SafeMath usage
    this.hasSafeMath = /using\s+SafeMath\s+for/i.test(sourceCode) ||
                       /import.*SafeMath/i.test(sourceCode);

    // Traverse the AST
    this.traverse(ast);

    return this.findings;
  }

  extractSolidityVersion(ast) {
    for (const node of ast.children || []) {
      if (node.type === 'PragmaDirective' && node.name === 'solidity') {
        // Handle version ranges like ^0.8.0, >=0.8.0, 0.8.0
        const versionPatterns = [
          /(\d+)\.(\d+)\.(\d+)/,           // Exact version
          /\^(\d+)\.(\d+)\.(\d+)/,         // Caret version
          />=\s*(\d+)\.(\d+)\.(\d+)/,      // Greater than or equal
          /(\d+)\.(\d+)/                    // Major.minor only
        ];

        for (const pattern of versionPatterns) {
          const match = node.value.match(pattern);
          if (match) {
            this.solidityVersion = {
              major: parseInt(match[1]),
              minor: parseInt(match[2]),
              patch: match[3] ? parseInt(match[3]) : 0
            };
            break;
          }
        }
      }
    }
  }

  isVersionBelow080() {
    if (!this.solidityVersion) {
      // Try to infer from code patterns
      if (this.hasSafeMath) {
        return true; // SafeMath typically means pre-0.8
      }
      return false; // Default to safe (0.8+) if unknown
    }
    return this.solidityVersion.major === 0 && this.solidityVersion.minor < 8;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'constructor';
    this.currentFunctionNode = node;

    // Track function parameters for user input detection
    this.functionParameters = new Set();
    if (node.parameters) {
      for (const param of node.parameters) {
        if (param.name) {
          this.functionParameters.add(param.name);
        }
      }
    }
  }

  visitUncheckedStatement(node) {
    // Mark that we're entering an unchecked block
    this.uncheckedDepth++;
    this.inUncheckedBlock = true;

    // Analyze the unchecked block with context
    this.analyzeUncheckedBlock(node);
  }

  /**
   * Analyze unchecked block for actual vulnerabilities
   */
  analyzeUncheckedBlock(node) {
    const code = this.getCodeSnippet(node.loc);

    // Check if this is a safe unchecked pattern
    const safePattern = this.identifySafeUncheckedPattern(code);

    if (safePattern.isSafe) {
      // Don't report - this is intentional and safe
      return;
    }

    // Find arithmetic operations in the block
    this.findArithmeticInBlock(node, code);

    // Reset after processing
    this.uncheckedDepth--;
    if (this.uncheckedDepth === 0) {
      this.inUncheckedBlock = false;
    }
  }

  /**
   * Identify safe unchecked patterns that are intentional
   */
  identifySafeUncheckedPattern(code) {
    const result = { isSafe: false, reason: '' };

    // Pattern 1: Loop counter increment (i++ in for loops)
    // Counters are bounded by array length, so overflow is impossible
    if (/\+\+\s*\}|i\s*\+\+|counter\s*\+\+/i.test(code) &&
        code.split('\n').length <= 3) {
      result.isSafe = true;
      result.reason = 'Loop counter increment (bounded by iteration)';
      return result;
    }

    // Pattern 2: Intentional wrapping arithmetic for circular buffers/counters
    if (/circular|wrap|ring|mod|%/i.test(code)) {
      result.isSafe = true;
      result.reason = 'Intentional wrapping arithmetic';
      return result;
    }

    // Pattern 3: Gas optimization for known-safe operations
    // e.g., unchecked { balances[from] -= amount; balances[to] += amount; }
    // where amount was already validated
    const hasValidation = this.checkPriorValidation(code);
    if (hasValidation) {
      result.isSafe = true;
      result.reason = 'Validated before unchecked operation';
      return result;
    }

    // Pattern 4: Timestamp/block number differences (always positive, bounded)
    if (/block\.timestamp|block\.number/i.test(code) &&
        /-/.test(code) &&
        !this.involvesUserInputInCode(code)) {
      result.isSafe = true;
      result.reason = 'Block timestamp/number difference (bounded)';
      return result;
    }

    return result;
  }

  /**
   * Check if there's validation before the unchecked block
   */
  checkPriorValidation(code) {
    // Look for require/if statements before arithmetic
    const funcCode = this.currentFunctionNode ?
      this.getCodeSnippet(this.currentFunctionNode.loc) : code;

    // Check for balance >= amount pattern before subtraction
    if (/-=/.test(code)) {
      const hasBalanceCheck = /require\s*\([^)]*>=|if\s*\([^)]*>=/i.test(funcCode);
      if (hasBalanceCheck) return true;
    }

    // Check for overflow prevention require
    const hasOverflowCheck = /require\s*\([^)]*\+[^)]*[<>]/i.test(funcCode);
    if (hasOverflowCheck) return true;

    return false;
  }

  /**
   * Find arithmetic operations within a block
   */
  findArithmeticInBlock(node, blockCode) {
    if (!node) return;

    if (node.type === 'BinaryOperation') {
      const vulnerableOps = ['+', '-', '*', '**'];
      if (vulnerableOps.includes(node.operator)) {
        this.analyzeUncheckedArithmetic(node, blockCode);
      }
    }

    // Traverse children
    for (const key in node) {
      if (key === 'loc' || key === 'range') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach(c => this.findArithmeticInBlock(c, blockCode));
      } else if (child && typeof child === 'object' && child.type) {
        this.findArithmeticInBlock(child, blockCode);
      }
    }
  }

  /**
   * Analyze a specific arithmetic operation in unchecked block
   */
  analyzeUncheckedArithmetic(node, blockCode) {
    const operator = node.operator;

    // Check if operands involve user input
    const leftIsUserInput = this.isUserControlled(node.left);
    const rightIsUserInput = this.isUserControlled(node.right);
    const hasUserInput = leftIsUserInput || rightIsUserInput;

    // Assess risk based on operation and input source
    const risk = this.assessOverflowRisk(operator, hasUserInput, node, blockCode);

    if (risk.shouldReport) {
      this.reportUncheckedOverflow(node, risk);
    }
  }

  visitBinaryOperation(node) {
    // Only check if in pre-0.8 code (outside of unchecked handling)
    if (!this.isVersionBelow080()) return;
    if (this.inUncheckedBlock) return; // Handled separately

    const vulnerableOps = ['+', '-', '*', '**'];
    if (!vulnerableOps.includes(node.operator)) return;

    // Check if SafeMath is being used
    if (this.hasSafeMath) {
      // Check if this specific operation uses SafeMath
      const code = this.getCodeSnippet(node.loc);
      if (/\.add\(|\.sub\(|\.mul\(|\.div\(/i.test(code)) {
        return; // Using SafeMath - safe
      }
    }

    // Analyze the operation
    const hasUserInput = this.isUserControlled(node.left) || this.isUserControlled(node.right);
    const risk = this.assessOverflowRisk(node.operator, hasUserInput, node, '');

    if (risk.shouldReport) {
      this.reportLegacyOverflow(node, risk);
    }
  }

  /**
   * Check if a node represents user-controlled input
   */
  isUserControlled(node) {
    if (!node) return false;

    // Direct function parameter
    if (node.type === 'Identifier') {
      if (this.functionParameters.has(node.name)) {
        return true;
      }
      // Common user-input naming patterns
      const name = node.name.toLowerCase();
      if (name.includes('amount') || name.includes('value') ||
          name.includes('input') || name.includes('qty') ||
          name.includes('quantity')) {
        return true;
      }
    }

    // msg.value
    if (node.type === 'MemberAccess') {
      if (node.expression && node.expression.name === 'msg') {
        return node.memberName === 'value';
      }
    }

    // Array/mapping access with user index
    if (node.type === 'IndexAccess') {
      return this.isUserControlled(node.index);
    }

    // Function call result (external data)
    if (node.type === 'FunctionCall') {
      const callCode = this.getCodeSnippet(node.loc);
      // External calls returning values
      if (/\.balanceOf\(|\.totalSupply\(|\.decimals\(/i.test(callCode)) {
        return true; // External contract data
      }
    }

    return false;
  }

  /**
   * Check if code string contains user-controlled values
   */
  involvesUserInputInCode(code) {
    const userInputPatterns = [
      /msg\.value/,
      /\(amount|Amount\)/,
      /\(value|Value\)/,
      /param|Param/,
      /input|Input/,
    ];
    return userInputPatterns.some(p => p.test(code));
  }

  /**
   * Assess the overflow risk of an operation
   */
  assessOverflowRisk(operator, hasUserInput, node, contextCode) {
    const result = {
      shouldReport: false,
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      reason: '',
      exploitabilityScore: 50
    };

    // Multiplication with user input - highest risk
    if (operator === '*' && hasUserInput) {
      result.shouldReport = true;
      result.severity = 'CRITICAL';
      result.confidence = 'HIGH';
      result.reason = 'Multiplication with user-controlled value can easily overflow';
      result.exploitabilityScore = 85;
      return result;
    }

    // Exponentiation - always risky with any variable
    if (operator === '**') {
      result.shouldReport = true;
      result.severity = 'HIGH';
      result.confidence = 'HIGH';
      result.reason = 'Exponentiation grows extremely fast and can overflow with small inputs';
      result.exploitabilityScore = 80;
      return result;
    }

    // Addition with user input
    if (operator === '+' && hasUserInput) {
      result.shouldReport = true;
      result.severity = 'HIGH';
      result.confidence = 'MEDIUM';
      result.reason = 'Addition with user-controlled value can overflow near uint max';
      result.exploitabilityScore = 70;
      return result;
    }

    // Subtraction - underflow risk
    if (operator === '-') {
      if (hasUserInput) {
        result.shouldReport = true;
        result.severity = 'HIGH';
        result.confidence = 'HIGH';
        result.reason = 'Subtraction can underflow if user provides value larger than minuend';
        result.exploitabilityScore = 75;
        return result;
      }
      // Even without direct user input, subtraction is risky
      result.shouldReport = true;
      result.severity = 'MEDIUM';
      result.confidence = 'MEDIUM';
      result.reason = 'Subtraction can underflow if not properly bounded';
      result.exploitabilityScore = 50;
      return result;
    }

    // Multiplication without direct user input - lower confidence
    if (operator === '*') {
      result.shouldReport = true;
      result.severity = 'MEDIUM';
      result.confidence = 'LOW';
      result.reason = 'Multiplication may overflow with large values';
      result.exploitabilityScore = 40;
      return result;
    }

    return result;
  }

  reportUncheckedOverflow(node, risk) {
    this.addFinding({
      title: 'Unchecked Arithmetic Overflow/Underflow',
      description: `Arithmetic operation '${node.operator}' in unchecked block may overflow or underflow. ${risk.reason}. Unchecked blocks bypass Solidity 0.8+ overflow protection.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: risk.severity,
      confidence: risk.confidence,
      exploitable: true,
      exploitabilityScore: risk.exploitabilityScore,
      attackVector: node.operator === '-' ? 'integer-underflow' : 'integer-overflow',
      recommendation: 'Add explicit bounds validation before the unchecked arithmetic, or remove the unchecked block if overflow protection is needed. Example: require(a + b >= a) for addition.',
      references: [
        'https://swcregistry.io/docs/SWC-101',
        'https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic'
      ],
      foundryPoC: risk.exploitabilityScore >= 70 ? this.generateOverflowPoC(node.operator) : undefined
    });
  }

  reportLegacyOverflow(node, risk) {
    this.addFinding({
      title: 'Integer Overflow/Underflow (Pre-0.8 Solidity)',
      description: `Arithmetic operation '${node.operator}' in Solidity < 0.8 without SafeMath. ${risk.reason}. Pre-0.8 Solidity has no built-in overflow protection.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: risk.severity,
      confidence: risk.confidence,
      exploitable: true,
      exploitabilityScore: risk.exploitabilityScore,
      attackVector: node.operator === '-' ? 'integer-underflow' : 'integer-overflow',
      recommendation: 'Upgrade to Solidity 0.8.0+ for built-in overflow checks, OR use OpenZeppelin SafeMath library for ALL arithmetic operations.',
      references: [
        'https://swcregistry.io/docs/SWC-101',
        'https://docs.openzeppelin.com/contracts/4.x/api/utils#SafeMath'
      ],
      foundryPoC: risk.exploitabilityScore >= 70 ? this.generateOverflowPoC(node.operator) : undefined
    });
  }

  generateOverflowPoC(operator) {
    const isUnderflow = operator === '-';
    const title = isUnderflow ? 'Integer Underflow' : 'Integer Overflow';
    const exploit = isUnderflow ?
      `// Underflow: 0 - 1 = MAX_UINT256
        uint256 balance = 0;
        uint256 amount = 1;
        // After: balance = 115792089237316195423570985008687907853269984665640564039457584007913129639935` :
      `// Overflow: MAX_UINT256 + 1 = 0
        uint256 balance = type(uint256).max;
        uint256 amount = 1;
        // After: balance = 0`;

    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: ${title}
 */
contract IntegerOverflowExploit is Test {
    address constant TARGET = address(0);

    function testExploit() public {
        ${exploit}

        // Call vulnerable function with crafted input
        // TARGET.vulnerableFunction(amount);

        // Verify exploitation:
        // - Balance check bypassed OR
        // - Received more tokens than should be possible
    }
}`;
  }
}

module.exports = IntegerOverflowDetector;
