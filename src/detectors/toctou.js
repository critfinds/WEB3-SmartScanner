const BaseDetector = require('./base-detector');

/**
 * Time-of-Check to Time-of-Use (TOCTOU) Detector
 * Detects race conditions where contract state changes between a check and its use
 * 
 * Detects:
 * - Balance checks before transfers
 * - Allowance checks before transfers
 * - State checks before state-dependent operations
 * - External calls between check and use
 * - Reentrancy-like patterns with state checks
 */
class TOCTOUDetector extends BaseDetector {
  constructor() {
    super(
      'Time-of-Check to Time-of-Use (TOCTOU) Vulnerability',
      'Detects race conditions where state changes between check and use',
      'HIGH'
    );
    this.currentContract = null;
    this.currentFunction = null;
    this.checkUsePairs = []; // Array of {check, use, hasExternalCall}
    this.cfg = null;
    this.dataFlow = null;
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

    // Post-traversal analysis
    this.analyzeTOCTOUPatterns();

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
    this.checkUsePairs = [];
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || '';
    
    if (!node.body || !node.body.statements) return;

    // Skip private/internal functions
    if (node.visibility === 'private' || node.visibility === 'internal') {
      return;
    }

    // Analyze function for TOCTOU patterns
    this.analyzeFunctionForTOCTOU(node);
  }

  /**
   * Analyze function for TOCTOU vulnerabilities
   */
  analyzeFunctionForTOCTOU(node) {
    if (!node.body || !node.body.statements) return;
    
    const statements = node.body.statements;
    const checks = []; // Array of check statements
    const uses = []; // Array of use statements
    const externalCalls = []; // Array of external calls

    for (let i = 0; i < statements.length; i++) {
      const stmt = statements[i];
      const stmtCode = this.getCodeSnippet(stmt.loc);
      const stmtCodeLower = stmtCode.toLowerCase();

      // Detect check patterns
      if (this.isCheckPattern(stmt, stmtCode)) {
        checks.push({
          statement: stmt,
          code: stmtCode,
          index: i,
          type: this.getCheckType(stmtCode)
        });
      }

      // Detect use patterns
      if (this.isUsePattern(stmt, stmtCode)) {
        uses.push({
          statement: stmt,
          code: stmtCode,
          index: i,
          type: this.getUseType(stmtCode)
        });
      }

      // Detect external calls
      if (this.isExternalCall(stmt, stmtCode)) {
        externalCalls.push({
          statement: stmt,
          code: stmtCode,
          index: i
        });
      }
    }

    // Find check-use pairs with external calls in between
    this.findTOCTOUPatterns(checks, uses, externalCalls, node);
  }

  /**
   * Check if statement is a check pattern
   */
  isCheckPattern(stmt, code) {
    const codeLower = code.toLowerCase();
    
    // Balance checks - look for balance reads/assignments that are used for checks
    const balanceChecks = [
      /balanceOf\s*\(/i,
      /balances\[/i,
      /\.balance\s*>/i,
      /\.balance\s*>=/i,
      /\.balance\s*</i,
      /\.balance\s*<=/i,
      /uint256\s+\w*balance/i,  // uint256 balance = ...
      /require\s*\(\s*.*balance/i,
      /if\s*\(\s*.*balance/i
    ];

    // Allowance checks
    const allowanceChecks = [
      /allowance\s*\(/i,
      /allowance\[/i,
      /uint256\s+\w*allowed/i,  // uint256 allowed = ...
      /require\s*\(\s*.*allowance/i,
      /if\s*\(\s*.*allowance/i
    ];

    // State variable checks
    const stateChecks = [
      /require\s*\(\s*.*==/i,
      /require\s*\(\s*.*!=/i,
      /if\s*\(\s*.*==/i,
      /if\s*\(\s*.*!=/i
    ];

    // Owner/role checks
    const accessChecks = [
      /require\s*\(\s*.*owner/i,
      /require\s*\(\s*.*role/i,
      /require\s*\(\s*.*hasRole/i
    ];

    const allChecks = [...balanceChecks, ...allowanceChecks, ...stateChecks, ...accessChecks];
    
    return allChecks.some(pattern => pattern.test(code));
  }

  /**
   * Get type of check
   */
  getCheckType(code) {
    const codeLower = code.toLowerCase();
    // Check for balance reads (including variable assignments)
    if (codeLower.includes('balance') || codeLower.includes('balances[')) return 'balance';
    // Check for allowance reads
    if (codeLower.includes('allowance') || codeLower.includes('allowed')) return 'allowance';
    if (codeLower.includes('owner') || codeLower.includes('role')) return 'access';
    return 'state';
  }

  /**
   * Check if statement is a use pattern (state modification)
   */
  isUsePattern(stmt, code) {
    const codeLower = code.toLowerCase();
    
    // State modifications - assignments to state variables
    const stateModPatterns = [
      /balances\[.*\]\s*=/i,  // balances[user] = ...
      /balances\[.*\]\s*-=/i,  // balances[user] -= ...
      /balances\[.*\]\s*\+=/i,  // balances[user] += ...
      /allowance\[.*\]\s*=/i,  // allowance[from][spender] = ...
      /allowance\[.*\]\s*-=/i,  // allowance[from][spender] -= ...
      /mapping\[.*\]\s*=/i,    // mapping assignments
      /\w+\s*=\s*[^=]/i,       // Variable assignment (but not ==)
      /\+\+/i,                  // Increment
      /--/i                     // Decrement
    ];

    // Check if it's an assignment statement
    if (stmt.type === 'ExpressionStatement' && stmt.expression) {
      const expr = stmt.expression;
      if (expr.type === 'Assignment') {
        // This is an assignment - check if it's a state variable
        const leftSide = this.getCodeSnippet(expr.left ? expr.left.loc : null);
        if (leftSide && (leftSide.includes('balances') || leftSide.includes('allowance') || leftSide.includes('mapping'))) {
          return true;
        }
      }
    }

    // Check patterns in code
    return stateModPatterns.some(pattern => pattern.test(code));
  }

  /**
   * Get type of use
   */
  getUseType(code) {
    const codeLower = code.toLowerCase();
    // Check for transfer operations
    if (codeLower.includes('transfer') || codeLower.includes('call{value') || codeLower.includes('send')) return 'transfer';
    // Check for state modifications to balances or allowance
    if (codeLower.includes('balances[') && (codeLower.includes('=') || codeLower.includes('-=') || codeLower.includes('+='))) return 'transfer';
    if (codeLower.includes('allowance[') && (codeLower.includes('=') || codeLower.includes('-='))) return 'transfer';
    if (codeLower.includes('mint') || codeLower.includes('burn')) return 'mintburn';
    return 'state';
  }

  /**
   * Check if statement is an external call
   */
  isExternalCall(stmt, code) {
    const codeLower = code.toLowerCase();
    
    const callPatterns = [
      /\.call\s*\(/i,
      /\.delegatecall\s*\(/i,
      /\.send\s*\(/i,
      /\.transfer\s*\(/i,
      /external\s+contract/i
    ];

    return callPatterns.some(pattern => pattern.test(code));
  }

  /**
   * Find TOCTOU patterns (check -> external call -> use)
   */
  findTOCTOUPatterns(checks, uses, externalCalls, node) {
    // For each check-use pair, see if there's an external call in between
    for (const check of checks) {
      for (const use of uses) {
        // Use must come after check
        if (use.index <= check.index) continue;

        // Check if there's an external call between check and use
        const hasExternalCall = externalCalls.some(call => 
          call.index > check.index && call.index < use.index
        );

        // Check if check and use are related (same variable/operation)
        if (this.areRelated(check, use)) {
          this.checkUsePairs.push({
            check: check,
            use: use,
            hasExternalCall: hasExternalCall,
            function: this.currentFunction,
            node: node
          });

          // If there's an external call, this is a TOCTOU vulnerability
          if (hasExternalCall) {
            this.reportTOCTOU(check, use, node);
          }
        }
      }
    }
  }

  /**
   * Check if check and use are related
   */
  areRelated(check, use) {
    const checkCode = check.code.toLowerCase();
    const useCode = use.code.toLowerCase();

    // Balance check -> transfer or balance state modification
    if (check.type === 'balance' && (use.type === 'transfer' || useCode.includes('balances['))) {
      return true;
    }

    // Allowance check -> transfer or allowance state modification
    if (check.type === 'allowance' && (use.type === 'transfer' || useCode.includes('allowance['))) {
      return true;
    }

    // State check -> state modification
    if (check.type === 'state' && use.type === 'state') {
      // Check if they reference the same variable
      const checkVar = this.extractVariable(check.code);
      const useVar = this.extractVariable(use.code);
      return checkVar && useVar && checkVar === useVar;
    }

    return false;
  }

  /**
   * Extract variable name from code
   */
  extractVariable(code) {
    // Simple extraction - look for common patterns
    const patterns = [
      /(\w+)\s*\.balance/i,
      /balanceOf\s*\(\s*(\w+)/i,
      /allowance\s*\(\s*(\w+)/i,
      /(\w+)\s*==/i,
      /(\w+)\s*!=/i
    ];

    for (const pattern of patterns) {
      const match = code.match(pattern);
      if (match && match[1]) {
        return match[1];
      }
    }

    return null;
  }

  /**
   * Report TOCTOU vulnerability
   */
  reportTOCTOU(check, use, node) {
    const funcName = this.currentFunction;
    const checkType = check.type;
    const useType = use.type;

    let title, description, recommendation;

    if (checkType === 'balance' && useType === 'transfer') {
      title = 'TOCTOU: Balance Check Before Transfer';
      description = `Function '${funcName}' checks balance before transfer, but an external call occurs between the check and use. An attacker can manipulate the balance during the external call, causing the transfer to use stale balance information.`;
      recommendation = 'Cache balance value before external calls. Use Checks-Effects-Interactions pattern: update state first, then make external calls.';
    } else if (checkType === 'allowance' && useType === 'transfer') {
      title = 'TOCTOU: Allowance Check Before Transfer';
      description = `Function '${funcName}' checks allowance before transferFrom, but an external call occurs between the check and use. An attacker can reduce allowance during the external call, causing the transfer to fail or use incorrect allowance.`;
      recommendation = 'Cache allowance value before external calls. Consider using increaseAllowance/decreaseAllowance pattern instead of direct allowance checks.';
    } else {
      title = 'TOCTOU: State Check Before Use';
      description = `Function '${funcName}' checks state before using it, but an external call occurs between the check and use. The state may change during the external call, leading to inconsistent behavior.`;
      recommendation = 'Cache state values before external calls. Update state before making external calls when possible.';
    }

    this.addFinding({
      title: title,
      description: description,
      location: `Contract: ${this.currentContract}, Function: ${funcName}`,
      line: check.statement.loc ? check.statement.loc.start.line : 0,
      column: check.statement.loc ? check.statement.loc.start.column : 0,
      code: `${check.code}\n...\n${use.code}`,
      severity: 'HIGH',
      confidence: 'HIGH',
      exploitable: true,
      exploitabilityScore: 80,
      attackVector: 'toctou',
      recommendation: recommendation,
      references: [
        'https://swcregistry.io/docs/SWC-107',
        'https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/',
        'https://fravoll.github.io/solidity-patterns/checks_effects_interactions.html'
      ],
      foundryPoC: this.generateTOCTOUPoC(this.currentContract, funcName, checkType, useType)
    });
  }

  /**
   * Post-traversal analysis
   */
  analyzeTOCTOUPatterns() {
    // Additional analysis can be done here
    // For example, finding patterns across multiple functions
  }

  /**
   * Generate Foundry PoC for TOCTOU
   */
  generateTOCTOUPoC(contractName, funcName, checkType, useType) {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: TOCTOU Attack
 * Target: ${contractName}.${funcName}()
 * Attack Vector: State changes between check and use
 */
contract TOCTOUExploit is Test {
    address constant TARGET = address(0); // ${contractName} address
    AttackerContract attacker;

    function setUp() public {
        attacker = new AttackerContract();
    }

    function testExploit() public {
        // 1. Setup: Attacker has some balance/allowance
        // 2. Call vulnerable function which:
        //    - Checks balance/allowance (${checkType})
        //    - Makes external call (attacker's callback)
        //    - Uses cached/stale value for ${useType}
        
        // 3. In callback, attacker manipulates state
        // 4. Function continues with stale check value
        
        // Assert exploit succeeded
        // assertGt(attacker.balance, initialBalance);
    }
}

contract AttackerContract {
    function onCallback() external {
        // Manipulate state that was checked earlier
        // This changes the state between check and use
    }
}`;
  }
}

module.exports = TOCTOUDetector;

