const BaseDetector = require('./base-detector');

/**
 * Assembly Usage Detector
 * Detects inline assembly usage and analyzes for dangerous operations
 * Assembly bypasses Solidity safety checks and requires careful review
 */
class AssemblyUsageDetector extends BaseDetector {
  constructor() {
    super(
      'Inline Assembly Usage',
      'Detects use of inline assembly which bypasses Solidity safety checks and may contain vulnerabilities',
      'MEDIUM'
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
      // Check for inline assembly blocks
      if (stmt.type === 'InlineAssemblyStatement') {
        this.analyzeAssembly(stmt, functionNode);
      }

      // Recurse into nested statements
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

  analyzeAssembly(stmt, functionNode) {
    const code = this.getCodeSnippet(stmt.loc);
    const lowerCode = code.toLowerCase();

    // Check for dangerous operations
    const dangerousOps = this.checkDangerousOperations(lowerCode);

    if (dangerousOps.length > 0) {
      this.addFinding({
        title: `Dangerous Assembly Operations: ${dangerousOps.join(', ')}`,
        description: `Function '${this.currentFunction}' contains inline assembly with potentially dangerous operations: ${dangerousOps.join(', ')}. These operations bypass Solidity's safety checks and can lead to vulnerabilities if not used carefully.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: stmt.loc ? stmt.loc.start.line : 0,
        column: stmt.loc ? stmt.loc.start.column : 0,
        code: code,
        severity: 'HIGH',
        recommendation: 'Carefully review assembly code for correctness and security. Consider whether assembly is truly necessary. Document why assembly is required and ensure proper bounds checking.',
        references: [
          'https://docs.soliditylang.org/en/latest/assembly.html',
          'https://github.com/crytic/slither/wiki/Detector-Documentation#assembly-usage',
          'https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/assembly/'
        ]
      });
    } else {
      // General assembly usage (informational)
      this.addFinding({
        title: 'Inline Assembly Usage Detected',
        description: `Function '${this.currentFunction}' uses inline assembly. While not immediately dangerous, assembly bypasses Solidity's type safety and should be reviewed carefully.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: stmt.loc ? stmt.loc.start.line : 0,
        column: stmt.loc ? stmt.loc.start.column : 0,
        code: code,
        severity: 'INFO',
        recommendation: 'Ensure assembly code is well-documented and thoroughly tested. Consider whether Solidity can achieve the same result.',
        references: [
          'https://docs.soliditylang.org/en/latest/assembly.html'
        ]
      });
    }
  }

  checkDangerousOperations(assemblyCode) {
    const dangerous = [];

    // Check for low-level memory operations
    if (assemblyCode.includes('mstore') || assemblyCode.includes('mload')) {
      // Check if it's modifying free memory pointer or other critical areas
      if (assemblyCode.includes('mstore(0x40') ||
          assemblyCode.includes('mload(0x40')) {
        dangerous.push('free-memory-pointer-manipulation');
      }
    }

    // Dangerous calls
    if (assemblyCode.includes('delegatecall')) {
      dangerous.push('delegatecall');
    }
    if (assemblyCode.includes('callcode')) {
      dangerous.push('callcode');
    }
    if (assemblyCode.includes('selfdestruct') || assemblyCode.includes('suicide')) {
      dangerous.push('selfdestruct');
    }

    // Direct storage manipulation
    if (assemblyCode.includes('sstore') || assemblyCode.includes('sload')) {
      dangerous.push('raw-storage-access');
    }

    // Return data manipulation
    if (assemblyCode.includes('return(') && assemblyCode.includes('revert(')) {
      // Could bypass important checks
      dangerous.push('return-manipulation');
    }

    // Check for hardcoded addresses or values that might be exploitable
    if (/0x[0-9a-f]{40}/i.test(assemblyCode)) {
      dangerous.push('hardcoded-address');
    }

    return dangerous;
  }
}

module.exports = AssemblyUsageDetector;
