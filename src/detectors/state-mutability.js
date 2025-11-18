const BaseDetector = require('./base-detector');

/**
 * State Mutability Detector
 * Detects functions that could be declared as view/pure but aren't
 * Proper mutability declarations improve gas efficiency and code clarity
 */
class StateMutabilityDetector extends BaseDetector {
  constructor() {
    super(
      'Incorrect State Mutability',
      'Detects functions that should be marked as view or pure for gas optimization',
      'LOW'
    );
    this.currentContract = null;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
  }

  visitFunctionDefinition(node) {
    const funcName = node.name;

    // Skip constructors, fallback, and receive functions
    if (node.isConstructor || !funcName) return;

    // Skip if already marked as view or pure
    if (node.stateMutability === 'view' || node.stateMutability === 'pure') {
      return;
    }

    const code = this.getCodeSnippet(node.loc);

    // Analyze function body
    if (node.body && node.body.statements) {
      const analysis = this.analyzeFunctionBody(node.body.statements);

      // If function doesn't modify state and doesn't read state, suggest pure
      if (!analysis.modifiesState && !analysis.readsState && !analysis.hasExternalCalls) {
        this.addFinding({
          title: 'Function Could Be Declared Pure',
          description: `Function '${funcName}' in contract '${this.currentContract}' does not read or modify state and does not make external calls. It should be declared as 'pure' to save gas and improve code clarity.`,
          location: `Contract: ${this.currentContract}, Function: ${funcName}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: code,
          severity: 'INFO',
          recommendation: `Add 'pure' modifier to function declaration: function ${funcName}(...) public pure { ... }`,
          references: [
            'https://docs.soliditylang.org/en/latest/contracts.html#pure-functions',
            'https://github.com/crytic/slither/wiki/Detector-Documentation#state-variables-that-could-be-declared-constant'
          ]
        });
      }
      // If function doesn't modify state but reads it, suggest view
      else if (!analysis.modifiesState && analysis.readsState) {
        this.addFinding({
          title: 'Function Could Be Declared View',
          description: `Function '${funcName}' in contract '${this.currentContract}' reads state but does not modify it. It should be declared as 'view' to save gas when called externally and improve code clarity.`,
          location: `Contract: ${this.currentContract}, Function: ${funcName}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: code,
          severity: 'INFO',
          recommendation: `Add 'view' modifier to function declaration: function ${funcName}(...) public view { ... }`,
          references: [
            'https://docs.soliditylang.org/en/latest/contracts.html#view-functions',
            'https://github.com/crytic/slither/wiki/Detector-Documentation#functions-that-could-be-declared-view'
          ]
        });
      }
    }
  }

  analyzeFunctionBody(statements) {
    const result = {
      modifiesState: false,
      readsState: false,
      hasExternalCalls: false
    };

    this.analyzeStatementsRecursive(statements, result);
    return result;
  }

  analyzeStatementsRecursive(statements, result) {
    if (!statements) return;

    statements.forEach(stmt => {
      const code = this.getCodeSnippet(stmt.loc);

      // Check for state modifications
      if (this.isStateModification(code, stmt)) {
        result.modifiesState = true;
      }

      // Check for state reads
      if (this.isStateRead(code, stmt)) {
        result.readsState = true;
      }

      // Check for external calls
      if (this.hasExternalCall(code)) {
        result.hasExternalCalls = true;
      }

      // Recurse into nested statements
      if (stmt.trueBody) {
        this.analyzeStatementsRecursive([stmt.trueBody], result);
      }
      if (stmt.falseBody) {
        this.analyzeStatementsRecursive([stmt.falseBody], result);
      }
      if (stmt.body && stmt.body.statements) {
        this.analyzeStatementsRecursive(stmt.body.statements, result);
      }
    });
  }

  isStateModification(code, stmt) {
    // Check for assignments to state variables (simplified heuristic)
    const modificationPatterns = [
      /\w+\s*=\s*[^=]/,              // Assignment (but not ==)
      /\.push\(/,                     // Array push
      /\.pop\(/,                      // Array pop
      /delete\s+\w+/,                 // Delete keyword
      /\+\+/,                         // Increment
      /--/,                           // Decrement
      /\+=/, /-=/, /\*=/, /\/=/      // Compound assignments
    ];

    // Exclude local variable assignments (very simplified)
    const isLocalVar = code.includes('memory') ||
                       code.includes('calldata') ||
                       stmt.type === 'VariableDeclarationStatement';

    if (isLocalVar) return false;

    return modificationPatterns.some(pattern => pattern.test(code));
  }

  isStateRead(code, stmt) {
    // Check for common state-reading patterns
    const stateReadPatterns = [
      /balances\[/,
      /mapping\(/,
      /storage\./,
      /this\./,
    ];

    // Also check for common state variable names (heuristic)
    const commonStateVars = [
      'owner', 'balance', 'total', 'count', 'supply',
      'allowed', 'approved', 'whitelist', 'blacklist'
    ];

    return stateReadPatterns.some(pattern => pattern.test(code)) ||
           commonStateVars.some(varName => code.includes(varName));
  }

  hasExternalCall(code) {
    return code.includes('.call(') ||
           code.includes('.delegatecall(') ||
           code.includes('.send(') ||
           code.includes('.transfer(') ||
           code.includes('.staticcall(');
  }
}

module.exports = StateMutabilityDetector;
