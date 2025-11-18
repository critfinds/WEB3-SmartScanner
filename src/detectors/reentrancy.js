const BaseDetector = require('./base-detector');

class ReentrancyDetector extends BaseDetector {
  constructor() {
    super(
      'Reentrancy Vulnerability',
      'Detects potential reentrancy attacks where external calls can recursively call back into the contract',
      'CRITICAL'
    );
    this.currentFunction = null;
    this.externalCalls = [];
    this.stateChanges = [];
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name;
    this.externalCalls = [];
    this.stateChanges = [];

    // Traverse function body
    if (node.body) {
      this.analyzeFunctionBody(node.body, node);
    }

    // Check for reentrancy pattern: external call followed by state change
    this.checkReentrancyPattern(node);
  }

  analyzeFunctionBody(body, functionNode) {
    if (!body || !body.statements) return;

    for (let i = 0; i < body.statements.length; i++) {
      const stmt = body.statements[i];

      // Detect external calls (call, send, transfer, delegatecall)
      if (this.isExternalCall(stmt)) {
        this.externalCalls.push({ statement: stmt, index: i });
      }

      // Detect state changes
      if (this.isStateChange(stmt)) {
        this.stateChanges.push({ statement: stmt, index: i });
      }
    }
  }

  isExternalCall(node) {
    if (!node) return false;

    const code = this.getCodeSnippet(node.loc);

    // Check for common external call patterns
    return (
      code.includes('.call(') ||
      code.includes('.send(') ||
      code.includes('.transfer(') ||
      code.includes('.delegatecall(') ||
      (node.type === 'FunctionCall' && this.isMemberAccess(node.expression))
    );
  }

  isStateChange(node) {
    if (!node) return false;

    // Check for assignments to state variables
    if (node.type === 'ExpressionStatement' && node.expression) {
      const expr = node.expression;
      if (expr.type === 'BinaryOperation' && expr.operator === '=') {
        // Check if left side is a state variable (not local)
        return this.isLikelyStateVariable(expr.left);
      }
    }

    return false;
  }

  isLikelyStateVariable(node) {
    if (!node) return false;

    // State variables are usually accessed without local keyword
    // and not function parameters
    if (node.type === 'Identifier') {
      return true; // Simplified check
    }

    if (node.type === 'IndexAccess' || node.type === 'MemberAccess') {
      return true;
    }

    return false;
  }

  isMemberAccess(node) {
    return node && (node.type === 'MemberAccess' || node.type === 'IndexAccess');
  }

  checkReentrancyPattern(functionNode) {
    // Classic reentrancy: external call before state change
    for (const call of this.externalCalls) {
      for (const change of this.stateChanges) {
        if (call.index < change.index) {
          this.addFinding({
            title: 'Reentrancy Vulnerability Detected',
            description: `Function '${this.currentFunction}' performs an external call before updating state variables. This can allow attackers to recursively call back into the contract before state is updated (reentrancy attack).`,
            location: `Function: ${this.currentFunction}`,
            line: call.statement.loc ? call.statement.loc.start.line : 0,
            column: call.statement.loc ? call.statement.loc.start.column : 0,
            code: this.getCodeSnippet(call.statement.loc),
            recommendation: 'Use the Checks-Effects-Interactions pattern: perform all state changes before making external calls. Consider using ReentrancyGuard from OpenZeppelin.',
            references: [
              'https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/',
              'https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard'
            ]
          });
        }
      }
    }

    // Cross-function reentrancy (more complex, basic detection)
    if (this.externalCalls.length > 0 && functionNode.visibility !== 'private' && functionNode.visibility !== 'internal') {
      const hasLock = this.checkForReentrancyGuard(functionNode);

      if (!hasLock && this.externalCalls.length > 0) {
        this.addFinding({
          title: 'Potential Cross-Function Reentrancy',
          description: `Public/External function '${this.currentFunction}' makes external calls without apparent reentrancy protection. This may be vulnerable to cross-function reentrancy attacks.`,
          location: `Function: ${this.currentFunction}`,
          line: functionNode.loc ? functionNode.loc.start.line : 0,
          column: functionNode.loc ? functionNode.loc.start.column : 0,
          code: this.getCodeSnippet(functionNode.loc),
          recommendation: 'Add a reentrancy guard (mutex lock) to prevent recursive calls. Use OpenZeppelin\'s ReentrancyGuard or implement your own mutex.',
          references: [
            'https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/'
          ]
        });
      }
    }
  }

  checkForReentrancyGuard(node) {
    // Check if function has nonReentrant modifier or similar
    if (node.modifiers) {
      for (const modifier of node.modifiers) {
        const modifierName = modifier.name || '';
        if (modifierName.toLowerCase().includes('nonreentrant') ||
            modifierName.toLowerCase().includes('lock')) {
          return true;
        }
      }
    }
    return false;
  }
}

module.exports = ReentrancyDetector;
