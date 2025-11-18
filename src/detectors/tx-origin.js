const BaseDetector = require('./base-detector');

/**
 * tx.origin Authentication Detector
 * Detects dangerous use of tx.origin for authorization
 * tx.origin can be exploited in phishing attacks
 */
class TxOriginDetector extends BaseDetector {
  constructor() {
    super(
      'Dangerous tx.origin Usage',
      'Detects use of tx.origin for authentication which is vulnerable to phishing attacks',
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
    this.checkFunctionForTxOrigin(node);
  }

  visitModifierDefinition(node) {
    this.currentFunction = `modifier ${node.name}`;
    this.checkFunctionForTxOrigin(node);
  }

  checkFunctionForTxOrigin(node) {
    if (!node.body) return;

    this.traverseStatements(node.body.statements, node);
  }

  traverseStatements(statements, functionNode) {
    if (!statements) return;

    statements.forEach(stmt => {
      this.checkStatement(stmt, functionNode);

      // Recurse into nested blocks
      if (stmt.trueBody) {
        this.traverseStatements([stmt.trueBody], functionNode);
      }
      if (stmt.falseBody) {
        this.traverseStatements([stmt.falseBody], functionNode);
      }
      if (stmt.body && stmt.body.statements) {
        this.traverseStatements(stmt.body.statements, functionNode);
      }
    });
  }

  checkStatement(stmt, functionNode) {
    const code = this.getCodeSnippet(stmt.loc);

    // Check for tx.origin usage
    if (code.includes('tx.origin')) {
      // Check if it's used in a security context (require, if, modifier)
      const isInSecurityContext =
        code.includes('require') ||
        code.includes('assert') ||
        code.includes('if') ||
        code.includes('==') ||
        code.includes('!=');

      if (isInSecurityContext) {
        this.addFinding({
          title: 'Dangerous Use of tx.origin for Authentication',
          description: `Function '${this.currentFunction}' in contract '${this.currentContract}' uses tx.origin for authentication. tx.origin represents the original sender of the transaction and can be exploited in phishing attacks where a malicious contract tricks a user into calling it, then uses the user's tx.origin to call your contract.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: stmt.loc ? stmt.loc.start.line : 0,
          column: stmt.loc ? stmt.loc.start.column : 0,
          code: code,
          recommendation: 'Replace tx.origin with msg.sender for authorization checks. msg.sender represents the immediate caller and cannot be spoofed through intermediary contracts.',
          references: [
            'https://swcregistry.io/docs/SWC-115',
            'https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/tx-origin/',
            'https://github.com/crytic/slither/wiki/Detector-Documentation#dangerous-usage-of-txorigin'
          ]
        });
      } else {
        // Even non-auth usage should be flagged as suspicious
        this.addFinding({
          title: 'Suspicious tx.origin Usage',
          description: `Function '${this.currentFunction}' uses tx.origin. While not immediately dangerous, tx.origin usage is generally discouraged as it can lead to security issues and makes code harder to reason about.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: stmt.loc ? stmt.loc.start.line : 0,
          column: stmt.loc ? stmt.loc.start.column : 0,
          code: code,
          severity: 'MEDIUM',
          recommendation: 'Consider using msg.sender instead of tx.origin unless you have a specific use case requiring the original transaction sender.',
          references: [
            'https://swcregistry.io/docs/SWC-115'
          ]
        });
      }
    }
  }
}

module.exports = TxOriginDetector;
