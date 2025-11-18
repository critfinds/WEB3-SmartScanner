const BaseDetector = require('./base-detector');

/**
 * Missing Events Detector
 * Detects critical state changes that don't emit events
 * Important for transparency and off-chain monitoring
 */
class MissingEventsDetector extends BaseDetector {
  constructor() {
    super(
      'Missing Events for Critical Operations',
      'Detects state-changing functions that should emit events for transparency and monitoring',
      'LOW'
    );
    this.currentFunction = null;
    this.currentContract = null;
    this.contractEvents = new Set();
  }

  async detect(ast, sourceCode, fileName) {
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.findings = [];
    this.contractEvents.clear();

    this.visit(ast);
    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
    this.contractEvents.clear();

    // Collect all events defined in the contract
    if (node.subNodes) {
      node.subNodes.forEach(subNode => {
        if (subNode.type === 'EventDefinition') {
          this.contractEvents.add(subNode.name);
        }
      });
    }
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name;

    // Skip view/pure functions and constructors
    if (node.stateMutability === 'view' ||
        node.stateMutability === 'pure' ||
        node.isConstructor ||
        !node.name) {
      return;
    }

    // Check if function modifies critical state
    const modifiesCriticalState = this.checkForCriticalStateChanges(node);

    if (modifiesCriticalState) {
      // Check if function emits events
      const emitsEvent = this.checkForEventEmission(node);

      if (!emitsEvent) {
        const code = this.getCodeSnippet(node.loc);

        // Determine severity based on function criticality
        const severity = this.determineSeverity(node, code);

        this.addFinding({
          title: 'Missing Event Emission',
          description: `Function '${this.currentFunction}' in contract '${this.currentContract}' modifies critical state but does not emit any events. Events are crucial for off-chain monitoring, transparency, and creating an audit trail of state changes.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: code,
          severity: severity,
          recommendation: 'Add event emission for this state change. Define an event and emit it after successful state modification. Example: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);',
          references: [
            'https://github.com/crytic/slither/wiki/Detector-Documentation#missing-events-arithmetic',
            'https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/event-monitoring/'
          ]
        });
      }
    }
  }

  checkForCriticalStateChanges(node) {
    if (!node.body || !node.body.statements) return false;

    const code = this.getCodeSnippet(node.loc);

    // Critical patterns that should always emit events
    const criticalPatterns = [
      /owner\s*=/,                    // Ownership changes
      /pause/i,                       // Pause/unpause
      /whitelist/i,                   // Whitelist changes
      /blacklist/i,                   // Blacklist changes
      /role/i,                        // Role changes
      /admin/i,                       // Admin changes
      /fee/i,                         // Fee changes
      /rate/i,                        // Rate changes
      /limit/i,                       // Limit changes
      /threshold/i,                   // Threshold changes
      /mint/i,                        // Token minting
      /burn/i,                        // Token burning
      /withdraw/i,                    // Withdrawals
      /deposit/i,                     // Deposits
      /transfer\s*\(/,                // Transfers
      /approve/i,                     // Approvals
      /upgrade/i,                     // Contract upgrades
      /selfdestruct/,                 // Contract destruction
    ];

    return criticalPatterns.some(pattern => pattern.test(code));
  }

  checkForEventEmission(node) {
    if (!node.body || !node.body.statements) return false;

    return this.hasEventInStatements(node.body.statements);
  }

  hasEventInStatements(statements) {
    if (!statements) return false;

    for (const stmt of statements) {
      // Check for emit statement
      if (stmt.type === 'EmitStatement') {
        return true;
      }

      // Check for old-style event (no emit keyword, pre-0.4.21)
      if (stmt.type === 'ExpressionStatement' && stmt.expression) {
        const code = this.getCodeSnippet(stmt.loc);
        // Check if it matches an event name
        for (const eventName of this.contractEvents) {
          if (code.includes(eventName + '(')) {
            return true;
          }
        }
      }

      // Recurse into nested blocks
      if (stmt.trueBody && this.hasEventInStatements([stmt.trueBody])) {
        return true;
      }
      if (stmt.falseBody && this.hasEventInStatements([stmt.falseBody])) {
        return true;
      }
      if (stmt.body && stmt.body.statements && this.hasEventInStatements(stmt.body.statements)) {
        return true;
      }
    }

    return false;
  }

  determineSeverity(node, code) {
    // High severity for critical operations
    const highSeverityPatterns = [
      /owner\s*=/,
      /selfdestruct/,
      /upgrade/i,
      /pause/i,
    ];

    if (highSeverityPatterns.some(pattern => pattern.test(code))) {
      return 'MEDIUM';
    }

    // Check if function is external/public
    if (node.visibility === 'external' || node.visibility === 'public') {
      return 'LOW';
    }

    return 'INFO';
  }
}

module.exports = MissingEventsDetector;
