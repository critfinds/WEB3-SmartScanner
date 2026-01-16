const BaseDetector = require('./base-detector');

/**
 * Detector for deprecated functions
 *
 * This detector finds usage of deprecated functions like `tx.origin` for authorization,
 * `selfdestruct` (in favor of CREATE2), and other patterns that are discouraged.
 */
class DeprecatedFunctionsDetector extends BaseDetector {
  constructor() {
    super(
      'Deprecated Functions',
      'Finds usage of deprecated or discouraged Solidity functions and patterns',
      'LOW' // Default severity
    );

    this.deprecatedPatterns = {
      'tx.origin': {
        severity: 'HIGH',
        description: 'Authorization using tx.origin is insecure and can be exploited by phishing attacks.',
        confidence: 'HIGH'
      },
      selfdestruct: {
        severity: 'MEDIUM',
        description:
          'selfdestruct is discouraged. Consider using CREATE2 for contract removal or disabling the contract instead.',
        confidence: 'MEDIUM'
      },
      'block.timestamp': {
        severity: 'LOW',
        description:
          'block.timestamp can be manipulated by miners. Do not rely on it for critical logic or entropy.',
        confidence: 'LOW'
      }
    };
  }

  visitMemberAccess(node) {
    const expression = this.getSourceFromNode(node);
    if (this.deprecatedPatterns[expression]) {
      const { severity, description, confidence } = this.deprecatedPatterns[expression];
      this.addFinding({
        title: `Usage of deprecated or insecure pattern: ${expression}`,
        description: description,
        severity: severity,
        confidence: confidence,
        location: node.loc,
        line: node.loc.start.line,
        column: node.loc.start.column,
        code: this.getCodeSnippet(node.loc)
      });
    }
  }

  // Helper to get source from a node
  getSourceFromNode(node) {
    if (!node || !node.range || !this.sourceCode) return '';
    return this.sourceCode.substring(node.range[0], node.range[1] + 1);
  }
}

module.exports = DeprecatedFunctionsDetector;
