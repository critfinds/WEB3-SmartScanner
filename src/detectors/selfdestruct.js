const BaseDetector = require('./base-detector');

class UnprotectedSelfdestructDetector extends BaseDetector {
  constructor() {
    super(
      'Unprotected Selfdestruct',
      'Detects selfdestruct calls that may be exploitable',
      'CRITICAL'
    );
  }

  visitFunctionCall(node) {
    const code = this.getCodeSnippet(node.loc);

    // Check for selfdestruct or suicide (deprecated)
    if (code.includes('selfdestruct(') || code.includes('suicide(')) {
      this.checkSelfdestructCall(node, code);
    }
  }

  checkSelfdestructCall(node, code) {
    // Get the function containing this selfdestruct
    const functionContext = this.findContainingFunction(node);

    if (functionContext) {
      const functionName = functionContext.name || 'anonymous';
      const visibility = functionContext.visibility || 'public';

      // Check if function has access control
      const hasAccessControl = this.checkAccessControl(functionContext);

      if (!hasAccessControl) {
        this.addFinding({
          title: 'Unprotected Selfdestruct',
          description: `Function '${functionName}' contains selfdestruct without proper access control. Any user can destroy the contract and steal its funds.`,
          location: `Function: ${functionName}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: code,
          recommendation: 'Add strict access control (e.g., onlyOwner modifier) to functions containing selfdestruct. Consider if selfdestruct is necessary at all.',
          references: [
            'https://swcregistry.io/docs/SWC-106',
            'https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/public-data/'
          ]
        });
      } else {
        // Even with access control, selfdestruct is dangerous
        this.addFinding({
          title: 'Selfdestruct Present',
          description: `Function '${functionName}' contains selfdestruct. This permanently destroys the contract and sends all ether to a target address. Ensure this is intentional and well-documented.`,
          location: `Function: ${functionName}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: code,
          recommendation: 'Consider alternatives to selfdestruct. If needed, implement timelock and multi-sig requirements. Note: selfdestruct will change behavior in future Ethereum upgrades.',
          references: [
            'https://eips.ethereum.org/EIPS/eip-6049',
            'https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/public-data/'
          ]
        });
      }

      // Check selfdestruct recipient
      this.checkSelfdestructRecipient(node, code, functionName);
    }
  }

  checkSelfdestructRecipient(node, code, functionName) {
    // Check if the recipient address is user-controlled
    const recipientPatterns = [
      /selfdestruct\(payable\(\s*msg\.sender\s*\)\)/,
      /selfdestruct\(\s*msg\.sender\s*\)/,
      /selfdestruct\(payable\(\s*_\w+\s*\)\)/,
      /selfdestruct\(\s*_\w+\s*\)/
    ];

    if (recipientPatterns.some(pattern => pattern.test(code))) {
      this.addFinding({
        title: 'User-Controlled Selfdestruct Recipient',
        description: `Function '${functionName}' allows user-controlled address as selfdestruct recipient. This may allow attackers to steal contract funds.`,
        location: `Function: ${functionName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: code,
        recommendation: 'Hardcode the recipient address or use a trusted, immutable address. Never allow user input to control selfdestruct destination.',
        references: [
          'https://swcregistry.io/docs/SWC-106'
        ]
      });
    }
  }

  findContainingFunction(node) {
    // This is a simplified version - would need proper AST parent tracking
    // We'll use a heuristic by checking if we're storing function context
    return this.currentFunction;
  }

  visitFunctionDefinition(node) {
    // Store current function context for nested checks
    this.currentFunction = node;

    // Continue with normal traversal
    this.traverse(node.body);

    this.currentFunction = null;
  }

  checkAccessControl(functionNode) {
    if (!functionNode.modifiers || functionNode.modifiers.length === 0) {
      return false;
    }

    const accessControlModifiers = [
      'onlyowner', 'onlyadmin', 'onlyauthorized',
      'onlygovernance', 'restricted'
    ];

    return functionNode.modifiers.some(modifier => {
      const modifierName = (modifier.name || '').toLowerCase().replace(/[_\s]/g, '');
      return accessControlModifiers.some(acm => modifierName.includes(acm));
    });
  }
}

module.exports = UnprotectedSelfdestructDetector;
