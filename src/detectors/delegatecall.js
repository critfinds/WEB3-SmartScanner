const BaseDetector = require('./base-detector');

class DelegateCallDetector extends BaseDetector {
  constructor() {
    super(
      'Dangerous Delegatecall',
      'Detects unsafe delegatecall usage that could lead to contract takeover',
      'CRITICAL'
    );
  }

  visitFunctionCall(node) {
    const code = this.getCodeSnippet(node.loc);

    if (code.includes('delegatecall(')) {
      this.checkDelegatecall(node, code);
    }
  }

  checkDelegatecall(node, code) {
    // Check if delegatecall target is controlled by user input
    if (this.hasUserControlledTarget(node, code)) {
      this.addFinding({
        title: 'User-Controlled Delegatecall',
        description: 'Delegatecall is made to a user-controlled address. This allows attackers to execute arbitrary code in the context of this contract, potentially taking full control.',
        location: this.getLocationString(node.loc),
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: code,
        recommendation: 'Never allow user input to control delegatecall targets. Use a whitelist of trusted contract addresses or avoid delegatecall entirely.',
        references: [
          'https://swcregistry.io/docs/SWC-112',
          'https://blog.openzeppelin.com/on-the-parity-wallet-multisig-hack-405a8c12e8f7'
        ]
      });
    } else {
      // Even with controlled targets, delegatecall is dangerous
      this.addFinding({
        title: 'Delegatecall Detected',
        description: 'Delegatecall executes code in the context of the calling contract. Ensure the called contract is trusted and storage layout is compatible to prevent storage corruption.',
        location: this.getLocationString(node.loc),
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: code,
        recommendation: 'Only use delegatecall with fully trusted contracts. Verify storage layout compatibility. Consider using libraries or regular calls instead.',
        references: [
          'https://docs.soliditylang.org/en/latest/introduction-to-smart-contracts.html#delegatecall-callcode-and-libraries',
          'https://swcregistry.io/docs/SWC-112'
        ]
      });
    }

    // Check if return value is checked
    if (!this.isReturnValueChecked(node)) {
      this.addFinding({
        title: 'Unchecked Delegatecall Return Value',
        description: 'Delegatecall return value is not checked. Failed delegatecalls will be silently ignored.',
        location: this.getLocationString(node.loc),
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: code,
        recommendation: 'Always check delegatecall return value: (bool success, ) = target.delegatecall(...); require(success, "Delegatecall failed");',
        references: [
          'https://swcregistry.io/docs/SWC-104'
        ]
      });
    }
  }

  hasUserControlledTarget(node, code) {
    // Check for common patterns of user-controlled addresses
    if (node.expression && node.expression.type === 'MemberAccess') {
      const target = node.expression.expression;

      if (target) {
        // Check if target is a parameter, msg.sender related, or mapping access
        if (target.type === 'Identifier') {
          const targetCode = this.getCodeSnippet(target.loc);

          // Check if it looks like a function parameter or user-influenced variable
          if (targetCode.includes('_') || // Common parameter naming
              this.looksLikeFunctionParameter(targetCode)) {
            return true;
          }
        }

        // Check if accessing mapping or array with user input
        if (target.type === 'IndexAccess') {
          return true;
        }
      }
    }

    // Check if the delegatecall includes parameters that might be user-controlled
    if (code.match(/delegatecall\([^)]*\b(msg\.sender|_\w+|\w+\[\w+\])/)) {
      return true;
    }

    return false;
  }

  looksLikeFunctionParameter(code) {
    // Simple heuristic: parameters often start with underscore or are simple names
    return code.startsWith('_') ||
           code === 'target' ||
           code === 'destination' ||
           code === 'implementation' ||
           code === 'logic';
  }

  isReturnValueChecked(node) {
    // This is a simplified check - would need parent context analysis for full accuracy
    // We'll look for assignment to variable or usage in require/if

    // Check if the node is part of an assignment
    // This is difficult without parent reference, so we'll check the surrounding code
    const line = this.getLineContent(node.loc ? node.loc.start.line : 0);

    return line.includes('bool') ||
           line.includes('success') ||
           line.includes('require(') ||
           line.includes('if (');
  }

  getLocationString(loc) {
    if (!loc || !loc.start) return 'Unknown';
    return `Line ${loc.start.line}, Column ${loc.start.column}`;
  }
}

module.exports = DelegateCallDetector;
