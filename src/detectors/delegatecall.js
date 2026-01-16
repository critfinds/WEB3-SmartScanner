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
    const codeLower = code.toLowerCase();
    
    // Skip delegatecall in fallback/receive functions with assembly (standard proxy pattern)
    if (codeLower.includes('fallback') || codeLower.includes('receive')) {
      if (codeLower.includes('assembly') || codeLower.includes('calldatacopy')) {
        // This is a standard proxy pattern - check if implementation is validated
        const funcCode = this.getCodeSnippet(node.loc);
        if (funcCode && (funcCode.includes('require') && funcCode.includes('implementation'))) {
          return; // Secure proxy pattern
        }
        // Also check if it's in a function that validates implementation
        if (this.hasWhitelistValidation(node)) {
          return; // Has validation
        }
      }
    }
    
    // Check if delegatecall target is controlled by user input
    if (this.hasUserControlledTarget(node, code)) {
      // Check if there's whitelist validation in the function
      if (!this.hasWhitelistValidation(node)) {
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
      }
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

  hasWhitelistValidation(node) {
    // Check if the function containing this delegatecall has whitelist validation
    // Look for patterns like: require(trustedAddresses[target], ...) or require(isApproved[target], ...)
    const lineNum = node.loc ? node.loc.start.line : 0;
    const funcCode = this.getCodeSnippet(node.loc);

    // Check the function code for whitelist patterns
    const whitelistPatterns = [
      /require\s*\(\s*[^)]*\b(trusted|approved|whitelist|allowed|authorized)\w*\[/i,
      /require\s*\(\s*[^)]*\b(trusted|approved|whitelist|allowed|authorized)\w*\s*\(/i,
      /mapping\s*\([^)]*\)\s*public\s*(trusted|approved|whitelist|allowed)/i,
      /trustedImplementations\[/i,
      /approvedImplementations\[/i
    ];

    if (whitelistPatterns.some(pattern => pattern.test(funcCode))) {
      return true;
    }

    // Check a few lines before the delegatecall for validation
    for (let i = Math.max(1, lineNum - 10); i < lineNum; i++) {
      const line = this.getLineContent(i);
      // Look for whitelist patterns
      if (whitelistPatterns.some(pattern => pattern.test(line))) {
        return true;
      }
    }

    return false;
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
