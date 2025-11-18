const BaseDetector = require('./base-detector');

class LogicBugDetector extends BaseDetector {
  constructor() {
    super(
      'Logic Bugs',
      'Detects common logic errors and anti-patterns in smart contracts',
      'HIGH'
    );
  }

  visitFunctionDefinition(node) {
    if (!node.body) return;

    const code = this.getCodeSnippet(node.body.loc);
    const functionName = node.name || '';

    // Check for strict equality with ether balance
    this.checkStrictEqualityWithBalance(node, code, functionName);

    // Check for loops over dynamic arrays
    this.checkDynamicArrayLoops(node, code, functionName);

    // Check for missing zero address validation
    this.checkZeroAddressValidation(node, code, functionName);

    // Check for division before multiplication
    this.checkDivisionBeforeMultiplication(node, code, functionName);

    // Check for unrestricted ether reception
    this.checkUnrestrictedEtherReception(node, code, functionName);
  }

  checkStrictEqualityWithBalance(node, code, functionName) {
    const strictBalancePatterns = [
      /==\s*address\(this\)\.balance/,
      /address\(this\)\.balance\s*==/,
      /==\s*this\.balance/,
      /this\.balance\s*==/
    ];

    if (strictBalancePatterns.some(pattern => pattern.test(code))) {
      this.addFinding({
        title: 'Strict Equality with Contract Balance',
        description: `Function '${functionName}' uses strict equality (==) with contract balance. This can be exploited by forcing ether into the contract via selfdestruct.`,
        location: `Function: ${functionName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        recommendation: 'Use >= or <= instead of == when checking contract balance. Attackers can forcibly send ether using selfdestruct.',
        references: [
          'https://swcregistry.io/docs/SWC-132',
          'https://consensys.github.io/smart-contract-best-practices/attacks/force-feeding/'
        ]
      });
    }
  }

  checkDynamicArrayLoops(node, code, functionName) {
    // Check for loops that iterate over potentially unbounded arrays
    const loopPatterns = [
      /for\s*\([^)]*\.length/,
      /while\s*\([^)]*\.length/
    ];

    if (loopPatterns.some(pattern => pattern.test(code))) {
      // Check if it's a storage array (more dangerous)
      if (!code.includes('memory') || code.includes('storage')) {
        this.addFinding({
          title: 'Unbounded Loop Over Dynamic Array',
          description: `Function '${functionName}' contains a loop over a dynamic array. If the array grows too large, the function may exceed the gas limit and become unusable.`,
          location: `Function: ${functionName}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: this.getCodeSnippet(node.loc),
          recommendation: 'Avoid loops over unbounded arrays. Use pagination, mappings, or limit array size. Consider pull-over-push pattern for token distributions.',
          references: [
            'https://swcregistry.io/docs/SWC-128',
            'https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/#gas-limit-dos-on-a-contract-via-unbounded-operations'
          ]
        });
      }
    }
  }

  checkZeroAddressValidation(node, code, functionName) {
    // Check if function accepts address parameters
    if (node.parameters) {
      const hasAddressParam = node.parameters.some(param =>
        param.typeName && param.typeName.name === 'address'
      );

      if (hasAddressParam) {
        // Check if there's zero address validation
        const hasValidation =
          code.includes('!= address(0)') ||
          code.includes('!= address(0x0)') ||
          code.includes('require(') && code.includes('address') ||
          code.includes('AddressZero');

        if (!hasValidation) {
          this.addFinding({
            title: 'Missing Zero Address Validation',
            description: `Function '${functionName}' accepts address parameters but does not validate against zero address. This can lead to loss of funds or locked contracts.`,
            location: `Function: ${functionName}`,
            line: node.loc ? node.loc.start.line : 0,
            column: node.loc ? node.loc.start.column : 0,
            code: this.getCodeSnippet(node.loc),
            recommendation: 'Add validation: require(address != address(0), "Zero address not allowed");',
            references: []
          });
        }
      }
    }
  }

  checkDivisionBeforeMultiplication(node, code, functionName) {
    // Look for pattern: a / b * c which loses precision
    const divMulPattern = /\/[^;]*\*/;

    if (divMulPattern.test(code)) {
      this.addFinding({
        title: 'Division Before Multiplication',
        description: `Function '${functionName}' performs division before multiplication. This causes precision loss in Solidity's integer arithmetic.`,
        location: `Function: ${functionName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        recommendation: 'Perform multiplication before division to minimize precision loss: (a * c) / b instead of (a / b) * c',
        references: [
          'https://docs.soliditylang.org/en/latest/types.html#division'
        ]
      });
    }
  }

  checkUnrestrictedEtherReception(node, code, functionName) {
    // Check for receive() or fallback() without proper restrictions
    if (functionName === 'receive' || functionName === 'fallback' || functionName === '') {
      const hasValidation = code.includes('require(') || code.includes('revert(');

      if (!hasValidation && code.includes('payable')) {
        this.addFinding({
          title: 'Unrestricted Ether Reception',
          description: 'Contract can receive ether without restrictions. Ensure this is intentional and won\'t break contract logic.',
          location: `Function: ${functionName || 'fallback/receive'}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: this.getCodeSnippet(node.loc),
          recommendation: 'Add validation to fallback/receive functions if ether reception should be restricted. Document the intended behavior.',
          references: []
        });
      }
    }
  }

  visitBinaryOperation(node) {
    // Check for potential short address attack in token transfers
    const code = this.getCodeSnippet(node.loc);

    if (node.operator === '==' && (code.includes('msg.data.length') || code.includes('msg.data.length'))) {
      this.addFinding({
        title: 'Potential Short Address Attack Vulnerability',
        description: 'Function checks msg.data.length which may be vulnerable to short address attack.',
        location: this.getLocationString(node.loc),
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: code,
        recommendation: 'Modern Solidity versions handle this automatically. Ensure you are using Solidity 0.5.0+',
        references: [
          'https://blog.golemproject.net/how-to-find-10m-by-just-reading-blockchain-6ae9d39fcd95'
        ]
      });
    }
  }

  getLocationString(loc) {
    if (!loc || !loc.start) return 'Unknown';
    return `Line ${loc.start.line}, Column ${loc.start.column}`;
  }
}

module.exports = LogicBugDetector;
