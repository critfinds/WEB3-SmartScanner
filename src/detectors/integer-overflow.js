const BaseDetector = require('./base-detector');

class IntegerOverflowDetector extends BaseDetector {
  constructor() {
    super(
      'Integer Overflow/Underflow',
      'Detects unchecked arithmetic operations that may overflow or underflow',
      'HIGH'
    );
    this.solidityVersion = '';
  }

  visitPragmaDirective(node) {
    if (node.name === 'solidity') {
      this.solidityVersion = node.value;
    }
  }

  visitBinaryOperation(node) {
    // Solidity 0.8.0+ has built-in overflow checks
    if (this.isSafeVersion(this.solidityVersion)) {
      return;
    }

    const operator = node.operator;
    const arithmeticOps = ['+', '-', '*', '/', '**', '<<', '>>'];

    if (arithmeticOps.includes(operator)) {
      // Check if SafeMath is being used
      const code = this.getCodeSnippet(node.loc);

      if (!this.usesSafeMath(code)) {
        this.addFinding({
          title: 'Unchecked Arithmetic Operation',
          description: `Arithmetic operation '${operator}' without overflow/underflow protection. In Solidity < 0.8.0, this can lead to integer overflow or underflow vulnerabilities.`,
          location: this.getLocationString(node.loc),
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: code,
          recommendation: 'Use SafeMath library for arithmetic operations or upgrade to Solidity 0.8.0+ which has built-in overflow checks.',
          references: [
            'https://docs.openzeppelin.com/contracts/2.x/api/math',
            'https://blog.soliditylang.org/2020/10/28/solidity-0.8.x-preview/'
          ]
        });
      }
    }
  }

  visitUnaryOperation(node) {
    if (this.isSafeVersion(this.solidityVersion)) {
      return;
    }

    if (node.operator === '++' || node.operator === '--') {
      const code = this.getCodeSnippet(node.loc);

      if (!this.usesSafeMath(code)) {
        this.addFinding({
          title: 'Unchecked Increment/Decrement',
          description: `Unary operation '${node.operator}' without overflow/underflow protection. This may cause unexpected behavior in edge cases.`,
          location: this.getLocationString(node.loc),
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: code,
          recommendation: 'Use SafeMath library or upgrade to Solidity 0.8.0+.',
          references: []
        });
      }
    }
  }

  isSafeVersion(versionString) {
    if (!versionString) return false;

    // Extract version number
    const match = versionString.match(/(\d+)\.(\d+)\.(\d+)/);
    if (!match) return false;

    const major = parseInt(match[1]);
    const minor = parseInt(match[2]);

    // Solidity 0.8.0+ has built-in overflow checks
    return major > 0 || (major === 0 && minor >= 8);
  }

  usesSafeMath(code) {
    // Basic check for SafeMath usage
    return code.includes('.add(') ||
           code.includes('.sub(') ||
           code.includes('.mul(') ||
           code.includes('.div(') ||
           code.includes('SafeMath');
  }

  getLocationString(loc) {
    if (!loc || !loc.start) return 'Unknown';
    return `Line ${loc.start.line}, Column ${loc.start.column}`;
  }
}

module.exports = IntegerOverflowDetector;
