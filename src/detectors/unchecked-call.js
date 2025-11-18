const BaseDetector = require('./base-detector');

class UncheckedCallDetector extends BaseDetector {
  constructor() {
    super(
      'Unchecked External Call',
      'Detects external calls whose return values are not checked',
      'HIGH'
    );
  }

  visitExpressionStatement(node) {
    if (!node.expression) return;

    const expr = node.expression;

    // Check for call expressions
    if (expr.type === 'FunctionCall') {
      this.checkFunctionCall(expr, node);
    }
  }

  checkFunctionCall(expr, parentNode) {
    const code = this.getCodeSnippet(expr.loc);

    // Check for low-level calls that should be checked
    if (this.isLowLevelCall(code)) {
      // If this is a standalone statement (not assigned or checked in if)
      // it means the return value is ignored
      if (parentNode.type === 'ExpressionStatement') {
        this.addFinding({
          title: 'Unchecked Low-Level Call',
          description: 'Low-level call (.call(), .delegatecall(), .staticcall()) return value is not checked. Failed calls will be silently ignored, potentially leading to unexpected behavior.',
          location: this.getLocationString(expr.loc),
          line: expr.loc ? expr.loc.start.line : 0,
          column: expr.loc ? expr.loc.start.column : 0,
          code: code,
          recommendation: 'Always check the return value of low-level calls. Use require(success, "error message") or implement proper error handling.',
          references: [
            'https://swcregistry.io/docs/SWC-104',
            'https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/'
          ]
        });
      }
    }

    // Check for .send() calls
    if (code.includes('.send(')) {
      if (parentNode.type === 'ExpressionStatement') {
        this.addFinding({
          title: 'Unchecked Send Return Value',
          description: 'The .send() function returns false on failure, but the return value is not checked. This can lead to unhandled failed transfers.',
          location: this.getLocationString(expr.loc),
          line: expr.loc ? expr.loc.start.line : 0,
          column: expr.loc ? expr.loc.start.column : 0,
          code: code,
          recommendation: 'Check the return value: require(recipient.send(amount), "Send failed"). Consider using .transfer() which reverts on failure, or .call{value: amount}() with proper checks.',
          references: [
            'https://swcregistry.io/docs/SWC-104'
          ]
        });
      }
    }
  }

  visitVariableDeclarationStatement(node) {
    // Check if a call's return value is assigned but never used
    if (node.variables && node.variables.length > 0) {
      const variable = node.variables[0];

      if (variable.name && node.initialValue) {
        const code = this.getCodeSnippet(node.initialValue.loc);

        if (this.isLowLevelCall(code)) {
          // Check if variable name suggests it should be checked (like 'success')
          if (variable.name.toLowerCase().includes('success')) {
            // This is actually good practice - assigning to success variable
            // We'd need flow analysis to see if it's checked later
            // For now, we'll warn about potential unchecked
            this.addFinding({
              title: 'Low-Level Call Return Value May Be Unchecked',
              description: `Low-level call result assigned to '${variable.name}'. Ensure this value is properly checked before proceeding with contract logic.`,
              location: this.getLocationString(node.loc),
              line: node.loc ? node.loc.start.line : 0,
              column: node.loc ? node.loc.start.column : 0,
              code: this.getCodeSnippet(node.loc),
              recommendation: 'Verify that the success variable is checked with require() or if statement before continuing execution.',
              references: []
            });
          }
        }
      }
    }
  }

  visitFunctionCall(node) {
    // Check for external contract calls
    if (node.expression && node.expression.type === 'MemberAccess') {
      const memberAccess = node.expression;
      const code = this.getCodeSnippet(node.loc);

      // Check for contract interface calls that might fail
      if (!code.includes('.transfer(') && // transfer reverts automatically
          !code.includes('.require(') &&
          !code.includes('.assert(') &&
          this.looksLikeExternalCall(memberAccess)) {

        // This might be an external contract call
        // We can only detect obvious cases
        const memberName = memberAccess.memberName;

        if (memberName && !this.isSafeFunction(memberName)) {
          this.addFinding({
            title: 'External Call Without Error Handling',
            description: `External call to '${memberName}' may fail silently. External calls can fail due to out-of-gas errors or reverts.`,
            location: this.getLocationString(node.loc),
            line: node.loc ? node.loc.start.line : 0,
            column: node.loc ? node.loc.start.column : 0,
            code: code,
            recommendation: 'Implement proper error handling for external calls. Consider using try/catch blocks (Solidity 0.6+) or check return values.',
            references: [
              'https://docs.soliditylang.org/en/latest/control-structures.html#try-catch'
            ]
          });
        }
      }
    }
  }

  isLowLevelCall(code) {
    return code.includes('.call(') ||
           code.includes('.call{') ||
           code.includes('.delegatecall(') ||
           code.includes('.delegatecall{') ||
           code.includes('.staticcall(') ||
           code.includes('.staticcall{');
  }

  looksLikeExternalCall(memberAccess) {
    // Check if this looks like an external contract call
    // This is a heuristic and may have false positives
    if (memberAccess.expression) {
      const expr = memberAccess.expression;

      // Check if it's calling a function on a variable (likely a contract)
      if (expr.type === 'Identifier') {
        return true;
      }

      // Check if it's calling a function on an indexed access (like contracts[0].function())
      if (expr.type === 'IndexAccess') {
        return true;
      }
    }

    return false;
  }

  isSafeFunction(functionName) {
    // Functions that are known to be safe or internal operations
    const safeFunctions = [
      'add', 'sub', 'mul', 'div', 'mod', // SafeMath
      'push', 'pop', 'length', // Array operations
      'keccak256', 'sha256', 'ripemd160', // Hash functions
      'encode', 'decode', 'encodePacked', // Encoding
      'toString', 'toUpperCase', 'toLowerCase' // String operations
    ];

    return safeFunctions.includes(functionName);
  }

  getLocationString(loc) {
    if (!loc || !loc.start) return 'Unknown';
    return `Line ${loc.start.line}, Column ${loc.start.column}`;
  }
}

module.exports = UncheckedCallDetector;
