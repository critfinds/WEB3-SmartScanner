const BaseDetector = require('./base-detector');

class FrontRunningDetector extends BaseDetector {
  constructor() {
    super(
      'Front-Running Vulnerability',
      'Detects potential front-running and transaction ordering dependencies',
      'HIGH'
    );
  }

  visitFunctionDefinition(node) {
    const functionName = node.name || '';
    const visibility = node.visibility || 'public';

    // Only check public/external functions
    if (visibility !== 'public' && visibility !== 'external') {
      return;
    }

    const code = node.body ? this.getCodeSnippet(node.body.loc) : '';

    // Check for price/rate setting functions
    if (this.isPriceSettingFunction(functionName, code)) {
      this.addFinding({
        title: 'Front-Runnable Price Update',
        description: `Function '${functionName}' updates prices/rates and can be front-run. Attackers can observe pending transactions and submit their own transactions with higher gas to profit from price changes.`,
        location: `Function: ${functionName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        recommendation: 'Implement commit-reveal scheme, use batch auctions, or implement price update delays/time locks.',
        references: [
          'https://consensys.github.io/smart-contract-best-practices/attacks/frontrunning/'
        ]
      });
    }

    // Check for approval-based patterns
    if (this.hasApprovalPattern(functionName, code)) {
      this.addFinding({
        title: 'ERC20 Approval Race Condition',
        description: `Function '${functionName}' uses approve pattern which is vulnerable to front-running. An attacker can observe approval changes and spend both old and new allowances.`,
        location: `Function: ${functionName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        recommendation: 'Use increaseAllowance/decreaseAllowance pattern instead of approve, or require allowance to be 0 before changing.',
        references: [
          'https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#ERC20-increaseAllowance-address-uint256-',
          'https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729'
        ]
      });
    }

    // Check for transaction ordering dependence
    if (this.hasOrderingDependence(code)) {
      this.addFinding({
        title: 'Transaction Ordering Dependence',
        description: `Function '${functionName}' has logic that depends on transaction ordering. This can be exploited by miners or through front-running.`,
        location: `Function: ${functionName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        recommendation: 'Design functions to be order-independent. Use commit-reveal schemes or batch processing for sensitive operations.',
        references: [
          'https://swcregistry.io/docs/SWC-114'
        ]
      });
    }

    // Check for vulnerable DEX/AMM patterns
    if (this.hasSwapPattern(functionName, code)) {
      this.addFinding({
        title: 'MEV Vulnerable Swap Function',
        description: `Function '${functionName}' performs token swaps and is vulnerable to MEV (Maximal Extractable Value) attacks including sandwich attacks.`,
        location: `Function: ${functionName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        recommendation: 'Implement slippage protection, minimum output amounts, and deadlines. Consider using MEV protection services or private transaction pools.',
        references: [
          'https://ethereum.org/en/developers/docs/mev/'
        ]
      });
    }
  }

  isPriceSettingFunction(functionName, code) {
    const priceFunctionPatterns = [
      'setprice', 'updateprice', 'changeprice',
      'setrate', 'updaterate', 'changerate',
      'setexchangerate', 'updateexchangerate'
    ];

    const lowerName = functionName.toLowerCase().replace(/[_\s]/g, '');

    if (priceFunctionPatterns.some(pattern => lowerName.includes(pattern))) {
      return true;
    }

    // Check code for price/rate assignments
    if ((code.includes('price =') || code.includes('rate =')) &&
        !code.includes('view') && !code.includes('pure')) {
      return true;
    }

    return false;
  }

  hasApprovalPattern(functionName, code) {
    const lowerName = functionName.toLowerCase();

    if (lowerName === 'approve' || lowerName.includes('approval')) {
      return true;
    }

    if (code.includes('allowance[') || code.includes('_allowances[')) {
      return true;
    }

    return false;
  }

  hasOrderingDependence(code) {
    // Check for patterns that suggest ordering matters
    const orderingPatterns = [
      /first\s*=.*true/i,
      /isFirst/i,
      /lastCaller/i,
      /previousTransaction/i,
      /txCounter/i
    ];

    return orderingPatterns.some(pattern => pattern.test(code));
  }

  hasSwapPattern(functionName, code) {
    const swapFunctionNames = [
      'swap', 'exchange', 'trade', 'buy', 'sell'
    ];

    const lowerName = functionName.toLowerCase().replace(/[_\s]/g, '');

    if (swapFunctionNames.some(pattern => lowerName.includes(pattern))) {
      return true;
    }

    // Check for swap-like operations in code
    if ((code.includes('transferFrom') && code.includes('transfer(')) ||
        code.includes('getAmountOut') ||
        code.includes('swapExactTokens')) {
      return true;
    }

    return false;
  }
}

module.exports = FrontRunningDetector;
