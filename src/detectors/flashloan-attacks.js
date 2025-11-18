const BaseDetector = require('./base-detector');

/**
 * Flash Loan Attack Detector
 * Detects vulnerable balance-based logic that can be exploited with flash loans
 * Critical for DeFi protocols handling significant value
 */
class FlashLoanAttackDetector extends BaseDetector {
  constructor() {
    super(
      'Flash Loan Attack Vulnerability',
      'Detects balance-based logic vulnerable to flash loan manipulation and price oracle attacks',
      'CRITICAL'
    );
    this.currentFunction = null;
    this.currentContract = null;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'fallback';

    if (node.body && node.body.statements) {
      this.analyzeFunction(node);
    }
  }

  analyzeFunction(node) {
    const code = this.getCodeSnippet(node.loc);
    const statements = this.getAllStatements(node.body.statements);

    // Pattern 1: Balance-based access control (CRITICAL)
    const balanceAccessControl = this.detectBalanceAccessControl(statements);
    if (balanceAccessControl) {
      this.addFinding({
        title: 'Flash Loan Attack: Balance-Based Access Control',
        description: `Function '${this.currentFunction}' uses token balance checks for access control or critical logic. An attacker can temporarily inflate their balance using a flash loan, bypass checks, and execute privileged operations. This is a critical vulnerability in DeFi protocols.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: balanceAccessControl.line,
        column: balanceAccessControl.column,
        code: balanceAccessControl.code,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        recommendation: 'Never use balanceOf() or address(this).balance for access control. Use explicit role-based permissions (e.g., onlyOwner, whitelists). For voting/governance, use snapshot-based mechanisms that record balances at specific blocks.',
        references: [
          'https://consensys.github.io/smart-contract-best-practices/attacks/oracle-manipulation/',
          'https://www.certik.com/resources/blog/flash-loan-attacks',
          'https://github.com/pcaversaccio/reentrancy-attacks#flash-loan-attack'
        ]
      });
    }

    // Pattern 2: Spot price usage (CRITICAL for DeFi)
    const spotPriceUsage = this.detectSpotPriceUsage(statements);
    if (spotPriceUsage) {
      this.addFinding({
        title: 'Flash Loan Attack: Spot Price Manipulation',
        description: `Function '${this.currentFunction}' appears to use spot prices from DEX reserves for critical calculations. Flash loans can manipulate reserves within a single transaction, causing incorrect pricing. This can lead to massive losses in lending/AMM protocols.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: spotPriceUsage.line,
        column: spotPriceUsage.column,
        code: spotPriceUsage.code,
        severity: 'CRITICAL',
        confidence: 'MEDIUM',
        recommendation: 'Use Chainlink price oracles, Uniswap V3 TWAP (Time-Weighted Average Price), or multiple oracle sources. Never rely on instant reserve ratios for pricing. Implement price deviation checks and circuit breakers.',
        references: [
          'https://docs.chain.link/data-feeds/price-feeds',
          'https://docs.uniswap.org/concepts/protocol/oracle',
          'https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles/'
        ]
      });
    }

    // Pattern 3: Unchecked balance changes
    const uncheckedBalanceChange = this.detectUncheckedBalanceChange(statements);
    if (uncheckedBalanceChange) {
      this.addFinding({
        title: 'Flash Loan Attack: Unchecked Balance Manipulation',
        description: `Function '${this.currentFunction}' performs calculations based on contract balance without validating expected vs actual amounts. Flash loan attacks can manipulate balances to exploit rounding errors or economic assumptions.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: uncheckedBalanceChange.line,
        column: uncheckedBalanceChange.column,
        code: uncheckedBalanceChange.code,
        severity: 'HIGH',
        confidence: 'MEDIUM',
        recommendation: 'Track internal accounting separately from actual balances. Validate that balance changes match expected amounts. Implement slippage protection and validate invariants before and after operations.',
        references: [
          'https://github.com/code-423n4/2021-10-slingshot-findings/issues/3'
        ]
      });
    }

    // Pattern 4: Single transaction liquidity dependency
    const liquidityDependency = this.detectLiquidityDependency(statements);
    if (liquidityDependency) {
      this.addFinding({
        title: 'Flash Loan Risk: Single-Transaction Liquidity Dependency',
        description: `Function '${this.currentFunction}' may depend on liquidity pool state that can be manipulated within a single transaction. This makes the protocol vulnerable to sandwich attacks and flash loan price manipulation.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: liquidityDependency.line,
        column: liquidityDependency.column,
        code: liquidityDependency.code,
        severity: 'HIGH',
        confidence: 'LOW',
        recommendation: 'Implement time-weighted mechanisms, use multiple blocks for price discovery, or require multi-block operations for critical state changes. Consider adding deposit/withdrawal delays.',
        references: [
          'https://github.com/yearn/yearn-security/blob/master/disclosures/2021-02-04.md'
        ]
      });
    }
  }

  detectBalanceAccessControl(statements) {
    for (const stmt of statements) {
      const code = this.getCodeSnippet(stmt.loc);

      // Check for balance in require/if statements for access control
      const balancePatterns = [
        /require\s*\([^)]*balanceOf\s*\(/i,
        /require\s*\([^)]*\.balance\s*>/,
        /if\s*\([^)]*balanceOf\s*\([^)]*\)\s*>=?/i,
        /if\s*\([^)]*\.balance\s*>=?/,
      ];

      if (balancePatterns.some(p => p.test(code))) {
        // Check if it's used for access control (has privileged operations after)
        const hasPrivilegedOps = code.match(/owner|admin|governance|mint|burn|withdraw|transfer/i);
        if (hasPrivilegedOps) {
          return {
            line: stmt.loc ? stmt.loc.start.line : 0,
            column: stmt.loc ? stmt.loc.start.column : 0,
            code: code
          };
        }
      }
    }
    return null;
  }

  detectSpotPriceUsage(statements) {
    for (const stmt of statements) {
      const code = this.getCodeSnippet(stmt.loc);

      // Check for reserve-based pricing calculations
      const spotPricePatterns = [
        /getReserves\s*\(/i,
        /reserve0\s*\*\s*reserve1/i,
        /\.mul\s*\([^)]*reserve/i,
        /price\s*=\s*[^;]*\.balanceOf/i,
        /amount\s*\*\s*reserve/i,
        /getAmountOut|getAmountIn/i, // Uniswap router calls without TWAP
      ];

      if (spotPricePatterns.some(p => p.test(code))) {
        // Verify it's not using TWAP
        if (!code.match(/twap|timeWeighted|observe|periodSize/i)) {
          return {
            line: stmt.loc ? stmt.loc.start.line : 0,
            column: stmt.loc ? stmt.loc.start.column : 0,
            code: code
          };
        }
      }
    }
    return null;
  }

  detectUncheckedBalanceChange(statements) {
    for (const stmt of statements) {
      const code = this.getCodeSnippet(stmt.loc);

      // Look for calculations using balance without validation
      if (code.match(/balanceOf|\.balance/) &&
          code.match(/[+\-*\/]/) &&
          !code.match(/require|assert|revert/)) {

        // Check if balance is used in calculation without safety checks
        if (code.match(/(balanceOf|\.balance)\s*[+\-*\/]/)) {
          return {
            line: stmt.loc ? stmt.loc.start.line : 0,
            column: stmt.loc ? stmt.loc.start.column : 0,
            code: code
          };
        }
      }
    }
    return null;
  }

  detectLiquidityDependency(statements) {
    for (const stmt of statements) {
      const code = this.getCodeSnippet(stmt.loc);

      // Check for liquidity-dependent operations
      const liquidityPatterns = [
        /swap\s*\(/i,
        /addLiquidity|removeLiquidity/i,
        /getReserves.*reserve/i,
      ];

      if (liquidityPatterns.some(p => p.test(code))) {
        // Check if there's slippage protection
        if (!code.match(/minAmount|maxAmount|deadline|slippage/i)) {
          return {
            line: stmt.loc ? stmt.loc.start.line : 0,
            column: stmt.loc ? stmt.loc.start.column : 0,
            code: code
          };
        }
      }
    }
    return null;
  }

  getAllStatements(statements, collected = []) {
    if (!statements) return collected;

    for (const stmt of statements) {
      collected.push(stmt);

      if (stmt.trueBody) {
        this.getAllStatements([stmt.trueBody], collected);
      }
      if (stmt.falseBody) {
        this.getAllStatements([stmt.falseBody], collected);
      }
      if (stmt.body && stmt.body.statements) {
        this.getAllStatements(stmt.body.statements, collected);
      }
    }

    return collected;
  }
}

module.exports = FlashLoanAttackDetector;
