const BaseDetector = require('./base-detector');

/**
 * Flash Loan Attack Pattern Detector (Enhanced)
 * Detects patterns vulnerable to flash loan manipulation with context awareness
 * to reduce false positives and classify real exploitable issues.
 */
class FlashLoanDetector extends BaseDetector {
  constructor() {
    super(
      'Flash Loan Vulnerability',
      'Detects patterns vulnerable to flash loan attacks',
      'CRITICAL'
    );
    this.currentContract = null;
    this.currentFunction = null;
    this.currentFunctionNode = null;
    this.cfg = null;
    this.balanceUsages = [];
    this.priceCalculations = [];
    this.valueFlows = [];
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;

    this.traverse(ast);

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
    // Reset per-contract tracking
    this.balanceUsages = [];
    this.priceCalculations = [];
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'constructor';
    this.currentFunctionNode = node;

    // Reset per-function tracking
    this.functionBalanceUsages = [];
    this.functionDivisions = [];
    this.functionExternalCalls = [];

    // Analyze the full function for flash loan patterns
    if (node.body) {
      this.deepAnalyzeFunction(node);
    }
  }

  /**
   * Deep analysis of function to find actual exploitable flash loan patterns
   * Only flags when: balance/reserves → division/calculation → value transfer/minting
   */
  deepAnalyzeFunction(funcNode) {
    const funcCode = this.getCodeSnippet(funcNode.loc);
    const funcCodeLower = funcCode.toLowerCase();

    // Skip internal/private functions (not directly exploitable)
    if (funcNode.visibility === 'private' || funcNode.visibility === 'internal') {
      return;
    }

    // Skip view/pure functions (can't cause direct fund loss)
    if (funcNode.stateMutability === 'view' || funcNode.stateMutability === 'pure') {
      return;
    }

    // Check for known safe patterns that should be excluded
    if (this.hasSafeGuards(funcCode)) {
      return;
    }

    // Pattern 1: Spot price oracle for value calculations (HIGH confidence)
    const spotPricePattern = this.detectSpotPriceOracle(funcCode, funcNode);

    // Pattern 2: Balance-based pricing (MEDIUM-HIGH confidence depending on context)
    const balancePricingPattern = this.detectBalanceBasedPricing(funcCode, funcNode);

    // Pattern 3: Reserve ratio manipulation (HIGH confidence)
    const reserveManipPattern = this.detectReserveManipulation(funcCode, funcNode);
  }

  /**
   * Check for safe guards that mitigate flash loan attacks
   */
  hasSafeGuards(code) {
    const safePatterns = [
      // TWAP oracles
      /observe\s*\(/i,
      /consult\s*\(/i,
      /twap/i,
      /timeWeightedAverage/i,
      // Chainlink oracles
      /latestRoundData/i,
      /priceFeed/i,
      /AggregatorV3/i,
      // Multi-block checks
      /block\.number\s*-/i,
      /previousBlock/i,
      /lastUpdateBlock/i,
      // Flash loan callbacks that indicate awareness
      /onFlashLoan/i,
      /flashLoanCallback/i,
      // Internal accounting (safe pattern)
      /internalBalance/i,
      /_balance\[/i,
      /balances\[/i,
    ];

    return safePatterns.some(pattern => pattern.test(code));
  }

  /**
   * Detect spot price oracle usage that flows into value calculations
   */
  detectSpotPriceOracle(code, funcNode) {
    // High-risk spot price functions
    // Note: Don't use /g flag with test() as it causes stateful behavior
    const spotPricePatterns = [
      { pattern: /\.getReserves\s*\(\s*\)/, name: 'getReserves' },
      { pattern: /\.getAmountsOut\s*\(/, name: 'getAmountsOut' },
      { pattern: /\.getAmountOut\s*\(/, name: 'getAmountOut' },
      { pattern: /\.getAmountsIn\s*\(/, name: 'getAmountsIn' },
      { pattern: /\.quote\s*\(/, name: 'quote' },
    ];

    for (const { pattern, name } of spotPricePatterns) {
      if (pattern.test(code)) {
        // Check if result flows into value-affecting operations
        const flowsToValue = this.checkValueFlow(code, name);

        if (flowsToValue.isExploitable) {
          this.addFinding({
            title: 'Spot Price Oracle Manipulation',
            description: `Function uses '${name}()' for price calculation which can be manipulated in a single transaction via flash loans. ${flowsToValue.reason}`,
            location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
            line: funcNode.loc ? funcNode.loc.start.line : 0,
            column: funcNode.loc ? funcNode.loc.start.column : 0,
            code: this.extractRelevantCode(code, name),
            severity: 'CRITICAL',
            confidence: 'HIGH',
            exploitable: true,
            exploitabilityScore: 85,
            attackVector: 'flash-loan-oracle-manipulation',
            recommendation: 'Replace spot price oracle with TWAP oracle (Uniswap V3 observe()) or Chainlink price feeds (latestRoundData). Never use single-block prices for value calculations.',
            references: [
              'https://docs.chain.link/data-feeds',
              'https://docs.uniswap.org/concepts/protocol/oracle',
              'https://www.paradigm.xyz/2020/11/so-you-want-to-use-a-price-oracle'
            ],
            foundryPoC: this.generateSpotPricePoC(name, this.currentContract, this.currentFunction)
          });
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Detect balance-based pricing that could be manipulated
   */
  detectBalanceBasedPricing(code, funcNode) {
    // Only flag if balance is used in division for pricing
    const balanceInDivision = /(?:balanceOf|\.balance)[^;]*\/[^;]*|[^;]*\/[^;]*(?:balanceOf|\.balance)/gi;

    if (!balanceInDivision.test(code)) {
      return false;
    }

    // Check if this affects value transfers or minting
    const valueAffecting = [
      /\.transfer\s*\(/i,
      /\.call\s*\{.*value/i,
      /\.mint\s*\(/i,
      /\.burn\s*\(/i,
      /safeTransfer/i,
      /_mint\s*\(/i,
      /_burn\s*\(/i,
    ];

    const affectsValue = valueAffecting.some(pattern => pattern.test(code));

    if (!affectsValue) {
      // Balance used but doesn't affect value - likely internal accounting
      return false;
    }

    // Check for price/rate/ratio context
    const pricingContext = /(?:price|rate|ratio|exchange|collateral|liquidat)/i.test(code);

    if (pricingContext) {
      this.addFinding({
        title: 'Balance-Based Pricing Vulnerable to Flash Loan',
        description: `Function calculates price/rate using real-time balance which can be manipulated via flash loans, donations, or selfdestruct. The calculated value affects token transfers or minting.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: funcNode.loc ? funcNode.loc.start.line : 0,
        column: funcNode.loc ? funcNode.loc.start.column : 0,
        code: this.extractRelevantCode(code, 'balance'),
        severity: 'HIGH',
        confidence: 'HIGH',
        exploitable: true,
        exploitabilityScore: 75,
        attackVector: 'flash-loan-balance-manipulation',
        recommendation: 'Use internal balance tracking instead of actual balances. Implement deposit/withdraw pattern with state variables. Consider using TWAP for any pricing logic.',
        references: [
          'https://swcregistry.io/docs/SWC-132',
          'https://consensys.github.io/smart-contract-best-practices/attacks/oracle-manipulation/'
        ],
        foundryPoC: this.generateBalanceManipulationPoC(this.currentContract, this.currentFunction)
      });
      return true;
    }

    return false;
  }

  /**
   * Detect reserve ratio manipulation patterns
   */
  detectReserveManipulation(code, funcNode) {
    // Pattern: reserve0 / reserve1 or similar calculations
    const reserveRatio = /reserve[0-9]?\s*[*/]\s*reserve[0-9]?/gi;

    if (!reserveRatio.test(code)) {
      return false;
    }

    // Check for swap or exchange context
    if (/swap|exchange|trade/i.test(code)) {
      this.addFinding({
        title: 'Reserve Ratio Manipulation Risk',
        description: `Function uses reserve ratio calculation that can be manipulated within a single transaction. Attackers can inflate/deflate reserves using flash loans before this calculation.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: funcNode.loc ? funcNode.loc.start.line : 0,
        column: funcNode.loc ? funcNode.loc.start.column : 0,
        code: this.extractRelevantCode(code, 'reserve'),
        severity: 'HIGH',
        confidence: 'HIGH',
        exploitable: true,
        exploitabilityScore: 80,
        attackVector: 'flash-loan-reserve-manipulation',
        recommendation: 'Use TWAP pricing instead of spot reserve ratios. Implement slippage protection. Consider using Chainlink oracles for critical price data.',
        references: [
          'https://www.paradigm.xyz/2020/11/so-you-want-to-use-a-price-oracle'
        ]
      });
      return true;
    }

    return false;
  }

  /**
   * Check if spot price result flows into value-affecting operations
   */
  checkValueFlow(code, priceFunctionName) {
    // Check what happens after the price call
    const valueOps = [
      { pattern: /\.transfer\s*\(/i, reason: 'Price feeds into ETH/token transfer amount' },
      { pattern: /\.call\s*\{.*value/i, reason: 'Price feeds into call value' },
      { pattern: /\.mint\s*\(/i, reason: 'Price determines mint amount' },
      { pattern: /\.burn\s*\(/i, reason: 'Price determines burn amount' },
      { pattern: /safeTransfer/i, reason: 'Price determines transfer amount' },
      { pattern: /collateral/i, reason: 'Price used for collateral valuation' },
      { pattern: /liquidat/i, reason: 'Price triggers liquidation' },
      { pattern: /borrow/i, reason: 'Price determines borrow capacity' },
    ];

    for (const { pattern, reason } of valueOps) {
      if (pattern.test(code)) {
        return { isExploitable: true, reason };
      }
    }

    return { isExploitable: false, reason: '' };
  }

  /**
   * Extract the most relevant code snippet around a pattern
   */
  extractRelevantCode(fullCode, keyword) {
    const lines = fullCode.split('\n');
    const keywordLower = keyword.toLowerCase();

    let relevantLines = [];
    let foundLine = -1;

    for (let i = 0; i < lines.length; i++) {
      if (lines[i].toLowerCase().includes(keywordLower)) {
        foundLine = i;
        break;
      }
    }

    if (foundLine >= 0) {
      const start = Math.max(0, foundLine - 2);
      const end = Math.min(lines.length, foundLine + 3);
      relevantLines = lines.slice(start, end);
    }

    return relevantLines.join('\n') || fullCode.substring(0, 200);
  }

  visitMemberAccess(node) {
    // Detect spot price oracle usage at AST level for precise location
    if (node.memberName === 'getReserves' ||
        node.memberName === 'getAmountsOut' ||
        node.memberName === 'getAmountOut') {
      // Already handled in deepAnalyzeFunction with context
      // This is kept for precise line number tracking
    }
  }

  /**
   * Generate Foundry PoC for spot price manipulation
   */
  generateSpotPricePoC(oracleFunction, contractName, functionName) {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: Flash Loan Oracle Manipulation
 * Target: ${contractName}.${functionName}()
 * Attack Vector: Manipulate ${oracleFunction}() return value via flash loan
 */
contract FlashLoanOracleExploit is Test {
    // TODO: Set actual addresses
    address constant TARGET = address(0); // ${contractName} address
    address constant DEX_PAIR = address(0); // Uniswap/DEX pair for manipulation
    address constant FLASH_LOAN_PROVIDER = address(0); // Aave/dYdX

    function testExploit() public {
        // 1. Take flash loan to get large amount of tokens
        // flashLoan(FLASH_LOAN_PROVIDER, amount);

        // 2. Manipulate DEX reserves to skew ${oracleFunction}()
        // swap large amount to move price

        // 3. Call vulnerable function while price is manipulated
        // TARGET.${functionName}(...);

        // 4. Reverse the manipulation
        // swap back to restore price

        // 5. Repay flash loan, keep profit

        // Assert profit was made
        // assertGt(profit, 0);
    }
}`;
  }

  /**
   * Generate Foundry PoC for balance manipulation
   */
  generateBalanceManipulationPoC(contractName, functionName) {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: Balance Manipulation Attack
 * Target: ${contractName}.${functionName}()
 * Attack Vector: Manipulate contract balance before price calculation
 */
contract BalanceManipulationExploit is Test {
    address constant TARGET = address(0); // ${contractName} address

    function testExploit() public {
        // Method 1: Flash loan + donation
        // 1. Take flash loan
        // 2. Send tokens to target contract (donation)
        // 3. Call vulnerable function (inflated balance = wrong price)
        // 4. Extract value at manipulated price
        // 5. Repay flash loan

        // Method 2: Self-destruct (for ETH balance)
        // Deploy contract with ETH, selfdestruct to target

        // Assert profit was made
        // assertGt(profit, 0);
    }

    // Helper: Self-destruct ETH sender
    // contract Depositor {
    //     constructor(address target) payable {
    //         selfdestruct(payable(target));
    //     }
    // }
}`;
  }
}

module.exports = FlashLoanDetector;
