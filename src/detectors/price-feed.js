const BaseDetector = require('./base-detector');

class PriceFeedManipulationDetector extends BaseDetector {
  constructor() {
    super(
      'Price Feed Manipulation',
      'Detects vulnerabilities related to price oracle manipulation and unsafe price feeds',
      'CRITICAL'
    );
  }

  visitFunctionDefinition(node) {
    if (!node.body) return;

    const code = this.getCodeSnippet(node.body.loc);
    const functionName = node.name || '';

    // Check for single DEX as price source
    this.checkSingleDexPriceSource(node, code, functionName);

    // Check for spot price usage
    this.checkSpotPriceUsage(node, code, functionName);

    // Check for missing oracle validation
    this.checkOracleValidation(node, code, functionName);

    // Check for TWAP implementation issues
    this.checkTWAPImplementation(node, code, functionName);
  }

  checkSingleDexPriceSource(node, code, functionName) {
    // Check for Uniswap/Sushiswap direct price queries
    const singleDexPatterns = [
      /getReserves\(\)/,
      /getAmountOut\(/,
      /getAmountsOut\(/,
      /quote\(/,
      /UniswapV2Pair/,
      /SushiswapPair/
    ];

    const usesDexPrice = singleDexPatterns.some(pattern => pattern.test(code));

    if (usesDexPrice && !this.hasMultipleOracleSources(code)) {
      this.addFinding({
        title: 'Single DEX as Price Oracle',
        description: `Function '${functionName}' relies on a single DEX for price information. This is vulnerable to flash loan attacks and price manipulation.`,
        location: `Function: ${functionName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        recommendation: 'Use multiple price sources or decentralized oracles like Chainlink. Implement price bounds and sanity checks. Consider using TWAP (Time-Weighted Average Price).',
        references: [
          'https://docs.chain.link/data-feeds',
          'https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles/',
          'https://docs.uniswap.org/concepts/protocol/oracle'
        ]
      });
    }
  }

  checkSpotPriceUsage(node, code, functionName) {
    // Check if using spot price without TWAP
    const spotPricePatterns = [
      /reserve0\s*\*\s*reserve1/,
      /reserve1\s*\/\s*reserve0/,
      /reserve0\s*\/\s*reserve1/,
      /balanceOf.*\*.*balanceOf/
    ];

    if (spotPricePatterns.some(pattern => pattern.test(code)) &&
        !code.includes('TWAP') &&
        !code.includes('timeWeighted')) {

      this.addFinding({
        title: 'Spot Price Usage Without TWAP',
        description: `Function '${functionName}' uses spot price which can be manipulated within a single transaction using flash loans.`,
        location: `Function: ${functionName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        recommendation: 'Use Time-Weighted Average Price (TWAP) to prevent single-block manipulation. Uniswap v2/v3 oracles provide TWAP functionality.',
        references: [
          'https://docs.uniswap.org/concepts/protocol/oracle',
          'https://blog.euler.finance/prices-can-be-wrong-35f2eb3c11b'
        ]
      });
    }
  }

  checkOracleValidation(node, code, functionName) {
    // Check for Chainlink oracle usage without proper validation
    if (code.includes('latestRoundData') || code.includes('getPrice')) {
      const hasTimestampCheck = code.includes('updatedAt') || code.includes('timestamp');
      const hasPriceValidation = code.includes('require(') && code.includes('price');
      const hasRoundValidation = code.includes('answeredInRound') || code.includes('roundId');

      if (!hasTimestampCheck || !hasPriceValidation) {
        this.addFinding({
          title: 'Insufficient Oracle Data Validation',
          description: `Function '${functionName}' uses price oracle data without sufficient validation. Stale or invalid data can lead to incorrect pricing.`,
          location: `Function: ${functionName}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: this.getCodeSnippet(node.loc),
          recommendation: 'Validate oracle data: check updatedAt timestamp, verify answeredInRound >= roundId, ensure price > 0, and implement staleness threshold.',
          references: [
            'https://docs.chain.link/data-feeds/historical-data',
            'https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles/'
          ]
        });
      }

      if (!hasRoundValidation) {
        this.addFinding({
          title: 'Missing Oracle Round Validation',
          description: `Function '${functionName}' does not validate oracle round data. This can lead to using stale or incomplete price updates.`,
          location: `Function: ${functionName}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: this.getCodeSnippet(node.loc),
          recommendation: 'Check: require(answeredInRound >= roundId, "Stale price data");',
          references: [
            'https://docs.chain.link/data-feeds/historical-data'
          ]
        });
      }
    }
  }

  checkTWAPImplementation(node, code, functionName) {
    // Check for manual TWAP implementation issues
    if (code.includes('observe(') || code.includes('observations')) {
      // Check for insufficient observation window
      const hasObservationValidation = code.includes('require(') &&
                                       (code.includes('secondsAgo') || code.includes('period'));

      if (!hasObservationValidation) {
        this.addFinding({
          title: 'TWAP Implementation Without Period Validation',
          description: `Function '${functionName}' implements TWAP but may not validate observation period. Short periods can still be manipulated.`,
          location: `Function: ${functionName}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: this.getCodeSnippet(node.loc),
          recommendation: 'Ensure TWAP observation period is sufficiently long (>= 10-30 minutes) to prevent manipulation. Validate observation timestamps.',
          references: [
            'https://docs.uniswap.org/concepts/protocol/oracle'
          ]
        });
      }
    }
  }

  hasMultipleOracleSources(code) {
    // Check if code appears to aggregate multiple price sources
    const aggregationPatterns = [
      /median\(/i,
      /average\(/i,
      /mean\(/i,
      /\.add\(.*\.add\(/,
      /price1.*price2/,
      /oracle1.*oracle2/,
      /Chainlink.*Uniswap/i,
      /Uniswap.*Chainlink/i
    ];

    return aggregationPatterns.some(pattern => pattern.test(code));
  }
}

module.exports = PriceFeedManipulationDetector;
