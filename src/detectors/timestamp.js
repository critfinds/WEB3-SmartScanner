const BaseDetector = require('./base-detector');

class TimestampDependenceDetector extends BaseDetector {
  constructor() {
    super(
      'Timestamp Dependence',
      'Detects dangerous reliance on block.timestamp or block.number',
      'MEDIUM'
    );
  }

  visitFunctionDefinition(node) {
    if (!node.body) return;

    const code = this.getCodeSnippet(node.body.loc);
    const functionName = node.name || '';

    // Check for block.timestamp usage
    if (code.includes('block.timestamp') || code.includes('now')) {
      this.checkTimestampUsage(node, code, functionName);
    }

    // Check for block.number usage
    if (code.includes('block.number')) {
      this.checkBlockNumberUsage(node, code, functionName);
    }
  }

  checkTimestampUsage(node, code, functionName) {
    // Check if timestamp is used in critical logic
    if (this.hasTimestampInCriticalLogic(code)) {
      this.addFinding({
        title: 'Timestamp Manipulation Risk',
        description: `Function '${functionName}' uses block.timestamp in critical logic. Miners can manipulate timestamps within ~15 seconds, potentially affecting contract behavior.`,
        location: `Function: ${functionName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        recommendation: 'Avoid using block.timestamp for critical logic like random number generation or precise timing. Use block.number for relative time or oracle-based time if precision is critical.',
        references: [
          'https://swcregistry.io/docs/SWC-116',
          'https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/timestamp-dependence/'
        ]
      });
    }

    // Check for random number generation using timestamp
    if (this.usesTimestampForRandomness(code)) {
      this.addFinding({
        title: 'Weak Randomness from Timestamp',
        description: `Function '${functionName}' uses block.timestamp for randomness. This is highly predictable and can be manipulated by miners.`,
        location: `Function: ${functionName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        recommendation: 'Never use block.timestamp, block.number, or blockhash for randomness. Use Chainlink VRF or commit-reveal schemes for unpredictable randomness.',
        references: [
          'https://docs.chain.link/vrf/v2/introduction',
          'https://swcregistry.io/docs/SWC-120'
        ]
      });
    }

    // Check for auction/deadline logic
    if (this.hasDeadlineLogic(code)) {
      this.addFinding({
        title: 'Timestamp Used in Deadline Logic',
        description: `Function '${functionName}' uses block.timestamp for deadlines or time-based conditions. Miners can manipulate this within bounds.`,
        location: `Function: ${functionName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        recommendation: 'If using timestamps for deadlines, ensure the logic is not exploitable within the ~15 second manipulation window. Consider using block.number instead.',
        references: [
          'https://swcregistry.io/docs/SWC-116'
        ]
      });
    }
  }

  checkBlockNumberUsage(node, code, functionName) {
    // Check if block.number is used for randomness
    if (code.includes('keccak256') && code.includes('block.number')) {
      this.addFinding({
        title: 'Weak Randomness from Block Number',
        description: `Function '${functionName}' uses block.number for randomness generation. This is predictable and can be manipulated.`,
        location: `Function: ${functionName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        recommendation: 'Use proper randomness source like Chainlink VRF instead of block properties.',
        references: [
          'https://docs.chain.link/vrf/v2/introduction'
        ]
      });
    }

    // Check for blockhash usage
    if (code.includes('blockhash')) {
      this.addFinding({
        title: 'Blockhash for Randomness',
        description: `Function '${functionName}' uses blockhash() for randomness. This is vulnerable to manipulation and only works for recent blocks.`,
        location: `Function: ${functionName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        recommendation: 'Blockhash can only access last 256 blocks and is manipulable by miners. Use Chainlink VRF for secure randomness.',
        references: [
          'https://swcregistry.io/docs/SWC-120',
          'https://docs.chain.link/vrf/v2/introduction'
        ]
      });
    }
  }

  hasTimestampInCriticalLogic(code) {
    // Check if timestamp is used in conditionals, assignments, or calculations
    const criticalPatterns = [
      /if\s*\([^)]*block\.timestamp/,
      /if\s*\([^)]*now/,
      /require\([^)]*block\.timestamp/,
      /require\([^)]*now/,
      /=.*block\.timestamp/,
      /=.*now\b/,
      /block\.timestamp\s*[+\-*/%]/,
      /now\s*[+\-*/%]/
    ];

    return criticalPatterns.some(pattern => pattern.test(code));
  }

  usesTimestampForRandomness(code) {
    // Check if timestamp is used with keccak256 or similar hashing
    const randomPatterns = [
      /keccak256\([^)]*block\.timestamp/,
      /keccak256\([^)]*now/,
      /sha256\([^)]*block\.timestamp/,
      /sha256\([^)]*now/,
      /random.*block\.timestamp/i,
      /random.*now/i
    ];

    return randomPatterns.some(pattern => pattern.test(code));
  }

  hasDeadlineLogic(code) {
    const deadlinePatterns = [
      /deadline/i,
      /expires?/i,
      /endTime/i,
      /startTime/i,
      /timelock/i,
      /block\.timestamp\s*[<>]=?\s*\w+Time/,
      /now\s*[<>]=?\s*\w+Time/
    ];

    return deadlinePatterns.some(pattern => pattern.test(code));
  }
}

module.exports = TimestampDependenceDetector;
