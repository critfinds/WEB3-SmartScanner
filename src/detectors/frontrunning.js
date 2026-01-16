const BaseDetector = require('./base-detector');

/**
 * Front-Running Vulnerability Detector (Enhanced)
 * Detects patterns susceptible to MEV and front-running attacks
 * with improved context awareness to reduce false positives.
 */
class FrontRunningDetector extends BaseDetector {
  constructor() {
    super(
      'Front-Running Vulnerability',
      'Detects patterns vulnerable to MEV and front-running attacks',
      'HIGH'
    );
    this.currentContract = null;
    this.currentFunction = null;
    this.currentFunctionNode = null;
    this.contractCode = '';
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
    this.contractCode = this.getCodeSnippet(node.loc);
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'constructor';
    this.currentFunctionNode = node;

    // Skip internal/private functions (not front-runnable by external actors)
    if (node.visibility === 'private' || node.visibility === 'internal') {
      return;
    }

    // Check function parameters for sensitive patterns
    this.checkSwapFunction(node);

    // Check function body for front-running patterns
    if (node.body) {
      this.checkFunctionBody(node);
    }
  }

  /**
   * Check swap functions for proper slippage protection
   */
  checkSwapFunction(node) {
    const funcName = (node.name || '').toLowerCase();
    const funcCode = node.body ? this.getCodeSnippet(node.loc) : '';

    // Check if this is a swap-like function
    const isSwapFunction = funcName.includes('swap') ||
                          funcName.includes('exchange') ||
                          funcName.includes('trade') ||
                          funcName.includes('buy') ||
                          funcName.includes('sell');

    if (!isSwapFunction) return;

    // Check for slippage protection in parameters
    const hasSlippageProtection = this.checkSlippageProtection(node, funcCode);

    if (!hasSlippageProtection.hasProtection) {
      // Check if it calls an external swap with protection
      const delegatesToProtected = this.delegatesToProtectedSwap(funcCode);

      if (!delegatesToProtected) {
        this.reportMissingSlippageProtection(node, hasSlippageProtection);
      }
    }
  }

  /**
   * Check for slippage protection mechanisms
   */
  checkSlippageProtection(node, funcCode) {
    const result = {
      hasProtection: false,
      hasMinAmount: false,
      hasDeadline: false,
      hasSlippageTolerance: false
    };

    if (!node.parameters) return result;

    // Check parameters
    for (const param of node.parameters) {
      const paramName = (param.name || '').toLowerCase();

      if (paramName.includes('min') && (paramName.includes('amount') || paramName.includes('out') || paramName.includes('return'))) {
        result.hasMinAmount = true;
      }
      if (paramName.includes('deadline') || paramName.includes('expiry') || paramName.includes('validuntil')) {
        result.hasDeadline = true;
      }
      if (paramName.includes('slippage') || paramName.includes('tolerance')) {
        result.hasSlippageTolerance = true;
      }
    }

    // Check function body for slippage checks
    if (funcCode) {
      // require(amountOut >= minAmount) patterns
      if (/require\s*\([^)]*>=\s*\w*(min|Min)/i.test(funcCode)) {
        result.hasMinAmount = true;
      }
      // Deadline checks
      if (/require\s*\([^)]*block\.timestamp\s*[<>=]/i.test(funcCode) ||
          /require\s*\([^)]*deadline/i.test(funcCode)) {
        result.hasDeadline = true;
      }
    }

    result.hasProtection = result.hasMinAmount || result.hasSlippageTolerance;

    return result;
  }

  /**
   * Check if function delegates to a protected swap (e.g., Uniswap Router)
   */
  delegatesToProtectedSwap(funcCode) {
    // Known protected swap patterns
    const protectedPatterns = [
      /swapExactTokensForTokens\s*\([^)]*,\s*\w+\s*,/,  // Uniswap V2 with minAmountOut
      /swapExactETHForTokens\s*\{/,
      /exactInputSingle\s*\(/,  // Uniswap V3
      /exactInput\s*\(/,
      /\.swap\s*\([^)]*amountOutMin/i,
    ];

    return protectedPatterns.some(p => p.test(funcCode));
  }

  checkFunctionBody(node) {
    const funcCode = this.getCodeSnippet(node.loc);
    const funcName = (node.name || '').toLowerCase();

    // 1. Check for weak commit-reveal patterns
    this.checkCommitReveal(node, funcCode, funcName);

    // 2. Check for auction patterns
    this.checkAuctionPattern(node, funcCode, funcName);

    // 3. Check for ERC20 approve (only in specific risky contexts)
    this.checkApprovePattern(node, funcCode);

    // 4. Check for signature replay issues
    this.checkSignatureReplay(node, funcCode);
  }

  /**
   * Check for weak commit-reveal implementations
   */
  checkCommitReveal(node, funcCode, funcName) {
    // Must be a reveal function with hash verification
    const isRevealFunction = funcName.includes('reveal') ||
                            (funcCode.includes('keccak256') && /commit|reveal|secret/i.test(funcCode));

    if (!isRevealFunction) return;

    // Check for proper block delay
    const hasBlockDelay = /block\.number\s*[->]\s*commit.*block/i.test(funcCode) ||
                         /commitBlock.*\+\s*\d+/i.test(funcCode) ||
                         /require.*block\.number\s*>=?\s*\w+\s*\+\s*\d+/i.test(funcCode);

    // Check for timestamp delay (less secure but still a protection)
    const hasTimestampDelay = /block\.timestamp\s*>=?\s*\w+\s*\+\s*\d+/i.test(funcCode);

    // Check for known secure patterns
    const hasSecurePattern = /revealDeadline|commitPeriod|REVEAL_DELAY/i.test(funcCode);

    if (!hasBlockDelay && !hasTimestampDelay && !hasSecurePattern) {
      this.reportWeakCommitReveal(node);
    }
  }

  /**
   * Check for vulnerable auction patterns
   */
  checkAuctionPattern(node, funcCode, funcName) {
    const isAuctionFunction = funcName.includes('bid') ||
                             funcName.includes('auction') ||
                             funcName.includes('offer');

    if (!isAuctionFunction) return;

    // Skip if it's just checking bids (view function)
    if (node.stateMutability === 'view' || node.stateMutability === 'pure') {
      return;
    }

    // Check for sealed/commit patterns
    const hasSealedBid = /commit|sealed|hash|blind/i.test(funcCode);

    // Check for private mempool usage indicators
    const hasPrivateSubmission = /flashbots|private|confidential/i.test(funcCode);

    if (!hasSealedBid && !hasPrivateSubmission) {
      // Check if bid amount is a direct parameter (front-runnable)
      const hasBidAmountParam = node.parameters &&
        node.parameters.some(p => /amount|value|bid/i.test(p.name || ''));

      if (hasBidAmountParam || /msg\.value/.test(funcCode)) {
        this.reportVisibleBidding(node);
      }
    }
  }

  /**
   * Check for ERC20 approve front-running (only flag risky patterns)
   */
  checkApprovePattern(node, funcCode) {
    // Only check if function contains approve
    if (!funcCode.includes('.approve(')) return;

    // Check for safe patterns that mitigate the issue

    // Pattern 1: Uses increaseAllowance/decreaseAllowance instead
    if (/increaseAllowance|decreaseAllowance/i.test(this.contractCode)) {
      // Contract uses safe allowance patterns
      return;
    }

    // Pattern 2: Sets to 0 first, then to new value
    const setsToZeroFirst = /\.approve\s*\([^,]+,\s*0\s*\)/i.test(funcCode) &&
                           /\.approve\s*\([^,]+,\s*[^0]/i.test(funcCode);
    if (setsToZeroFirst) {
      return;
    }

    // Pattern 3: Uses SafeERC20
    if (/safeApprove|safeIncreaseAllowance|forceApprove/i.test(funcCode)) {
      return;
    }

    // Pattern 4: Initial approval (setting from 0)
    // If the function is named like "initialize" or happens in constructor, it's likely safe
    if (/constructor|initialize|init|setup/i.test(this.currentFunction)) {
      return;
    }

    // Pattern 5: Approval to trusted addresses only (routers, etc)
    if (/ROUTER|UNISWAP|SUSHISWAP|PANCAKE/i.test(funcCode)) {
      // Approving to known routers - common safe pattern
      return;
    }

    // Only flag if this looks like user-facing allowance change
    const funcName = this.currentFunction.toLowerCase();
    const isUserFacing = /approve|allowance|permit/i.test(funcName) ||
                        node.visibility === 'external' ||
                        node.visibility === 'public';

    if (isUserFacing) {
      this.reportApprovalFrontRunning(node, funcCode);
    }
  }

  /**
   * Check for signature replay vulnerabilities
   */
  checkSignatureReplay(node, funcCode) {
    // Check for signature verification
    const hasSignatureVerification = /ecrecover|ECDSA\.recover|SignatureChecker/i.test(funcCode);

    if (!hasSignatureVerification) return;

    // Check for replay protection
    const replayProtection = {
      hasNonce: /nonce/i.test(funcCode),
      hasDeadline: /deadline|expir|validUntil/i.test(funcCode),
      hasChainId: /chainId|chainid|block\.chainid/i.test(funcCode),
      marksUsed: /used\[|usedNonces|usedSignatures|invalidate/i.test(funcCode),
      hasEIP712: /DOMAIN_SEPARATOR|_domainSeparator|EIP712/i.test(funcCode)
    };

    const protectionCount = Object.values(replayProtection).filter(v => v).length;

    // EIP712 typically includes chain ID and proper domain
    if (replayProtection.hasEIP712) {
      // Still check for nonce/deadline even with EIP712
      if (!replayProtection.hasNonce && !replayProtection.marksUsed) {
        this.reportSignatureReplayMissingNonce(node);
      }
      return;
    }

    // Need at least nonce OR marking as used, plus deadline/chainId
    if (!replayProtection.hasNonce && !replayProtection.marksUsed) {
      this.reportSignatureReplay(node, replayProtection);
    } else if (!replayProtection.hasDeadline && !replayProtection.hasChainId) {
      // Has nonce but missing other protections
      this.reportSignatureReplayWeak(node, replayProtection);
    }
  }

  reportMissingSlippageProtection(node, analysis) {
    const missingParts = [];
    if (!analysis.hasMinAmount && !analysis.hasSlippageTolerance) {
      missingParts.push('minimum output amount');
    }
    if (!analysis.hasDeadline) {
      missingParts.push('deadline');
    }

    this.addFinding({
      title: 'Missing Slippage Protection in Swap',
      description: `Function '${this.currentFunction}' performs token swaps without ${missingParts.join(' or ')}. Transactions can be sandwiched by MEV bots, resulting in users receiving fewer tokens than expected.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'HIGH',
      confidence: 'HIGH',
      exploitable: true,
      exploitabilityScore: 85,
      attackVector: 'sandwich-attack',
      recommendation: `Add 'minAmountOut' parameter and require that output >= minAmountOut. Add 'deadline' parameter and require block.timestamp <= deadline. Consider using a DEX aggregator with built-in MEV protection.`,
      references: [
        'https://docs.uniswap.org/contracts/v2/guides/smart-contract-integration/trading-from-a-smart-contract',
        'https://www.paradigm.xyz/2020/08/ethereum-is-a-dark-forest'
      ],
      foundryPoC: this.generateSandwichPoC()
    });
  }

  reportWeakCommitReveal(node) {
    this.addFinding({
      title: 'Weak Commit-Reveal Pattern',
      description: `Commit-reveal implementation without sufficient block delay. Attackers watching the mempool can front-run reveal transactions in the same block by paying higher gas.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'HIGH',
      confidence: 'MEDIUM',
      exploitable: true,
      exploitabilityScore: 70,
      attackVector: 'commit-reveal-frontrun',
      recommendation: 'Require minimum block delay (e.g., 2+ blocks) between commit and reveal. Store commitBlock and require block.number >= commitBlock + DELAY. Consider using Flashbots Protect for private submission.',
      references: [
        'https://swcregistry.io/docs/SWC-114'
      ]
    });
  }

  reportVisibleBidding(node) {
    this.addFinding({
      title: 'Visible Bid Amount - Front-Running Risk',
      description: `Auction bid amount is visible in mempool before execution. Competitors can see bids and front-run with higher amounts, or miners can reorder transactions for profit.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      exploitable: true,
      exploitabilityScore: 60,
      attackVector: 'auction-frontrun',
      recommendation: 'Implement sealed-bid auction: (1) Commit phase: users submit hash(bid, salt), (2) Reveal phase: users reveal actual bid after commit deadline. Alternatively, use private transaction submission via Flashbots.',
      references: [
        'https://ethereum.org/en/developers/docs/mev/'
      ]
    });
  }

  reportApprovalFrontRunning(node, funcCode) {
    this.addFinding({
      title: 'ERC20 Approve Race Condition',
      description: `Direct use of approve() when changing non-zero allowances creates a race condition. A malicious spender can front-run the approve transaction to use both old and new allowances.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.extractApproveCode(funcCode),
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      exploitable: true,
      exploitabilityScore: 45,
      attackVector: 'approve-race-condition',
      recommendation: 'Use increaseAllowance()/decreaseAllowance() from OpenZeppelin, or set allowance to 0 first with require(currentAllowance == 0 || newAllowance == 0). Consider using permit() for gasless approvals.',
      references: [
        'https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#ERC20-increaseAllowance-address-uint256-'
      ]
    });
  }

  reportSignatureReplay(node, protection) {
    this.addFinding({
      title: 'Signature Replay Vulnerability',
      description: `Signature verification without proper replay protection. Signed messages can be replayed multiple times (missing nonce) or across chains (missing chainId).`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'CRITICAL',
      confidence: 'HIGH',
      exploitable: true,
      exploitabilityScore: 90,
      attackVector: 'signature-replay',
      recommendation: 'Implement EIP-712 typed data signing. Include: (1) nonce that increments per-signer, (2) deadline/expiry timestamp, (3) chainId from block.chainid. Track used signatures/nonces in mapping.',
      references: [
        'https://swcregistry.io/docs/SWC-121',
        'https://eips.ethereum.org/EIPS/eip-712'
      ],
      foundryPoC: this.generateSignatureReplayPoC()
    });
  }

  reportSignatureReplayMissingNonce(node) {
    this.addFinding({
      title: 'Signature Missing Nonce/Usage Tracking',
      description: `EIP-712 signature implementation without nonce or usage tracking. While EIP-712 provides domain separation, signatures can still be replayed if not invalidated after use.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'HIGH',
      confidence: 'MEDIUM',
      exploitable: true,
      exploitabilityScore: 70,
      recommendation: 'Add incrementing nonce per-signer OR track used signature hashes in mapping. Include nonce in the signed struct.',
      references: [
        'https://eips.ethereum.org/EIPS/eip-712'
      ]
    });
  }

  reportSignatureReplayWeak(node, protection) {
    const missing = [];
    if (!protection.hasDeadline) missing.push('deadline');
    if (!protection.hasChainId) missing.push('chainId');

    this.addFinding({
      title: 'Weak Signature Replay Protection',
      description: `Signature has nonce but missing ${missing.join(' and ')}. Signatures may be held indefinitely or replayed on other chains.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      exploitable: true,
      exploitabilityScore: 50,
      recommendation: `Add ${missing.join(' and ')} to the signed message. Use block.chainid for cross-chain protection.`,
      references: [
        'https://eips.ethereum.org/EIPS/eip-712'
      ]
    });
  }

  extractApproveCode(funcCode) {
    // Extract just the approve-related lines
    const lines = funcCode.split('\n');
    const approveLines = lines.filter(l => /\.approve\s*\(/.test(l));
    return approveLines.join('\n') || funcCode.substring(0, 150);
  }

  generateSandwichPoC() {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: Sandwich Attack on Unprotected Swap
 * Demonstrates how MEV bots profit from missing slippage protection
 */
contract SandwichAttackExploit is Test {
    address constant TARGET = address(0);  // Vulnerable contract
    address constant DEX = address(0);     // DEX being used

    function testSandwichAttack() public {
        // Attacker monitors mempool for unprotected swaps

        // Step 1: FRONTRUN - Buy tokens before victim
        // This increases the price
        // DEX.swap(ETH_AMOUNT, 0); // No minOut needed for attacker

        // Step 2: Victim's transaction executes at worse price
        // (simulated - in reality this is the pending tx)

        // Step 3: BACKRUN - Sell tokens after victim
        // Attacker profits from price increase caused by victim
        // DEX.swap(TOKENS_BOUGHT, 0);

        // Profit = tokens received in step 3 - ETH spent in step 1
        // Victim receives fewer tokens due to price manipulation
    }
}`;
  }

  generateSignatureReplayPoC() {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: Signature Replay Attack
 * Demonstrates replaying a valid signature multiple times
 */
contract SignatureReplayExploit is Test {
    address constant TARGET = address(0);

    function testSignatureReplay() public {
        // Assume we have a valid signature for some action
        bytes memory signature; // = captured from previous transaction

        // First use - legitimate
        // TARGET.executeWithSignature(data, signature);

        // Replay 1 - should fail but succeeds without nonce
        // TARGET.executeWithSignature(data, signature);

        // Replay 2 - continues to succeed
        // TARGET.executeWithSignature(data, signature);

        // Attacker can replay indefinitely until signature is manually invalidated
    }

    function testCrossChainReplay() public {
        // On Mainnet, user signs transaction
        bytes memory signature; // = signed on mainnet

        // Without chainId in signature, same signature works on:
        // - Polygon fork
        // vm.chainId(137);
        // TARGET.executeWithSignature(data, signature); // Works!

        // - Arbitrum fork
        // vm.chainId(42161);
        // TARGET.executeWithSignature(data, signature); // Works!
    }
}`;
  }
}

module.exports = FrontRunningDetector;
