const BaseDetector = require('./base-detector');

/**
 * ERC4626 Vault Inflation Attack Detector
 * Detects first depositor attacks, donation attacks, and share manipulation
 *
 * Attack vectors detected:
 * 1. First Depositor Attack - Attacker deposits 1 wei, donates tokens, inflating share price
 * 2. Donation Attack - Direct token transfer to vault manipulates share calculations
 * 3. Share Inflation - Division rounding exploits in share/asset calculations
 * 4. Empty Vault Manipulation - Special case handling when totalSupply = 0
 */
class VaultInflationDetector extends BaseDetector {
  constructor() {
    super(
      'Vault Inflation Attack',
      'Detects ERC4626 vault inflation, first depositor, and donation attacks',
      'CRITICAL'
    );
    this.currentContract = null;
    this.currentFunction = null;
    this.isVaultContract = false;
    this.hasVirtualShares = false;
    this.hasVirtualAssets = false;
    this.hasMinDeposit = false;
    this.depositFunction = null;
    this.withdrawFunction = null;
    this.shareCalculations = [];
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;
    this.shareCalculations = [];

    // First pass: determine if this is a vault contract
    this.traverse(ast);

    // Second pass: analyze vault-specific vulnerabilities
    if (this.isVaultContract) {
      this.analyzeVaultVulnerabilities();
    }

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
    this.isVaultContract = false;
    this.hasVirtualShares = false;
    this.hasVirtualAssets = false;
    this.hasMinDeposit = false;

    // Check if contract inherits from ERC4626 or implements vault pattern
    const contractCode = this.getCodeSnippet(node.loc);

    // ERC4626 inheritance patterns
    const vaultPatterns = [
      /ERC4626/i,
      /Vault/i,
      /is\s+.*Vault/i,
      /totalAssets/i,
      /convertToShares/i,
      /convertToAssets/i,
    ];

    this.isVaultContract = vaultPatterns.some(p => p.test(contractCode));

    // Check for protection mechanisms
    this.hasVirtualShares = /virtualShares|_decimalsOffset|VIRTUAL_SHARES/i.test(contractCode);
    this.hasVirtualAssets = /virtualAssets|VIRTUAL_ASSETS/i.test(contractCode);
    this.hasMinDeposit = /minDeposit|MIN_DEPOSIT|minimumDeposit/i.test(contractCode);
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'constructor';

    if (!this.isVaultContract) return;

    const funcName = (node.name || '').toLowerCase();
    const funcCode = node.body ? this.getCodeSnippet(node.loc) : '';

    // Track deposit/withdraw functions
    if (funcName.includes('deposit') || funcName === 'mint') {
      this.depositFunction = { node, code: funcCode };
    }
    if (funcName.includes('withdraw') || funcName === 'redeem') {
      this.withdrawFunction = { node, code: funcCode };
    }

    // Track share calculation functions
    if (funcName.includes('converttoshares') || funcName.includes('converttoassets') ||
        funcName.includes('previewdeposit') || funcName.includes('previewmint') ||
        funcName.includes('previewwithdraw') || funcName.includes('previewredeem')) {
      this.analyzeShareCalculation(node, funcCode);
    }
  }

  visitBinaryOperation(node) {
    if (!this.isVaultContract) return;

    // Track division operations in share calculations
    if (node.operator === '/') {
      const code = this.getCodeSnippet(node.loc);
      const leftCode = this.getCodeSnippet(node.left?.loc);
      const rightCode = this.getCodeSnippet(node.right?.loc);

      // Check for share/asset division patterns
      if (this.isShareRelatedDivision(code, leftCode, rightCode)) {
        this.shareCalculations.push({
          loc: node.loc,
          code: code,
          type: 'division',
          left: leftCode,
          right: rightCode
        });
      }
    }
  }

  analyzeShareCalculation(node, funcCode) {
    // Check for vulnerable patterns in share calculations

    // Pattern 1: Division without rounding protection
    if (funcCode.includes('/') && !funcCode.includes('mulDiv')) {
      this.shareCalculations.push({
        function: node.name,
        code: funcCode,
        type: 'manual_division',
        vulnerable: !this.hasRoundingProtection(funcCode)
      });
    }

    // Pattern 2: No check for zero totalSupply
    if (!funcCode.includes('totalSupply() == 0') &&
        !funcCode.includes('totalSupply() > 0') &&
        !funcCode.includes('supply == 0') &&
        !funcCode.includes('supply > 0')) {
      this.shareCalculations.push({
        function: node.name,
        code: funcCode,
        type: 'no_zero_check',
        vulnerable: true
      });
    }
  }

  analyzeVaultVulnerabilities() {
    // Check 1: First Depositor Attack vulnerability
    if (!this.hasVirtualShares && !this.hasVirtualAssets && !this.hasMinDeposit) {
      this.reportFirstDepositorVulnerability();
    }

    // Check 2: Donation Attack vulnerability
    if (!this.hasDonationProtection()) {
      this.reportDonationAttackVulnerability();
    }

    // Check 3: Share calculation precision issues
    this.shareCalculations.forEach(calc => {
      if (calc.vulnerable) {
        if (calc.type === 'no_zero_check') {
          this.reportZeroSupplyVulnerability(calc);
        } else if (calc.type === 'manual_division') {
          this.reportPrecisionLossVulnerability(calc);
        }
      }
    });

    // Check 4: Empty vault edge cases
    if (!this.hasEmptyVaultProtection()) {
      this.reportEmptyVaultVulnerability();
    }
  }

  hasRoundingProtection(code) {
    // Check for mulDiv or similar rounding-safe operations
    const roundingPatterns = [
      /mulDiv/i,
      /FullMath/i,
      /roundUp|roundDown/i,
      /Math\.ceil|Math\.floor/i,
      /\+ 1\s*\)|1 \+/,  // Adding 1 for rounding
    ];

    return roundingPatterns.some(p => p.test(code));
  }

  hasDonationProtection() {
    // Check for mechanisms that prevent donation attacks
    const protectionPatterns = [
      /virtualAssets/i,
      /virtualShares/i,
      /\_decimalsOffset/i,
      /balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)\s*-/,  // Tracking internal balance
      /internalBalance/i,
      /lastBalance/i,
      /storedBalance/i,
    ];

    return protectionPatterns.some(p => p.test(this.sourceCode));
  }

  hasEmptyVaultProtection() {
    // Check for empty vault handling
    if (!this.depositFunction) return true;

    const depositCode = this.depositFunction.code;

    const protectionPatterns = [
      /require\s*\(\s*totalSupply\(\)\s*[>!]/i,
      /if\s*\(\s*totalSupply\(\)\s*==\s*0/i,
      /supply\s*==\s*0\s*\?/i,  // Ternary check
      /firstDeposit/i,
      /initialDeposit/i,
      /deadShares/i,  // Burn initial shares pattern
    ];

    return protectionPatterns.some(p => p.test(depositCode));
  }

  isShareRelatedDivision(code, left, right) {
    const shareTerms = ['share', 'asset', 'supply', 'balance', 'totalassets', 'totalsupply'];
    const combined = `${code} ${left} ${right}`.toLowerCase();
    return shareTerms.some(term => combined.includes(term));
  }

  reportFirstDepositorVulnerability() {
    this.addFinding({
      title: 'First Depositor / Vault Inflation Attack',
      description: `Contract '${this.currentContract}' implements ERC4626 vault pattern without protection against first depositor attack. An attacker can:
1. Deposit 1 wei as the first depositor to get 1 share
2. Donate (directly transfer) large amount of tokens to vault
3. This inflates share price so next depositor's deposit rounds down to 0 shares
4. Attacker withdraws, taking victim's deposit

This attack has caused >$100M in losses across DeFi protocols.`,
      location: `Contract: ${this.currentContract}`,
      line: 1,
      column: 0,
      code: this.sourceLines.slice(0, 10).join('\n'),
      severity: 'CRITICAL',
      confidence: 'HIGH',
      exploitable: true,
      exploitabilityScore: 95,
      attackVector: 'first-depositor-attack',
      recommendation: `Implement one or more of these mitigations:
1. Virtual shares/assets offset (OpenZeppelin ERC4626 pattern): Add virtual offset to calculations
2. Minimum deposit amount: Require minimum first deposit (e.g., 1000 tokens)
3. Dead shares: Burn small amount of shares on first deposit to address(1)
4. Internal balance tracking: Track deposited amount separately from balance

Example (OpenZeppelin pattern):
function _decimalsOffset() internal pure override returns (uint8) {
    return 3; // Adds virtual 1000 shares/assets offset
}`,
      references: [
        'https://blog.openzeppelin.com/a-]novel-defense-against-erc4626-inflation-attacks',
        'https://docs.openzeppelin.com/contracts/4.x/erc4626',
        'https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3706'
      ],
      foundryPoC: this.generateFirstDepositorPoC()
    });
  }

  reportDonationAttackVulnerability() {
    this.addFinding({
      title: 'Donation Attack Vulnerability',
      description: `Contract '${this.currentContract}' uses balanceOf(address(this)) or similar for share calculations without tracking internal deposits. An attacker can directly transfer tokens to manipulate share prices.

Attack scenario:
1. Attacker monitors mempool for large deposits
2. Front-runs with direct token transfer (donation) to vault
3. Victim's deposit receives fewer shares due to inflated totalAssets
4. Attacker back-runs by withdrawing, extracting donated value`,
      location: `Contract: ${this.currentContract}`,
      line: 1,
      column: 0,
      code: this.sourceLines.slice(0, 10).join('\n'),
      severity: 'HIGH',
      confidence: 'MEDIUM',
      exploitable: true,
      exploitabilityScore: 75,
      attackVector: 'donation-attack',
      recommendation: `Track internal balance separately from actual balance:
1. Use internal accounting (internalBalance) for share calculations
2. Or use virtual offset that dominates small donations
3. Or add sweep function to handle unexpected balance increases

Example:
uint256 internal _totalDeposited;
function totalAssets() public view returns (uint256) {
    return _totalDeposited; // Not balanceOf(address(this))
}`,
      references: [
        'https://mixbytes.io/blog/overview-of-the-inflation-attack'
      ]
    });
  }

  reportZeroSupplyVulnerability(calc) {
    this.addFinding({
      title: 'Missing Zero Supply Check in Share Calculation',
      description: `Function '${calc.function}' performs share calculations without checking for totalSupply == 0. This can lead to division by zero or unexpected behavior for first depositor.`,
      location: `Contract: ${this.currentContract}, Function: ${calc.function}`,
      line: calc.loc?.start?.line || 0,
      column: calc.loc?.start?.column || 0,
      code: calc.code?.substring(0, 200),
      severity: 'HIGH',
      confidence: 'HIGH',
      exploitable: true,
      exploitabilityScore: 70,
      attackVector: 'share-calculation-edge-case',
      recommendation: `Add explicit check for zero supply:
if (totalSupply() == 0) {
    return assets; // 1:1 ratio for first deposit
}
return assets.mulDiv(totalSupply(), totalAssets(), rounding);`
    });
  }

  reportPrecisionLossVulnerability(calc) {
    this.addFinding({
      title: 'Precision Loss in Share Calculation',
      description: `Function '${calc.function}' uses manual division for share calculations without rounding protection. Integer division truncates, allowing attackers to exploit rounding in their favor.`,
      location: `Contract: ${this.currentContract}, Function: ${calc.function}`,
      line: calc.loc?.start?.line || 0,
      column: calc.loc?.start?.column || 0,
      code: calc.code?.substring(0, 200),
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      exploitable: true,
      exploitabilityScore: 50,
      attackVector: 'rounding-exploit',
      recommendation: `Use mulDiv with explicit rounding direction:
// For deposits (round down - favor vault)
shares = assets.mulDiv(totalSupply(), totalAssets(), Math.Rounding.Down);
// For withdrawals (round down - favor vault)
assets = shares.mulDiv(totalAssets(), totalSupply(), Math.Rounding.Down);`
    });
  }

  reportEmptyVaultVulnerability() {
    this.addFinding({
      title: 'Empty Vault Edge Case Not Handled',
      description: `Deposit function does not properly handle the empty vault case (totalSupply == 0). First depositor can manipulate initial share price.`,
      location: `Contract: ${this.currentContract}`,
      line: this.depositFunction?.node?.loc?.start?.line || 0,
      column: 0,
      code: this.depositFunction?.code?.substring(0, 200) || '',
      severity: 'HIGH',
      confidence: 'MEDIUM',
      exploitable: true,
      exploitabilityScore: 70,
      attackVector: 'empty-vault-manipulation',
      recommendation: `Handle first deposit specially:
1. Burn dead shares: mint shares to address(1) on first deposit
2. Enforce minimum deposit for first depositor
3. Use virtual offset (OpenZeppelin pattern)`
    });
  }

  generateFirstDepositorPoC() {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * Proof of Concept: First Depositor / Vault Inflation Attack
 * This demonstrates stealing funds from the second depositor
 */
contract FirstDepositorExploit is Test {
    // Target vault and underlying token
    // IERC4626 vault;
    // IERC20 token;

    address attacker = address(0x1);
    address victim = address(0x2);

    function testFirstDepositorAttack() public {
        uint256 victimDeposit = 10000e18; // Victim wants to deposit 10,000 tokens

        // Step 1: Attacker front-runs, deposits minimum amount
        vm.startPrank(attacker);
        // vault.deposit(1, attacker); // Deposit 1 wei, get 1 share
        vm.stopPrank();

        // Step 2: Attacker donates tokens directly (not through deposit)
        vm.prank(attacker);
        // token.transfer(address(vault), victimDeposit - 1);

        // Now: totalAssets = victimDeposit, totalShares = 1
        // Share price = victimDeposit / 1

        // Step 3: Victim deposits
        vm.prank(victim);
        // uint256 victimShares = vault.deposit(victimDeposit, victim);

        // Victim receives: victimDeposit * 1 / victimDeposit = 1 share (rounds down to 0 or 1)

        // Step 4: Attacker withdraws
        vm.prank(attacker);
        // uint256 attackerReceived = vault.redeem(1, attacker, attacker);

        // Attacker gets ~50% of victim's deposit
        // console.log("Victim deposited:", victimDeposit);
        // console.log("Victim shares:", victimShares);
        // console.log("Attacker profit:", attackerReceived - 1);
    }
}`;
  }
}

module.exports = VaultInflationDetector;
