const BaseDetector = require('./base-detector');

/**
 * Read-Only Reentrancy Detector
 * Detects vulnerabilities where view functions return stale data during reentrancy
 *
 * This is the attack vector used in the Curve Finance exploit and similar attacks.
 * View functions may return incorrect values when called during the execution of
 * another function that modifies state but hasn't completed yet.
 *
 * Attack vectors detected:
 * 1. View functions reading state that's modified by non-view functions with external calls
 * 2. Price/rate calculations that can be manipulated via reentrancy
 * 3. Virtual price functions in LP tokens
 * 4. Share/asset calculations during mint/burn
 */
class ReadOnlyReentrancyDetector extends BaseDetector {
  constructor() {
    super(
      'Read-Only Reentrancy',
      'Detects view functions vulnerable to read-only reentrancy attacks',
      'CRITICAL'
    );
    this.currentContract = null;
    this.viewFunctions = new Map();
    this.stateModifyingFunctions = new Map();
    this.externalCallFunctions = [];
    this.sharedStateAccess = new Map();
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;
    this.viewFunctions.clear();
    this.stateModifyingFunctions.clear();
    this.externalCallFunctions = [];
    this.sharedStateAccess.clear();

    if (!cfg) {
      return this.findings;
    }

    // First pass: categorize functions
    this.categorizeFunctions();

    // Second pass: find cross-function vulnerabilities
    this.findReadOnlyReentrancy();

    // Third pass: check for specific vulnerable patterns
    this.checkVulnerablePatterns();

    return this.findings;
  }

  categorizeFunctions() {
    for (const [funcKey, funcInfo] of this.cfg.functions) {
      const funcCode = funcInfo.node?.body ? this.getCodeSnippet(funcInfo.node.loc) : '';

      // Categorize view/pure functions
      if (funcInfo.stateMutability === 'view' || funcInfo.stateMutability === 'pure') {
        this.viewFunctions.set(funcKey, {
          info: funcInfo,
          code: funcCode,
          readsState: funcInfo.stateReads.map(r => r.variable),
          isPriceFunction: this.isPriceRelatedFunction(funcInfo.name, funcCode)
        });
      }

      // Categorize state-modifying functions with external calls
      if (funcInfo.externalCalls.length > 0 && funcInfo.stateWrites.length > 0) {
        this.stateModifyingFunctions.set(funcKey, {
          info: funcInfo,
          code: funcCode,
          externalCalls: funcInfo.externalCalls,
          writesState: funcInfo.stateWrites.map(w => w.variable),
          hasReentrancyGuard: this.hasReentrancyGuard(funcInfo)
        });

        this.externalCallFunctions.push({
          key: funcKey,
          info: funcInfo,
          code: funcCode
        });
      }
    }
  }

  findReadOnlyReentrancy() {
    // For each state-modifying function with external calls
    for (const [modFuncKey, modFunc] of this.stateModifyingFunctions) {
      // Skip if has reentrancy guard (but note: guard doesn't help view functions!)
      // Actually, regular reentrancy guards DO NOT prevent read-only reentrancy

      // Find view functions that read state this function writes
      for (const [viewFuncKey, viewFunc] of this.viewFunctions) {
        // Check for shared state variables
        const sharedState = modFunc.writesState.filter(writeVar =>
          viewFunc.readsState.some(readVar =>
            readVar === writeVar || this.variablesOverlap(readVar, writeVar)
          )
        );

        if (sharedState.length > 0) {
          // Check if there's a window for exploitation
          const vulnerability = this.analyzeReentrancyWindow(modFunc, viewFunc, sharedState);

          if (vulnerability.isVulnerable) {
            this.reportReadOnlyReentrancy(modFunc, viewFunc, sharedState, vulnerability);
          }
        }
      }
    }
  }

  analyzeReentrancyWindow(modFunc, viewFunc, sharedState) {
    // Check if external call happens BEFORE state update (classic pattern)
    // OR if state is partially updated when external call happens

    const funcCode = modFunc.code;

    // Find positions of external calls and state writes
    let externalCallLine = 0;
    let lastStateWriteLine = 0;

    for (const call of modFunc.info.externalCalls) {
      if (call.loc?.start?.line > externalCallLine) {
        externalCallLine = call.loc.start.line;
      }
    }

    for (const write of modFunc.info.stateWrites) {
      if (write.loc?.start?.line > lastStateWriteLine) {
        lastStateWriteLine = write.loc.start.line;
      }
    }

    // Vulnerable if: external call happens before last state write
    // OR if view function reads derived value (like price) that depends on multiple state vars
    const callBeforeWrite = externalCallLine < lastStateWriteLine;
    const viewReadsDerivedValue = viewFunc.isPriceFunction;

    return {
      isVulnerable: callBeforeWrite || viewReadsDerivedValue,
      callBeforeWrite,
      viewReadsDerivedValue,
      externalCallLine,
      lastStateWriteLine
    };
  }

  checkVulnerablePatterns() {
    // Check for specific known vulnerable patterns

    // Pattern 1: Curve-style virtual price in LP tokens
    this.checkCurveVirtualPrice();

    // Pattern 2: ERC4626-style share price
    this.checkSharePriceVulnerability();

    // Pattern 3: Balancer-style rate providers
    this.checkRateProviderVulnerability();

    // Pattern 4: Lending protocol exchange rates
    this.checkExchangeRateVulnerability();
  }

  checkCurveVirtualPrice() {
    // Check for get_virtual_price or similar patterns
    const curvePatterns = [
      /get_virtual_price/i,
      /virtualPrice/i,
      /getVirtualPrice/i,
    ];

    for (const [funcKey, viewFunc] of this.viewFunctions) {
      const funcName = viewFunc.info.name || '';
      const funcCode = viewFunc.code;

      if (curvePatterns.some(p => p.test(funcName) || p.test(funcCode))) {
        // Check if there are functions that modify the underlying state
        const hasVulnerableModifier = this.hasStateModifierWithCallback(viewFunc.readsState);

        if (hasVulnerableModifier) {
          this.addFinding({
            title: 'Curve-Style Virtual Price Read-Only Reentrancy',
            description: `Function '${funcName}' returns a virtual price that can be manipulated during reentrancy. An attacker can:
1. Call a function that modifies reserves/balances with a callback (e.g., remove_liquidity with ETH)
2. During the callback, call this view function which returns stale price
3. Use the manipulated price in another protocol (lending, DEX, etc.)

This attack vector was used in the Curve Finance exploit causing >$50M in losses.`,
            location: `Contract: ${this.currentContract}, Function: ${funcName}`,
            line: viewFunc.info.node?.loc?.start?.line || 0,
            column: 0,
            code: funcCode.substring(0, 200),
            severity: 'CRITICAL',
            confidence: 'HIGH',
            exploitable: true,
            exploitabilityScore: 95,
            attackVector: 'read-only-reentrancy',
            recommendation: `Implement reentrancy lock that also blocks view functions:
1. Use a reentrancy guard that reverts in view functions
2. Or use Vyper's @nonreentrant decorator which protects all functions
3. For integrators: Don't trust virtual_price during callbacks

Example view function protection:
modifier nonReentrantView() {
    require(!_locked, "Reentrancy");
    _;
}`,
            references: [
              'https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/',
              'https://blog.openzeppelin.com/read-only-reentrancy-is-real'
            ],
            foundryPoC: this.generateReadOnlyReentrancyPoC(funcName)
          });
        }
      }
    }
  }

  checkSharePriceVulnerability() {
    // ERC4626 and similar share-based systems
    const sharePricePatterns = [
      /convertToAssets/i,
      /convertToShares/i,
      /pricePerShare/i,
      /sharePrice/i,
      /exchangeRate/i,
      /getRate/i,
    ];

    for (const [funcKey, viewFunc] of this.viewFunctions) {
      const funcName = viewFunc.info.name || '';

      if (sharePricePatterns.some(p => p.test(funcName))) {
        // Check if mint/burn functions have external calls
        const hasMintBurnWithCallback = this.hasMintBurnWithCallback();

        if (hasMintBurnWithCallback) {
          this.addFinding({
            title: 'Share Price Vulnerable to Read-Only Reentrancy',
            description: `Function '${funcName}' calculates share/asset conversion which may return incorrect values during mint/burn operations that include callbacks (e.g., safeTransferFrom with callback).

During these callbacks, totalSupply or totalAssets may be in an intermediate state, allowing manipulation of the apparent share price.`,
            location: `Contract: ${this.currentContract}, Function: ${funcName}`,
            line: viewFunc.info.node?.loc?.start?.line || 0,
            column: 0,
            code: viewFunc.code.substring(0, 200),
            severity: 'HIGH',
            confidence: 'MEDIUM',
            exploitable: true,
            exploitabilityScore: 70,
            attackVector: 'read-only-reentrancy',
            recommendation: `1. Ensure state updates complete before any external calls (CEI pattern)
2. Use reentrancy guards that also protect view functions
3. Consider caching prices at the start of transactions`
          });
        }
      }
    }
  }

  checkRateProviderVulnerability() {
    // Balancer-style rate providers
    const ratePatterns = [
      /getRate\s*\(/i,
      /IRateProvider/i,
      /rateProvider/i,
    ];

    if (ratePatterns.some(p => p.test(this.sourceCode))) {
      // Check for implementation
      for (const [funcKey, viewFunc] of this.viewFunctions) {
        if (/getRate/i.test(viewFunc.info.name || '')) {
          this.addFinding({
            title: 'Rate Provider Potential Read-Only Reentrancy',
            description: `Contract implements rate provider pattern (getRate). If the underlying rate calculation depends on state that can be manipulated during callbacks, this creates a read-only reentrancy vector.

Protocols integrating this rate provider may use stale rates during their operations.`,
            location: `Contract: ${this.currentContract}, Function: ${viewFunc.info.name}`,
            line: viewFunc.info.node?.loc?.start?.line || 0,
            column: 0,
            code: viewFunc.code.substring(0, 200),
            severity: 'MEDIUM',
            confidence: 'MEDIUM',
            exploitable: true,
            exploitabilityScore: 55,
            attackVector: 'read-only-reentrancy',
            recommendation: `Ensure rate calculations are not affected by reentrancy:
1. Cache rate at start of state-modifying functions
2. Use Balancer's rate provider update mechanism
3. Document reentrancy behavior for integrators`
          });
        }
      }
    }
  }

  checkExchangeRateVulnerability() {
    // Compound-style exchange rates
    const exchangePatterns = [
      /exchangeRateStored/i,
      /exchangeRateCurrent/i,
      /underlying.*balance|balance.*underlying/i,
    ];

    for (const [funcKey, viewFunc] of this.viewFunctions) {
      const funcName = viewFunc.info.name || '';
      const funcCode = viewFunc.code;

      if (exchangePatterns.some(p => p.test(funcName) || p.test(funcCode))) {
        if (this.hasStateModifierWithCallback(viewFunc.readsState)) {
          this.addFinding({
            title: 'Exchange Rate Read-Only Reentrancy Risk',
            description: `Function '${funcName}' calculates exchange rate which may be vulnerable during reentrant calls. Lending protocols and other integrators may receive manipulated rates.`,
            location: `Contract: ${this.currentContract}, Function: ${funcName}`,
            line: viewFunc.info.node?.loc?.start?.line || 0,
            column: 0,
            code: funcCode.substring(0, 200),
            severity: 'HIGH',
            confidence: 'MEDIUM',
            exploitable: true,
            exploitabilityScore: 65,
            attackVector: 'read-only-reentrancy',
            recommendation: `Use non-reentrant exchange rate calculation or document the risk for integrators.`
          });
        }
      }
    }
  }

  // Helper methods

  isPriceRelatedFunction(funcName, funcCode) {
    if (!funcName) return false;

    const pricePatterns = [
      /price/i, /rate/i, /value/i, /convert/i, /exchange/i,
      /virtual/i, /balance/i, /supply/i, /reserves/i
    ];

    return pricePatterns.some(p => p.test(funcName) || p.test(funcCode));
  }

  hasReentrancyGuard(funcInfo) {
    if (!funcInfo.modifiers) return false;

    const guardPatterns = [
      /nonReentrant/i, /lock/i, /mutex/i, /noReentrancy/i
    ];

    return funcInfo.modifiers.some(mod =>
      guardPatterns.some(p => p.test(mod))
    );
  }

  variablesOverlap(var1, var2) {
    // Check if variables might refer to same storage
    // e.g., "balances" and "balances[msg.sender]"
    const base1 = var1.split('[')[0];
    const base2 = var2.split('[')[0];
    return base1 === base2;
  }

  hasStateModifierWithCallback(stateVars) {
    // Check if any function modifies these state vars and has external calls
    for (const [funcKey, modFunc] of this.stateModifyingFunctions) {
      const modifiesSharedState = stateVars.some(sv =>
        modFunc.writesState.some(ws => this.variablesOverlap(sv, ws))
      );

      if (modifiesSharedState && modFunc.externalCalls.length > 0) {
        return true;
      }
    }
    return false;
  }

  hasMintBurnWithCallback() {
    // Check for mint/burn functions with potential callbacks
    for (const func of this.externalCallFunctions) {
      const funcName = (func.info.name || '').toLowerCase();
      if (/mint|burn|deposit|withdraw|redeem/i.test(funcName)) {
        // Check if external call could be a callback (ERC20/721 hooks, etc.)
        const hasCallback = func.code.includes('safeTransfer') ||
                           func.code.includes('_beforeTokenTransfer') ||
                           func.code.includes('_afterTokenTransfer') ||
                           func.code.includes('.call');
        if (hasCallback) return true;
      }
    }
    return false;
  }

  reportReadOnlyReentrancy(modFunc, viewFunc, sharedState, vulnerability) {
    const modFuncName = modFunc.info.name || 'unknown';
    const viewFuncName = viewFunc.info.name || 'unknown';

    this.addFinding({
      title: 'Read-Only Reentrancy Vulnerability',
      description: `View function '${viewFuncName}' reads state (${sharedState.join(', ')}) that is modified by '${modFuncName}' which has external calls.

During the external call in '${modFuncName}', an attacker can call '${viewFuncName}' and receive stale data. This can be exploited if other protocols use this view function for price/rate calculations.

${vulnerability.callBeforeWrite ? 'External call happens BEFORE state update - classic reentrancy window.' : ''}
${vulnerability.viewReadsDerivedValue ? 'View function calculates derived value (price/rate) - high impact if manipulated.' : ''}`,
      location: `Contract: ${this.currentContract}`,
      line: viewFunc.info.node?.loc?.start?.line || 0,
      column: 0,
      code: viewFunc.code.substring(0, 200),
      severity: vulnerability.viewReadsDerivedValue ? 'CRITICAL' : 'HIGH',
      confidence: 'HIGH',
      exploitable: true,
      exploitabilityScore: vulnerability.viewReadsDerivedValue ? 85 : 70,
      attackVector: 'read-only-reentrancy',
      recommendation: `1. Apply CEI (Checks-Effects-Interactions) pattern: update all state BEFORE external calls
2. Use reentrancy guard that also reverts in view functions:
   modifier nonReentrantView() {
       require(!_locked, "ReentrancyGuard: reentrant call");
       _;
   }
3. For price functions, consider caching price at transaction start
4. Document for integrators that view functions may return stale data during callbacks`,
      references: [
        'https://blog.openzeppelin.com/read-only-reentrancy-is-real',
        'https://chainsecurity.com/heartbreaks-curve-lp-oracles/'
      ]
    });
  }

  generateReadOnlyReentrancyPoC(funcName) {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: Read-Only Reentrancy Attack
 * Exploits stale ${funcName} during callback
 */
contract ReadOnlyReentrancyExploit is Test {
    // ITarget target;
    // IIntegrator integrator; // Protocol that uses target's view function

    function testExploit() public {
        // Step 1: Call function that triggers callback (e.g., remove_liquidity)
        // This will call our receive() or fallback() during execution
        // target.remove_liquidity{value: 1 ether}(...);
    }

    receive() external payable {
        // Step 2: During callback, the state is inconsistent
        // View function returns manipulated value
        // uint256 manipulatedPrice = target.${funcName}();

        // Step 3: Use manipulated price in another protocol
        // e.g., borrow against inflated collateral value
        // integrator.borrow(manipulatedPrice * myCollateral / 1e18);

        // Step 4: After this callback returns, target's state is updated
        // but we already exploited the stale price
    }
}`;
  }
}

module.exports = ReadOnlyReentrancyDetector;
