const BaseDetector = require('./base-detector');

/**
 * Gas Griefing and DoS Detector (Enhanced)
 * Detects patterns vulnerable to denial of service via gas manipulation
 * with improved loop bound analysis to reduce false positives.
 */
class GasGriefingDetector extends BaseDetector {
  constructor() {
    super(
      'Gas Griefing / DoS',
      'Detects patterns vulnerable to gas-based denial of service',
      'HIGH'
    );
    this.currentContract = null;
    this.currentFunction = null;
    this.currentFunctionNode = null;
    this.isInLoop = false;
    this.loopDepth = 0;
    this.currentLoopIsUnbounded = false;

    // Safe iteration limit - loops with bounds under this are considered safe
    this.SAFE_ITERATION_LIMIT = 100;
    // Warning threshold - bounded but could still be expensive
    this.WARNING_ITERATION_LIMIT = 1000;
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');

    this.traverse(ast);

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'constructor';
    this.currentFunctionNode = node;
    this.isInLoop = false;
    this.loopDepth = 0;
  }

  visitForStatement(node) {
    this.loopDepth++;
    this.isInLoop = true;

    // Analyze the loop with context awareness
    this.analyzeForLoop(node);

    // After processing children
    this.loopDepth--;
    if (this.loopDepth === 0) {
      this.isInLoop = false;
    }
  }

  visitWhileStatement(node) {
    this.loopDepth++;
    this.isInLoop = true;

    // Analyze while loop - check if it has proper bounds
    this.analyzeWhileLoop(node);

    this.loopDepth--;
    if (this.loopDepth === 0) {
      this.isInLoop = false;
    }
  }

  visitFunctionCall(node) {
    if (!node.expression) return;

    const code = this.getCodeSnippet(node.loc);

    // Check for external calls in loops (only if unbounded)
    if (this.isInLoop && this.currentLoopIsUnbounded) {
      if (code.includes('.call') || code.includes('.transfer') || code.includes('.send')) {
        this.reportExternalCallInLoop(node);
      }
    }

    // Check for push to dynamic array - only if it's user-controlled
    if (node.expression.type === 'MemberAccess' && node.expression.memberName === 'push') {
      this.checkArrayPush(node);
    }
  }

  /**
   * Analyze for loop with comprehensive bound checking
   */
  analyzeForLoop(node) {
    const code = this.getCodeSnippet(node.loc);
    const funcCode = this.currentFunctionNode ? this.getCodeSnippet(this.currentFunctionNode.loc) : code;

    // Extract loop bounds analysis
    const boundAnalysis = this.analyzeLoopBounds(node, code, funcCode);

    // Track if this loop is unbounded for nested analysis
    this.currentLoopIsUnbounded = !boundAnalysis.hasBound;

    if (boundAnalysis.hasBound) {
      // Loop has explicit bounds
      if (boundAnalysis.boundValue <= this.SAFE_ITERATION_LIMIT) {
        // Safe - small fixed bound, no report needed
        return;
      } else if (boundAnalysis.boundValue <= this.WARNING_ITERATION_LIMIT) {
        // Warning - moderate bound
        if (this.hasGasHeavyOperations(code)) {
          this.reportBoundedButExpensive(node, boundAnalysis);
        }
        return;
      }
      // Large bound - continue to check if it's problematic
    }

    // Check for dynamic array iteration
    const dynamicArrayAnalysis = this.analyzeDynamicArrayIteration(code, funcCode);

    if (dynamicArrayAnalysis.iteratesOverDynamicArray) {
      // Check if there's pagination or safe guards
      if (dynamicArrayAnalysis.hasSafeGuards) {
        // Has pagination, batching, or limits - safe
        return;
      }

      // Check if it's truly unbounded and user-controllable
      if (dynamicArrayAnalysis.isUserControllable) {
        this.reportUnboundedIteration(node, dynamicArrayAnalysis);
      }
    }

    // Check for gas-heavy operations in unbounded loops
    if (!boundAnalysis.hasBound && this.hasGasHeavyOperations(code)) {
      this.reportGasHeavyLoop(node);
    }
  }

  /**
   * Analyze while loop for proper termination bounds
   */
  analyzeWhileLoop(node) {
    const code = this.getCodeSnippet(node.loc);
    const funcCode = this.currentFunctionNode ? this.getCodeSnippet(this.currentFunctionNode.loc) : code;

    // Check for counter-based while loops (actually bounded)
    const hasCounterBound = this.hasCounterBasedBound(code);

    if (hasCounterBound) {
      // While loop with explicit counter check - analyze the bound
      const boundAnalysis = this.analyzeWhileBounds(code, funcCode);

      if (boundAnalysis.hasBound && boundAnalysis.boundValue <= this.WARNING_ITERATION_LIMIT) {
        // Bounded while loop - safe
        this.currentLoopIsUnbounded = false;
        return;
      }
    }

    // Check for state-based termination (e.g., queue processing)
    const hasStateTermination = this.hasStateBasedTermination(code);

    if (hasStateTermination) {
      // While loop processes state that will eventually terminate
      // Only flag if it has gas-heavy operations
      if (this.hasGasHeavyOperations(code)) {
        this.reportPotentiallyUnboundedWhile(node);
      }
      this.currentLoopIsUnbounded = true;
      return;
    }

    // Check for infinite loop patterns (truly dangerous)
    const hasInfinitePattern = this.hasInfiniteLoopPattern(code);

    if (hasInfinitePattern) {
      this.reportInfiniteLoop(node);
      this.currentLoopIsUnbounded = true;
      return;
    }

    // Default: flag if no clear termination condition
    this.currentLoopIsUnbounded = true;
    if (this.hasGasHeavyOperations(code)) {
      this.reportUnboundedWhileLoop(node);
    }
  }

  /**
   * Analyze loop bounds from for-loop structure
   */
  analyzeLoopBounds(node, code, funcCode) {
    const result = {
      hasBound: false,
      boundValue: Infinity,
      boundSource: 'unknown'
    };

    // Pattern 1: Explicit numeric bound (for i = 0; i < 10; i++)
    const numericBound = code.match(/[<>=]\s*(\d+)/);
    if (numericBound) {
      result.hasBound = true;
      result.boundValue = parseInt(numericBound[1]);
      result.boundSource = 'literal';
      return result;
    }

    // Pattern 2: Constant bound (for i = 0; i < MAX_ITERATIONS; i++)
    const constantPattern = /[<>=]\s*([A-Z_][A-Z0-9_]*)/;
    const constantMatch = code.match(constantPattern);
    if (constantMatch) {
      const constantName = constantMatch[1];
      // Try to find constant definition
      const constantDef = funcCode.match(new RegExp(`${constantName}\\s*=\\s*(\\d+)`));
      if (constantDef) {
        result.hasBound = true;
        result.boundValue = parseInt(constantDef[1]);
        result.boundSource = 'constant';
        return result;
      }
      // Known safe constants
      if (/^MAX_|^LIMIT_|^BATCH_SIZE/i.test(constantName)) {
        result.hasBound = true;
        result.boundValue = this.WARNING_ITERATION_LIMIT; // Assume reasonable
        result.boundSource = 'constant';
        return result;
      }
    }

    // Pattern 3: Min/Math.min bound
    if (/Math\.min|min\s*\(/i.test(code)) {
      result.hasBound = true;
      result.boundValue = this.WARNING_ITERATION_LIMIT;
      result.boundSource = 'min-function';
      return result;
    }

    // Pattern 4: Parameter with require check
    const paramBound = code.match(/[<>=]\s*(\w+)/);
    if (paramBound) {
      const boundVar = paramBound[1];
      // Check if there's a require limiting this parameter
      const requirePattern = new RegExp(`require\\s*\\([^;]*${boundVar}[^;]*[<>=]\\s*(\\d+)`);
      const requireMatch = funcCode.match(requirePattern);
      if (requireMatch) {
        result.hasBound = true;
        result.boundValue = parseInt(requireMatch[1]);
        result.boundSource = 'require-bounded';
        return result;
      }
    }

    return result;
  }

  /**
   * Analyze while loop bounds
   */
  analyzeWhileBounds(code, funcCode) {
    const result = {
      hasBound: false,
      boundValue: Infinity
    };

    // Check for counter increment patterns
    const counterPatterns = [
      /(\w+)\s*\+\+/,  // i++
      /(\w+)\s*\+=\s*1/, // i += 1
      /(\w+)\s*=\s*\1\s*\+\s*1/ // i = i + 1
    ];

    let counterVar = null;
    for (const pattern of counterPatterns) {
      const match = code.match(pattern);
      if (match) {
        counterVar = match[1];
        break;
      }
    }

    if (counterVar) {
      // Find the bound for this counter
      const boundPattern = new RegExp(`${counterVar}\\s*[<>=]+\\s*(\\d+|[A-Z_]+)`);
      const boundMatch = code.match(boundPattern);

      if (boundMatch) {
        const boundValue = parseInt(boundMatch[1]);
        if (!isNaN(boundValue)) {
          result.hasBound = true;
          result.boundValue = boundValue;
        } else {
          // It's a constant, assume bounded
          result.hasBound = true;
          result.boundValue = this.WARNING_ITERATION_LIMIT;
        }
      }
    }

    return result;
  }

  /**
   * Check for counter-based bounds in while loops
   */
  hasCounterBasedBound(code) {
    // Look for patterns like: while (i < limit) with i++ inside
    const hasComparison = /while\s*\([^)]*[<>=]/i.test(code);
    const hasIncrement = /\+\+|\+=\s*1|=\s*\w+\s*\+\s*1/i.test(code);

    return hasComparison && hasIncrement;
  }

  /**
   * Check for state-based termination
   */
  hasStateBasedTermination(code) {
    // Queue/stack processing patterns
    const statePatterns = [
      /\.length\s*>\s*0/,  // while (queue.length > 0)
      /\.pop\s*\(/,        // with pop operation
      /\.shift\s*\(/,      // with shift operation
      /isEmpty/i,          // isEmpty check
    ];

    return statePatterns.some(p => p.test(code));
  }

  /**
   * Check for infinite loop patterns
   */
  hasInfiniteLoopPattern(code) {
    // while(true), while(1), for(;;)
    return /while\s*\(\s*(true|1)\s*\)|for\s*\(\s*;\s*;\s*\)/.test(code);
  }

  /**
   * Analyze if loop iterates over dynamic, user-controllable array
   */
  analyzeDynamicArrayIteration(code, funcCode) {
    const result = {
      iteratesOverDynamicArray: false,
      arrayName: null,
      isUserControllable: false,
      hasSafeGuards: false
    };

    // Check for .length iteration
    const lengthMatch = code.match(/(\w+)\.length/);
    if (!lengthMatch) return result;

    result.iteratesOverDynamicArray = true;
    result.arrayName = lengthMatch[1];

    // Check if array is user-controllable
    const userControllablePatterns = [
      /public\s+\w+\[\]/,           // public array
      /push.*msg\.sender/,          // users can add themselves
      /push.*external/,             // external function can add
      /users|addresses|recipients/i // named like user list
    ];

    result.isUserControllable = userControllablePatterns.some(p => p.test(funcCode));

    // Check for safe guards
    const safeGuardPatterns = [
      /require.*\.length\s*[<>=]/,  // Length check in require
      /Math\.min|min\s*\(/,         // Min function for batching
      /start.*end|offset.*limit/i,  // Pagination parameters
      /batch/i,                     // Batch processing
      /MAX_|LIMIT_/,                // Named limits
    ];

    result.hasSafeGuards = safeGuardPatterns.some(p => p.test(funcCode));

    return result;
  }

  /**
   * Check if code contains gas-heavy operations
   */
  hasGasHeavyOperations(code) {
    const gasHeavyPatterns = [
      /\.transfer\s*\(/,
      /\.call\s*\{/,
      /\.call\s*\(/,
      /\.send\s*\(/,
      /\.delegatecall/,
      /delete\s+\w+\[/,  // Storage deletion
      /\w+\[\w+\]\s*=/,  // Storage write in loop
    ];

    return gasHeavyPatterns.some(p => p.test(code));
  }

  checkArrayPush(node) {
    const funcCode = this.currentFunctionNode ?
      this.getCodeSnippet(this.currentFunctionNode.loc) :
      this.sourceLines.slice(Math.max(0, node.loc.start.line - 10), node.loc.start.line + 5).join('\n');

    // Check for size limits
    const hasLimit = /require[^;]*length\s*[<]=?\s*\d+|MAX_|LIMIT_/i.test(funcCode);

    // Check if push is user-controllable
    const isUserTriggered = /external|public/i.test(funcCode) &&
                           !(/onlyOwner|onlyAdmin|onlyRole/i.test(funcCode));

    if (!hasLimit && isUserTriggered) {
      // Check if array is ever iterated
      const arrayName = this.findArrayName(node);
      const isIterated = arrayName && new RegExp(`for[^}]*${arrayName}\\.length`).test(this.sourceCode);

      if (isIterated) {
        this.reportUnboundedArrayGrowth(node, arrayName);
      }
    }
  }

  findArrayName(pushNode) {
    if (pushNode.expression && pushNode.expression.expression) {
      const expr = pushNode.expression.expression;
      if (expr.type === 'Identifier') {
        return expr.name;
      }
    }
    return null;
  }

  reportUnboundedIteration(node, analysis) {
    this.addFinding({
      title: 'Unbounded Loop Over User-Controlled Array',
      description: `Loop iterates over '${analysis.arrayName}' array which can grow without bounds. If users can add elements via external calls, gas costs could exceed block limit causing permanent DoS.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'HIGH',
      confidence: 'HIGH',
      exploitable: true,
      exploitabilityScore: 80,
      attackVector: 'gas-exhaustion-dos',
      recommendation: 'Implement pagination (start/end indices), set maximum array size, or use pull payment pattern where users withdraw individually.',
      references: [
        'https://swcregistry.io/docs/SWC-128',
        'https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/'
      ],
      foundryPoC: this.generateDoSPoC(analysis.arrayName)
    });
  }

  reportBoundedButExpensive(node, boundAnalysis) {
    this.addFinding({
      title: 'Gas-Expensive Loop',
      description: `Loop has bound of ${boundAnalysis.boundValue} iterations with gas-heavy operations. While bounded, this could still be expensive and approach gas limits.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      exploitable: false,
      exploitabilityScore: 20,
      recommendation: 'Consider reducing maximum iterations, batching operations, or using pull payment pattern for transfers.',
      references: [
        'https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/'
      ]
    });
  }

  reportGasHeavyLoop(node) {
    this.addFinding({
      title: 'Gas-Heavy Operations in Unbounded Loop',
      description: `External calls or storage operations inside a loop without explicit bounds. Each iteration costs significant gas, risking block gas limit exhaustion.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'HIGH',
      confidence: 'HIGH',
      exploitable: true,
      exploitabilityScore: 75,
      attackVector: 'gas-exhaustion-dos',
      recommendation: 'Add explicit iteration limits. Move external calls outside loops. Use pull payment pattern. Batch storage updates.',
      references: [
        'https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/'
      ]
    });
  }

  reportExternalCallInLoop(node) {
    this.addFinding({
      title: 'External Call in Unbounded Loop',
      description: `External call (.call, .transfer, .send) inside an unbounded loop. A single failing recipient can block all subsequent transfers (DoS), or gas costs could exceed block limit.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'CRITICAL',
      confidence: 'HIGH',
      exploitable: true,
      exploitabilityScore: 90,
      attackVector: 'gas-exhaustion-dos',
      recommendation: 'Use pull payment pattern (recipients withdraw individually). If push is required: add try/catch, continue on failure, and track failed transfers for retry.',
      references: [
        'https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/',
        'https://docs.openzeppelin.com/contracts/4.x/api/security#PullPayment'
      ],
      foundryPoC: this.generateExternalCallDoSPoC()
    });
  }

  reportUnboundedWhileLoop(node) {
    this.addFinding({
      title: 'Unbounded While Loop with Gas-Heavy Operations',
      description: `While loop without clear termination bounds contains operations that could exhaust gas. The loop may not terminate or could consume excessive gas.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'HIGH',
      confidence: 'MEDIUM',
      exploitable: true,
      exploitabilityScore: 65,
      recommendation: 'Add explicit iteration counter with maximum limit. Consider converting to bounded for-loop. Add gas checks (gasleft()) if processing must continue across transactions.',
      references: [
        'https://swcregistry.io/docs/SWC-128'
      ]
    });
  }

  reportPotentiallyUnboundedWhile(node) {
    this.addFinding({
      title: 'State-Processing While Loop',
      description: `While loop processes state (queue/stack pattern) with gas-heavy operations. While logically bounded by state, could still exhaust gas with large state.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      exploitable: true,
      exploitabilityScore: 40,
      recommendation: 'Add maximum iteration limit per transaction. Consider processing in batches across multiple transactions.',
      references: [
        'https://swcregistry.io/docs/SWC-128'
      ]
    });
  }

  reportInfiniteLoop(node) {
    this.addFinding({
      title: 'Potential Infinite Loop',
      description: `Loop with while(true) or for(;;) pattern detected. This will always consume all available gas unless explicitly broken.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'CRITICAL',
      confidence: 'HIGH',
      exploitable: true,
      exploitabilityScore: 95,
      attackVector: 'infinite-loop-dos',
      recommendation: 'Add explicit break conditions and maximum iteration counter. Verify all code paths lead to termination.',
      references: [
        'https://swcregistry.io/docs/SWC-128'
      ]
    });
  }

  reportUnboundedArrayGrowth(node, arrayName) {
    this.addFinding({
      title: 'Unbounded Array Growth',
      description: `Array '${arrayName || 'unknown'}' can grow without limits via user-accessible function, and is later iterated. Attackers can add elements until iteration exceeds block gas limit, causing permanent DoS.`,
      location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
      line: node.loc ? node.loc.start.line : 0,
      column: node.loc ? node.loc.start.column : 0,
      code: this.getCodeSnippet(node.loc),
      severity: 'HIGH',
      confidence: 'HIGH',
      exploitable: true,
      exploitabilityScore: 85,
      attackVector: 'unbounded-growth-dos',
      recommendation: 'Add maximum array size with require check. Use mapping with counter instead of array if iteration not needed. Implement removal mechanism.',
      references: [
        'https://swcregistry.io/docs/SWC-128'
      ],
      foundryPoC: this.generateArrayGrowthPoC(arrayName)
    });
  }

  generateDoSPoC(arrayName) {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: Gas Exhaustion DoS via Unbounded Loop
 * Target array: ${arrayName || 'users'}
 */
contract GasExhaustionExploit is Test {
    address constant TARGET = address(0);

    function testExploit() public {
        // Step 1: Grow the array to exceed gas limits
        // Each push adds an element that will be iterated
        for (uint i = 0; i < 10000; i++) {
            // TARGET.addUser(address(uint160(i)));
        }

        // Step 2: Attempt to call function that iterates
        // This should fail with out-of-gas
        // vm.expectRevert();
        // TARGET.processAllUsers();

        // The contract is now permanently DoS'd for this function
    }
}`;
  }

  generateExternalCallDoSPoC() {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: DoS via Malicious Recipient in Loop
 */
contract MaliciousRecipient {
    // Consume all gas or revert on receive
    receive() external payable {
        // Option 1: Infinite loop
        while(true) {}

        // Option 2: Simply revert
        // revert("DoS");
    }
}

contract ExternalCallLoopExploit is Test {
    function testExploit() public {
        // Deploy malicious recipient
        MaliciousRecipient malicious = new MaliciousRecipient();

        // Add malicious address to the payment queue
        // TARGET.addRecipient(address(malicious));

        // Now any call to distribute payments will fail
        // Either consuming all gas or reverting

        // vm.expectRevert();
        // TARGET.distributePayments();
    }
}`;
  }

  generateArrayGrowthPoC(arrayName) {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: Permanent DoS via Array Growth
 * Target array: ${arrayName || 'array'}
 */
contract ArrayGrowthExploit is Test {
    address constant TARGET = address(0);

    function testExploit() public {
        uint256 initialGas = gasleft();

        // Keep adding elements until we approach gas limits
        // Each element makes future iterations more expensive

        uint256 elementsAdded = 0;
        while (gasleft() > 100000) {
            // TARGET.push(someValue);
            elementsAdded++;

            if (elementsAdded > 50000) break; // Safety limit for test
        }

        console.log("Elements added:", elementsAdded);

        // Now try to call function that iterates over the array
        // vm.expectRevert(); // Should fail with out-of-gas
        // TARGET.processArray();
    }
}`;
  }
}

module.exports = GasGriefingDetector;
