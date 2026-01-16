const BaseDetector = require('./base-detector');

/**
 * Cross-Contract Reentrancy Detector
 * Detects complex reentrancy attacks involving multiple contracts
 * 
 * Detects:
 * - Reentrancy across multiple contracts in same transaction
 * - State changes in one contract affecting another
 * - External calls that can trigger state changes in related contracts
 * - Missing reentrancy guards in cross-contract interactions
 * - Reentrancy via delegatecall patterns
 * - Reentrancy in multi-step protocols
 */
class CrossContractReentrancyDetector extends BaseDetector {
  constructor() {
    super(
      'Cross-Contract Reentrancy',
      'Detects reentrancy attacks involving multiple contracts and complex state interactions',
      'CRITICAL'
    );
    this.currentContract = null;
    this.externalCalls = [];
    this.stateChanges = [];
    this.contractInteractions = new Map(); // contract -> [functions called]
    this.cfg = null;
    this.dataFlow = null;
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

    // Post-traversal analysis
    this.analyzeCrossContractReentrancy();

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
    this.externalCalls = [];
    this.stateChanges = [];
    this.contractInteractions = new Map();
  }

  visitFunctionDefinition(node) {
    const funcName = node.name || '';
    const funcCode = this.getCodeSnippet(node.loc);
    
    // Skip private/internal functions (not directly exploitable)
    if (node.visibility === 'private' || node.visibility === 'internal') {
      return;
    }

    // Reset per-function tracking
    const functionExternalCalls = [];
    const functionStateChanges = [];
    const functionInteractions = new Set();

    // Analyze function body - use both AST and code analysis
    this.analyzeFunctionBody(node, functionExternalCalls, functionStateChanges, functionInteractions);
    
    // Also do direct AST traversal for interface calls
    if (node.body && node.body.statements) {
      this.analyzeFunctionBodyAST(node.body.statements, functionExternalCalls, functionStateChanges, functionInteractions);
    }

    // Store for cross-contract analysis
    if (functionExternalCalls.length > 0 || functionStateChanges.length > 0) {
      this.externalCalls.push({
        function: funcName,
        calls: functionExternalCalls,
        stateChanges: functionStateChanges,
        interactions: Array.from(functionInteractions),
        node: node
      });
    }
  }
  
  /**
   * Direct AST analysis for interface calls
   */
  analyzeFunctionBodyAST(statements, externalCalls, stateChanges, interactions) {
    for (let i = 0; i < statements.length; i++) {
      const stmt = statements[i];
      
      // Check for interface calls: contractA.withdraw() pattern
      if (stmt.type === 'ExpressionStatement' && stmt.expression) {
        const expr = stmt.expression;
        if (expr.type === 'FunctionCall' && expr.expression && expr.expression.type === 'MemberAccess') {
          const memberAccess = expr.expression;
          if (memberAccess.expression && memberAccess.expression.type === 'Identifier') {
            const varName = memberAccess.expression.name;
            // Check if it's a contract variable (not a built-in)
            if (!['msg', 'tx', 'block', 'this', 'address', 'abi', 'bytes', 'string'].includes(varName.toLowerCase())) {
              // This is an interface call
              if (!externalCalls.some(c => c.index === i)) {
                const stmtCode = this.getCodeSnippet(stmt.loc);
                externalCalls.push({
                  type: 'external',
                  target: varName,
                  statement: stmt,
                  code: stmtCode || `${varName}.${memberAccess.memberName}()`,
                  index: i
                });
                interactions.add(varName);
              }
            }
          }
        }
      }
      
      // Check for state changes: balances[user] = value
      if (stmt.type === 'ExpressionStatement' && stmt.expression && stmt.expression.type === 'Assignment') {
        const assignment = stmt.expression;
        if (assignment.left) {
          // Check if left side is a mapping access or state variable
          const leftCode = this.getCodeSnippet(assignment.left.loc);
          if (leftCode && (leftCode.includes('balances[') || leftCode.includes('['))) {
            if (!stateChanges.some(s => s.index === i)) {
              stateChanges.push({
                type: 'balance',
                statement: stmt,
                code: this.getCodeSnippet(stmt.loc),
                index: i
              });
            }
          }
        }
      }
    }
  }

  /**
   * Analyze function body for external calls and state changes
   */
  analyzeFunctionBody(node, externalCalls, stateChanges, interactions) {
    if (!node.body || !node.body.statements) return;

    const statements = node.body.statements;
    let externalCallBeforeStateUpdate = false;
    let stateUpdateAfterExternalCall = false;

    for (let i = 0; i < statements.length; i++) {
      const stmt = statements[i];
      let stmtCode = this.getCodeSnippet(stmt.loc);
      
      // If code snippet is too short, try to get more context from surrounding lines
      if (stmtCode.length < 10 && stmt.loc) {
        const lineNum = stmt.loc.start.line;
        if (lineNum > 0 && lineNum <= this.sourceLines.length) {
          stmtCode = this.sourceLines[lineNum - 1] || stmtCode;
        }
      }
      
      const stmtCodeLower = stmtCode.toLowerCase();

      // Detect external calls
      if (this.isExternalCall(stmt, stmtCode)) {
        const callTarget = this.getCallTarget(stmtCode);
        externalCalls.push({
          type: this.getCallType(stmtCode),
          target: callTarget,
          statement: stmt,
          code: stmtCode,
          index: i
        });

        // Track which contract is being called
        if (callTarget) {
          interactions.add(callTarget);
        } else {
          // Even if we can't extract the target, mark as external call
          interactions.add('external contract');
        }

        externalCallBeforeStateUpdate = true;
      }
      
      // Also check AST structure directly for interface calls (e.g., contractA.withdraw())
      // This is a more reliable way to detect interface calls
      if (stmt.type === 'ExpressionStatement' && stmt.expression) {
        const expr = stmt.expression;
        if (expr.type === 'FunctionCall' && expr.expression) {
          // Check if it's a member access (variable.function())
          if (expr.expression.type === 'MemberAccess') {
            const memberAccess = expr.expression;
            // Check if the base is an identifier (contract variable)
            if (memberAccess.expression && memberAccess.expression.type === 'Identifier') {
              const varName = memberAccess.expression.name;
              // Check if it's a contract variable (not a built-in)
              if (!['msg', 'tx', 'block', 'this', 'address', 'abi', 'bytes', 'string'].includes(varName.toLowerCase())) {
                // This is an interface call - add it if not already added
                if (!externalCalls.some(c => c.index === i)) {
                  externalCalls.push({
                    type: 'external',
                    target: varName,
                    statement: stmt,
                    code: stmtCode,
                    index: i
                  });
                  interactions.add(varName);
                  externalCallBeforeStateUpdate = true;
                }
              }
            }
          }
        }
      }

      // Detect state changes
      if (this.isStateChange(stmt, stmtCode)) {
        stateChanges.push({
          type: this.getStateChangeType(stmtCode),
          statement: stmt,
          code: stmtCode,
          index: i
        });

        // If we had an external call before, this is a reentrancy pattern
        if (externalCallBeforeStateUpdate) {
          stateUpdateAfterExternalCall = true;
        }
      }
    }

    // Check for cross-contract reentrancy pattern
    // Report if there's at least one external call and state change after it
    if (externalCalls.length > 0 && stateChanges.length > 0) {
      // Check if any state change happens after an external call
      const hasStateAfterCall = stateChanges.some(stateChange => {
        return externalCalls.some(call => stateChange.index > call.index);
      });

      if (hasStateAfterCall) {
        this.checkCrossContractReentrancy(
          node,
          externalCalls,
          stateChanges,
          interactions
        );
      }
    }
  }

  /**
   * Check for cross-contract reentrancy vulnerabilities
   */
  checkCrossContractReentrancy(node, externalCalls, stateChanges, interactions) {
    const funcName = node.name || '';
    const funcCode = this.getCodeSnippet(node.loc);

    // Check if function has reentrancy guard
    const hasReentrancyGuard = this.hasReentrancyGuard(funcCode, node);

    // Check for cross-contract patterns
    // Report if there's at least one external call and state update after it
    if (externalCalls.length > 0 && stateChanges.length > 0) {
      // Check if state is updated after external call
      const hasStateAfterCall = stateChanges.some(stateChange => {
        return externalCalls.some(call => stateChange.index > call.index);
      });

      if (hasStateAfterCall && !hasReentrancyGuard) {
        // Check if there are multiple contracts or just one
        const contractList = interactions.size > 0 ? Array.from(interactions).join(', ') : 'external contract(s)';
        const isMultiContract = interactions.size > 1;
        
        this.addFinding({
          title: isMultiContract ? 'Cross-Contract Reentrancy Vulnerability' : 'Reentrancy Vulnerability (External Call Before State Update)',
          description: `Function '${funcName}' makes external calls to ${contractList} before updating state. An attacker can exploit this by having the called contract call back into this function while state is still inconsistent.`,
          location: `Contract: ${this.currentContract}, Function: ${funcName}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: this.getCodeSnippet(node.loc),
          severity: 'CRITICAL',
          confidence: 'HIGH',
          exploitable: true,
          exploitabilityScore: 90,
          attackVector: 'cross-contract-reentrancy',
          recommendation: 'Apply reentrancy guard (nonReentrant modifier) or use Checks-Effects-Interactions pattern. Update all state before making external calls. Consider using internal functions for state updates.',
          references: [
            'https://swcregistry.io/docs/SWC-107',
            'https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/',
            'https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard'
          ],
          foundryPoC: this.generateCrossContractReentrancyPoC(this.currentContract, funcName, Array.from(interactions))
        });
      }
    }

    // Check for delegatecall reentrancy
    const hasDelegatecall = externalCalls.some(call => call.type === 'delegatecall');
    if (hasDelegatecall && !hasReentrancyGuard) {
      this.addFinding({
        title: 'Delegatecall Reentrancy Vulnerability',
        description: `Function '${funcName}' uses delegatecall which can be exploited for reentrancy. The called contract can call back into this contract with elevated privileges.`,
        location: `Contract: ${this.currentContract}, Function: ${funcName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        severity: 'CRITICAL',
        confidence: 'HIGH',
        exploitable: true,
        exploitabilityScore: 95,
        attackVector: 'delegatecall-reentrancy',
        recommendation: 'Never use delegatecall with user-controlled addresses. If delegatecall is necessary, apply strict reentrancy guards and validate the target contract.',
        references: [
          'https://swcregistry.io/docs/SWC-112',
          'https://swcregistry.io/docs/SWC-107'
        ],
        foundryPoC: this.generateDelegatecallReentrancyPoC(this.currentContract, funcName)
      });
    }

    // Check for state dependency across contracts
    if (this.hasStateDependency(externalCalls, stateChanges)) {
      if (!hasReentrancyGuard) {
        this.addFinding({
          title: 'State-Dependent Cross-Contract Reentrancy',
          description: `Function '${funcName}' reads state from one contract and writes to another, creating a reentrancy vector. An attacker can manipulate the state between the read and write.`,
          location: `Contract: ${this.currentContract}, Function: ${funcName}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: this.getCodeSnippet(node.loc),
          severity: 'CRITICAL',
          confidence: 'MEDIUM',
          exploitable: true,
          exploitabilityScore: 85,
          attackVector: 'state-dependent-reentrancy',
          recommendation: 'Cache state values before external calls. Update all state before making external calls. Use internal functions to separate state updates from external interactions.',
          references: [
            'https://swcregistry.io/docs/SWC-107',
            'https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/'
          ]
        });
      }
    }
  }

  /**
   * Check if statement is an external call
   */
  isExternalCall(stmt, code) {
    const codeLower = code.toLowerCase();
    
    // External call patterns
    const callPatterns = [
      /\.call\s*\(/i,
      /\.delegatecall\s*\(/i,
      /\.send\s*\(/i,
      /\.transfer\s*\(/i,
      /\.callcode\s*\(/i,
      /external\s+contract/i,
      /interface\s+\w+\s*\(/i
    ];

    // Check for call patterns in code first (most reliable)
    if (callPatterns.some(pattern => pattern.test(code))) {
      return true;
    }

    // Check for interface/contract calls (e.g., contractA.withdraw(), contractB.deposit())
    // These are function calls on contract variables
    if (stmt.type === 'ExpressionStatement' && stmt.expression) {
      const expr = stmt.expression;
      
      // Direct function call on a variable (interface call)
      if (expr.type === 'FunctionCall' && expr.expression) {
        // Check if it's a member access (contract.method())
        if (expr.expression.type === 'MemberAccess') {
          // Check if the base is an identifier (variable name)
          if (expr.expression.expression && expr.expression.expression.type === 'Identifier') {
            const varName = expr.expression.expression.name;
            // Skip built-in variables
            if (!['msg', 'tx', 'block', 'this', 'address', 'abi'].includes(varName.toLowerCase())) {
              // This is likely an external contract call
              return true;
            }
          }
          // Even without identifier check, member access with function call is likely external
          return true;
        }
      }
    }

    // Also check for interface calls by looking at the code directly
    // Pattern: variableName.functionName() where variableName is a contract interface
    // This catches patterns like: contractA.withdraw(), contractB.deposit{value: ...}()
    // Match: contractA.withdraw() or contractB.deposit{value: ...}()
    const interfaceCallPattern = /(\w+)\.(\w+)\s*[\{\(]/;
    if (interfaceCallPattern.test(code)) {
      const match = code.match(interfaceCallPattern);
      if (match && match[1]) {
        const varName = match[1].toLowerCase();
        // Skip built-in variables and common Solidity keywords
        if (!['msg', 'tx', 'block', 'this', 'address', 'abi', 'bytes', 'string', 'uint', 'int', 'bool', 'mapping', 'array'].includes(varName)) {
          // Check if it looks like a contract variable (camelCase, not a type)
          // Contract variables typically start with lowercase and are not Solidity types
          if (varName[0] === varName[0].toLowerCase() && varName.length > 1) {
            return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * Get type of external call
   */
  getCallType(code) {
    const codeLower = code.toLowerCase();
    if (codeLower.includes('delegatecall')) return 'delegatecall';
    if (codeLower.includes('.call(')) return 'call';
    if (codeLower.includes('.send(')) return 'send';
    if (codeLower.includes('.transfer(')) return 'transfer';
    return 'external';
  }

  /**
   * Extract call target from code
   */
  getCallTarget(code) {
    // Try to extract contract/address being called
    // Pattern: contractVariable.function() or address.call()
    const patterns = [
      /(\w+)\.call\s*\(/i,
      /(\w+)\.delegatecall\s*\(/i,
      /(\w+)\.transfer\s*\(/i,
      /(\w+)\.send\s*\(/i,
      /(\w+)\.\w+\s*\{/i,  // contractVariable.function{value: ...}() - interface calls with value
      /(\w+)\.\w+\s*\(/i   // contractVariable.function() - interface calls
    ];
    
    // Try patterns in order - more specific first
    for (const pattern of patterns) {
      const match = code.match(pattern);
      if (match && match[1]) {
        const target = match[1];
        const targetLower = target.toLowerCase();
        // Skip common keywords and built-ins
        if (!['msg', 'tx', 'block', 'this', 'address', 'abi', 'bytes', 'string'].includes(targetLower)) {
          // Check if it looks like a contract variable
          // Contract variables are typically camelCase
          if (target[0] === target[0].toLowerCase()) {
            return target;
          }
        }
      }
    }

    return null;
  }

  /**
   * Check if statement is a state change
   */
  isStateChange(stmt, code) {
    const codeLower = code.toLowerCase();
    
    // Skip variable declarations (local variables)
    if (stmt.type === 'VariableDeclarationStatement') {
      // Only count if it's a state variable assignment
      // State variables are typically declared at contract level, not in functions
      // But we can check if it's modifying a mapping or state variable
      if (codeLower.includes('balances[') || codeLower.includes('allowance[') || 
          codeLower.includes('mapping[') || codeLower.match(/\w+\[.*\]\s*=/)) {
        // This is modifying a state variable through mapping
        return true;
      }
      return false; // Local variable declaration, not a state change
    }
    
    // State change patterns - assignments to state variables
    const stateChangePatterns = [
      /balances\[.*\]\s*=/i,  // balances[user] = ...
      /allowance\[.*\]\s*=/i,  // allowance[from][spender] = ...
      /mapping\[.*\]\s*=/i,    // mapping assignments
      /\+\+/,                  // Increment
      /--/,                    // Decrement
      /\+\s*=/,                // Add assign
      /-\s*=/                  // Subtract assign
    ];

    // Check for state variable assignments (ExpressionStatement with Assignment)
    if (stmt.type === 'ExpressionStatement' && stmt.expression) {
      const expr = stmt.expression;
      if (expr.type === 'Assignment') {
        // Check if left side is a state variable (mapping, storage variable)
        const leftSide = this.getCodeSnippet(expr.left ? expr.left.loc : null);
        if (leftSide && (leftSide.includes('balances') || leftSide.includes('allowance') || 
            leftSide.includes('mapping') || stateChangePatterns.some(p => p.test(leftSide)))) {
          return true;
        }
      }
      if (expr.type === 'UnaryOperation') {
        // ++ or -- operations
        return /\+\+|--/.test(code);
      }
    }

    return false;
  }

  /**
   * Get type of state change
   */
  getStateChangeType(code) {
    const codeLower = code.toLowerCase();
    if (codeLower.includes('balance')) return 'balance';
    if (codeLower.includes('mapping')) return 'mapping';
    if (codeLower.includes('array')) return 'array';
    return 'state';
  }

  /**
   * Check if function has reentrancy guard
   */
  hasReentrancyGuard(code, node) {
    const codeLower = code.toLowerCase();
    
    // Check for nonReentrant modifier
    if (node.modifiers) {
      const hasNonReentrant = node.modifiers.some(m => 
        m.name && m.name.toLowerCase().includes('nonreentrant')
      );
      if (hasNonReentrant) return true;
    }

    // Check for reentrancy guard patterns
    const guardPatterns = [
      /nonReentrant/i,
      /reentrancyGuard/i,
      /_status\s*==\s*_NOT_ENTERED/i,
      /require\s*\(\s*.*reentrant/i
    ];

    return guardPatterns.some(pattern => pattern.test(codeLower));
  }

  /**
   * Check for state dependency across contracts
   */
  hasStateDependency(externalCalls, stateChanges) {
    // If we read from one contract and write to another, that's a dependency
    if (externalCalls.length > 0 && stateChanges.length > 0) {
      // Check if external calls read state
      const readsState = externalCalls.some(call => {
        const callCode = call.code.toLowerCase();
        return callCode.includes('balance') || 
               callCode.includes('get') ||
               callCode.includes('view') ||
               callCode.includes('read');
      });

      return readsState;
    }

    return false;
  }

  /**
   * Post-traversal analysis
   */
  analyzeCrossContractReentrancy() {
    // Analyze interactions between contracts
    if (this.externalCalls.length === 0) return;

    // Group by function
    const functionGroups = new Map();
    this.externalCalls.forEach(callInfo => {
      if (!functionGroups.has(callInfo.function)) {
        functionGroups.set(callInfo.function, []);
      }
      functionGroups.get(callInfo.function).push(callInfo);
    });

    // Check each function for cross-contract patterns
    functionGroups.forEach((callInfos, funcName) => {
      const allInteractions = new Set();
      callInfos.forEach(info => {
        info.interactions.forEach(interaction => allInteractions.add(interaction));
      });

      if (allInteractions.size > 1) {
        // Multiple contracts - potential cross-contract reentrancy
        // Already handled in checkCrossContractReentrancy
      }
    });
  }

  /**
   * Generate Foundry PoC for cross-contract reentrancy
   */
  generateCrossContractReentrancyPoC(contractName, funcName, interactions) {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: Cross-Contract Reentrancy Attack
 * Target: ${contractName}.${funcName}()
 * Attack Vector: Reentrancy via multiple contracts
 */
contract CrossContractReentrancyExploit is Test {
    address constant TARGET = address(0); // ${contractName} address
    address constant CONTRACT_A = address(0); // ${interactions[0] || 'ContractA'}
    address constant CONTRACT_B = address(0); // ${interactions[1] || 'ContractB'}
    
    AttackerContract attacker;

    function setUp() public {
        attacker = new AttackerContract();
    }

    function testExploit() public {
        // 1. Setup: Attacker has funds in both contracts
        // 2. Call vulnerable function which interacts with Contract A
        // ${contractName}(TARGET).${funcName}(...);
        
        // 3. Contract A's callback triggers interaction with Contract B
        // 4. Contract B's callback re-enters ${contractName}.${funcName}()
        // 5. State is inconsistent, attacker benefits
        
        // Assert exploit succeeded
        // assertGt(attacker.balance, initialBalance);
    }
}

contract AttackerContract {
    function onCallback() external {
        // Re-enter target contract
        // Or trigger another contract to re-enter
    }
}`;
  }

  /**
   * Generate Foundry PoC for delegatecall reentrancy
   */
  generateDelegatecallReentrancyPoC(contractName, funcName) {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: Delegatecall Reentrancy Attack
 * Target: ${contractName}.${funcName}()
 * Attack Vector: Reentrancy via delegatecall
 */
contract DelegatecallReentrancyExploit is Test {
    address constant TARGET = address(0); // ${contractName} address
    MaliciousImplementation maliciousImpl;

    function setUp() public {
        maliciousImpl = new MaliciousImplementation();
    }

    function testExploit() public {
        // 1. Deploy malicious implementation
        // 2. Call ${funcName}() which delegatecalls to malicious contract
        // ${contractName}(TARGET).${funcName}(address(maliciousImpl), ...);
        
        // 3. Malicious contract executes in target's context
        // 4. Malicious contract calls back into target
        // 5. Reentrancy occurs with elevated privileges
        
        // Assert exploit succeeded
    }
}

contract MaliciousImplementation {
    address target;
    
    function maliciousFunction() external {
        // Execute in target's storage context
        // Call back into target for reentrancy
        // ${contractName}(target).vulnerableFunction();
    }
}`;
  }
}

module.exports = CrossContractReentrancyDetector;

