const BaseDetector = require('./base-detector');

/**
 * Gas Griefing and DoS Detector
 * Detects unbounded loops, gas-intensive operations, and DoS vectors
 * Critical for production contracts handling high value
 */
class GasGriefingDetector extends BaseDetector {
  constructor() {
    super(
      'Gas Griefing and Denial of Service',
      'Detects unbounded loops, excessive gas consumption, and DoS attack vectors',
      'HIGH'
    );
    this.currentFunction = null;
    this.currentContract = null;
    this.stateArrays = new Set();
  }

  async detect(ast, sourceCode, fileName) {
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.findings = [];
    this.stateArrays.clear();

    // First collect state arrays
    this.visit(ast);

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;

    // Collect state-level arrays
    if (node.subNodes) {
      node.subNodes.forEach(subNode => {
        if (subNode.type === 'StateVariableDeclaration') {
          subNode.variables.forEach(variable => {
            if (variable.typeName && variable.typeName.type === 'ArrayTypeName') {
              this.stateArrays.add(variable.name);
            }
          });
        }
      });
    }
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'fallback';

    if (node.body && node.body.statements) {
      this.analyzeFunction(node);
    }
  }

  analyzeFunction(node) {
    const statements = this.getAllStatements(node.body.statements);
    const code = this.getCodeSnippet(node.loc);

    // Pattern 1: Unbounded loop over storage array (CRITICAL DoS)
    const unboundedLoop = this.detectUnboundedStorageLoop(statements);
    if (unboundedLoop) {
      this.addFinding({
        title: 'Critical DoS: Unbounded Loop Over Storage',
        description: `Function '${this.currentFunction}' loops over a storage array without gas limits. As the array grows, gas costs increase unboundedly, eventually making the function impossible to execute (permanent DoS). Attackers can intentionally grow the array to brick the contract.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: unboundedLoop.line,
        column: unboundedLoop.column,
        code: unboundedLoop.code,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        recommendation: 'Use pagination/batching: function processBatch(uint start, uint end). Implement pull-over-push pattern where users call individual functions instead of contract iterating. Consider off-chain indexing with Merkle proofs for large datasets.',
        references: [
          'https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/',
          'https://github.com/code-423n4/2021-04-maple-findings/issues/42',
          'https://swcregistry.io/docs/SWC-128'
        ]
      });
    }

    // Pattern 2: External calls in loops (Gas griefing)
    const externalCallsInLoop = this.detectExternalCallsInLoop(statements);
    if (externalCallsInLoop) {
      this.addFinding({
        title: 'Gas Griefing: External Calls in Loop',
        description: `Function '${this.currentFunction}' makes external calls inside a loop. A single failing call or gas-intensive callback can cause the entire transaction to fail or exceed block gas limit. Malicious recipients can grief by consuming all gas or reverting.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: externalCallsInLoop.line,
        column: externalCallsInLoop.column,
        code: externalCallsInLoop.code,
        severity: 'HIGH',
        confidence: 'HIGH',
        recommendation: 'Use pull-over-push: Instead of sending to recipients in a loop, let them withdraw individually. Implement a withdrawal pattern. For multi-send, provide batch limits and error handling that doesn\'t revert all operations.',
        references: [
          'https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/',
          'https://github.com/crytic/building-secure-contracts/blob/master/development-guidelines/dos.md'
        ]
      });
    }

    // Pattern 3: Dynamic array operations without limits
    const unboundedArrayOp = this.detectUnboundedArrayOperation(statements, code);
    if (unboundedArrayOp) {
      this.addFinding({
        title: 'DoS Risk: Unbounded Array Growth',
        description: `Function '${this.currentFunction}' pushes to storage array without size limits. Attackers can grow the array to make future operations prohibitively expensive or impossible.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: unboundedArrayOp.line,
        column: unboundedArrayOp.column,
        code: unboundedArrayOp.code,
        severity: 'MEDIUM',
        confidence: 'HIGH',
        recommendation: 'Implement maximum array size limits. Example: require(array.length < MAX_SIZE, "Array full"). Consider using EnumerableSet with size limits or off-chain storage for large datasets.',
        references: [
          'https://github.com/crytic/not-so-smart-contracts/tree/master/denial_of_service'
        ]
      });
    }

    // Pattern 4: Gas-intensive operations (CREATE2, SSTORE in loops)
    const gasIntensiveOp = this.detectGasIntensiveOperations(statements);
    if (gasIntensiveOp) {
      this.addFinding({
        title: 'Gas Griefing: Expensive Operations in Loop',
        description: `Function '${this.currentFunction}' performs gas-intensive operations (storage writes, contract creation) in loops. This can easily exceed block gas limits as data grows.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: gasIntensiveOp.line,
        column: gasIntensiveOp.column,
        code: gasIntensiveOp.code,
        severity: 'MEDIUM',
        confidence: 'MEDIUM',
        recommendation: 'Batch operations with reasonable limits. Implement batched processing with start/end indices. Consider using bitmap patterns for boolean flags instead of arrays.',
        references: [
          'https://www.rareskills.io/post/gas-optimization'
        ]
      });
    }

    // Pattern 5: Owner-dependent operations without timelock
    const ownerDoS = this.detectOwnerDependentDoS(code, node);
    if (ownerDoS) {
      this.addFinding({
        title: 'DoS Risk: Owner Centralization',
        description: `Function '${this.currentFunction}' has critical functionality that depends on owner actions. If owner key is lost or owner becomes malicious/inactive, contract functionality can be permanently disabled.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: ownerDoS.line,
        column: ownerDoS.column,
        code: ownerDoS.code,
        severity: 'MEDIUM',
        confidence: 'LOW',
        recommendation: 'Implement multi-sig ownership, timelock mechanisms, or emergency withdrawal patterns. Consider making critical functions callable by governance or after delay periods.',
        references: [
          'https://docs.openzeppelin.com/contracts/4.x/api/governance',
          'https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/governance/TimelockController.sol'
        ]
      });
    }

    // Pattern 6: Fallback with complex logic
    const complexFallback = this.detectComplexFallback(node);
    if (complexFallback) {
      this.addFinding({
        title: 'DoS Risk: Complex Fallback/Receive Function',
        description: `Function '${this.currentFunction}' is a fallback/receive function with complex logic. This can cause transfers to this contract to fail, potentially locking funds in other contracts that try to send ETH here.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: complexFallback.line,
        column: complexFallback.column,
        code: complexFallback.code,
        severity: 'MEDIUM',
        confidence: 'MEDIUM',
        recommendation: 'Keep fallback/receive functions minimal (emit event, update balance). Move complex logic to explicit functions. Ensure fallback stays under 2300 gas for .transfer() compatibility if needed.',
        references: [
          'https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/#dont-use-transfer-or-send'
        ]
      });
    }
  }

  detectUnboundedStorageLoop(statements) {
    for (const stmt of statements) {
      if (stmt.type === 'ForStatement') {
        const code = this.getCodeSnippet(stmt.loc);

        // Check if loop condition uses .length of state array
        for (const arrayName of this.stateArrays) {
          const pattern = new RegExp(`${arrayName}\\.length`, 'i');
          if (pattern.test(code)) {
            return {
              line: stmt.loc ? stmt.loc.start.line : 0,
              column: stmt.loc ? stmt.loc.start.column : 0,
              code: code
            };
          }
        }
      }
    }
    return null;
  }

  detectExternalCallsInLoop(statements) {
    for (const stmt of statements) {
      if (stmt.type === 'ForStatement' || stmt.type === 'WhileStatement') {
        const loopBody = this.getAllStatements([stmt]);

        for (const innerStmt of loopBody) {
          const code = this.getCodeSnippet(innerStmt.loc);

          // Check for external calls
          if (code.match(/\.call\(|\.transfer\(|\.send\(|\.delegatecall\(/)) {
            return {
              line: innerStmt.loc ? innerStmt.loc.start.line : 0,
              column: innerStmt.loc ? innerStmt.loc.start.column : 0,
              code: code
            };
          }
        }
      }
    }
    return null;
  }

  detectUnboundedArrayOperation(statements, fullCode) {
    for (const stmt of statements) {
      const code = this.getCodeSnippet(stmt.loc);

      // Check for .push() on state arrays
      for (const arrayName of this.stateArrays) {
        const pushPattern = new RegExp(`${arrayName}\\.push`, 'i');
        if (pushPattern.test(code)) {
          // Check if there's a size limit check
          if (!fullCode.match(new RegExp(`${arrayName}\\.length\\s*[<>]|MAX.*SIZE|require.*length`, 'i'))) {
            return {
              line: stmt.loc ? stmt.loc.start.line : 0,
              column: stmt.loc ? stmt.loc.start.column : 0,
              code: code
            };
          }
        }
      }
    }
    return null;
  }

  detectGasIntensiveOperations(statements) {
    for (const stmt of statements) {
      if (stmt.type === 'ForStatement' || stmt.type === 'WhileStatement') {
        const loopBody = this.getAllStatements([stmt]);

        for (const innerStmt of loopBody) {
          const code = this.getCodeSnippet(innerStmt.loc);

          // Check for storage writes in loops
          if (code.match(/\w+\[.*\]\s*=|\.push\(|new \w+/)) {
            return {
              line: innerStmt.loc ? innerStmt.loc.start.line : 0,
              column: innerStmt.loc ? innerStmt.loc.start.column : 0,
              code: code
            };
          }
        }
      }
    }
    return null;
  }

  detectOwnerDependentDoS(code, node) {
    // Check if function requires owner but performs critical operations
    const hasOnlyOwner = code.match(/onlyOwner|require.*msg\.sender.*==.*owner/i);
    const hasCriticalOps = code.match(/withdraw|pause|unpause|migrate|upgrade/i);

    if (hasOnlyOwner && hasCriticalOps) {
      return {
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc)
      };
    }
    return null;
  }

  detectComplexFallback(node) {
    if (!this.currentFunction) {
      // Check if it's fallback or receive
      const code = this.getCodeSnippet(node.loc);
      if (code.match(/fallback|receive.*external.*payable/)) {
        // Count statements (simple heuristic)
        if (node.body && node.body.statements && node.body.statements.length > 3) {
          return {
            line: node.loc ? node.loc.start.line : 0,
            column: node.loc ? node.loc.start.column : 0,
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

module.exports = GasGriefingDetector;
