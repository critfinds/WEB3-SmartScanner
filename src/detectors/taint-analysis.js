const BaseDetector = require('./base-detector');

/**
 * Taint Analysis Detector (Data Flow Analysis)
 * Tracks user-controlled inputs to dangerous sinks
 * Similar to Slither's taint tracking capabilities
 */
class TaintAnalysisDetector extends BaseDetector {
  constructor() {
    super(
      'Taint Analysis: User-Controlled Data Flow',
      'Tracks flow of user-controlled data to dangerous operations (data flow analysis)',
      'HIGH'
    );
    this.currentFunction = null;
    this.currentContract = null;
    this.taintedVars = new Set();
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'fallback';
    this.taintedVars.clear();

    // Mark function parameters as tainted (user-controlled)
    if (node.parameters && node.parameters.length > 0) {
      node.parameters.forEach(param => {
        if (param.name) {
          this.taintedVars.add(param.name);
        }
      });
    }

    // Also mark msg.sender, msg.value, msg.data as tainted
    this.taintedVars.add('msg.sender');
    this.taintedVars.add('msg.value');
    this.taintedVars.add('msg.data');
    this.taintedVars.add('tx.origin');

    // Analyze function body for taint propagation
    if (node.body && node.body.statements) {
      this.analyzeStatements(node.body.statements, node);
    }
  }

  analyzeStatements(statements, functionNode) {
    if (!statements) return;

    statements.forEach(stmt => {
      // Track taint propagation through assignments
      this.trackTaintPropagation(stmt);

      // Check for dangerous sinks with tainted data
      this.checkDangerousSinks(stmt, functionNode);

      // Recurse into nested blocks
      if (stmt.trueBody) {
        this.analyzeStatements([stmt.trueBody], functionNode);
      }
      if (stmt.falseBody) {
        this.analyzeStatements([stmt.falseBody], functionNode);
      }
      if (stmt.body && stmt.body.statements) {
        this.analyzeStatements(stmt.body.statements, functionNode);
      }
    });
  }

  trackTaintPropagation(stmt) {
    const code = this.getCodeSnippet(stmt.loc);

    // Track assignments: if right side is tainted, left side becomes tainted
    if (stmt.type === 'VariableDeclarationStatement' ||
        (stmt.type === 'ExpressionStatement' && code.includes('='))) {

      // Extract variable name being assigned to
      const assignmentMatch = code.match(/(\w+)\s*=/);
      if (assignmentMatch) {
        const leftVar = assignmentMatch[1];

        // Check if any tainted variable is on the right side
        for (const taintedVar of this.taintedVars) {
          if (code.includes(taintedVar)) {
            this.taintedVars.add(leftVar);
            break;
          }
        }
      }
    }
  }

  checkDangerousSinks(stmt, functionNode) {
    const code = this.getCodeSnippet(stmt.loc);

    // Check for tainted data in dangerous operations
    const dangerousSinks = [
      {
        pattern: /\.call\(/,
        name: 'call',
        description: 'Low-level call with user-controlled data'
      },
      {
        pattern: /\.delegatecall\(/,
        name: 'delegatecall',
        description: 'Delegatecall with user-controlled data'
      },
      {
        pattern: /selfdestruct\s*\(/,
        name: 'selfdestruct',
        description: 'Selfdestruct with user-controlled recipient'
      },
      {
        pattern: /\.transfer\s*\(/,
        name: 'transfer',
        description: 'Transfer to user-controlled address'
      },
      {
        pattern: /\.send\s*\(/,
        name: 'send',
        description: 'Send to user-controlled address'
      },
      {
        pattern: /assembly\s*\{/,
        name: 'assembly',
        description: 'Assembly with user-controlled data'
      },
    ];

    dangerousSinks.forEach(sink => {
      if (sink.pattern.test(code)) {
        // Check if any tainted variable is used in this statement
        for (const taintedVar of this.taintedVars) {
          if (code.includes(taintedVar)) {
            this.addFinding({
              title: `Taint Analysis: User-Controlled ${sink.name}`,
              description: `Function '${this.currentFunction}' uses ${sink.description}. User-controlled variable '${taintedVar}' flows to a dangerous operation. This could allow attackers to manipulate critical contract behavior.`,
              location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
              line: stmt.loc ? stmt.loc.start.line : 0,
              column: stmt.loc ? stmt.loc.start.column : 0,
              code: code,
              severity: 'CRITICAL',
              recommendation: `Validate and sanitize user input before use in ${sink.name}. Add strict access controls and input validation. Consider using a whitelist approach for addresses. Never use user-controlled data directly in dangerous operations.`,
              references: [
                'https://github.com/crytic/slither/wiki/Detector-Documentation#taint-analysis',
                'https://swcregistry.io/docs/SWC-105',
                'https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/'
              ]
            });
            break;
          }
        }

        // Special check for msg.sender/tx.origin in access control
        if ((code.includes('msg.sender') || code.includes('tx.origin')) &&
            (sink.name === 'selfdestruct' || sink.name === 'delegatecall')) {
          // This might be okay if properly restricted, but flag for review
          this.addFinding({
            title: `Taint Analysis: Address-Based ${sink.name}`,
            description: `Function '${this.currentFunction}' uses ${sink.name} with address-based logic. Ensure proper access controls are in place.`,
            location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
            line: stmt.loc ? stmt.loc.start.line : 0,
            column: stmt.loc ? stmt.loc.start.column : 0,
            code: code,
            severity: 'MEDIUM',
            recommendation: `Review access controls. Ensure only authorized addresses can trigger this operation. Consider using role-based access control (RBAC).`,
            references: [
              'https://docs.openzeppelin.com/contracts/4.x/access-control'
            ]
          });
        }
      }
    });

    // Check for tainted data in array indexing (potential out-of-bounds)
    if (/\[\s*\w+\s*\]/.test(code)) {
      for (const taintedVar of this.taintedVars) {
        const regex = new RegExp(`\\[\\s*${taintedVar}\\s*\\]`);
        if (regex.test(code)) {
          this.addFinding({
            title: 'Taint Analysis: User-Controlled Array Index',
            description: `Function '${this.currentFunction}' uses user-controlled variable '${taintedVar}' as an array index. This could lead to out-of-bounds access or denial of service if not properly validated.`,
            location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
            line: stmt.loc ? stmt.loc.start.line : 0,
            column: stmt.loc ? stmt.loc.start.column : 0,
            code: code,
            severity: 'MEDIUM',
            recommendation: `Add bounds checking before using user input as array index. Example: require(index < array.length, "Index out of bounds");`,
            references: [
              'https://swcregistry.io/docs/SWC-123'
            ]
          });
          break;
        }
      }
    }

    // Check for tainted data in loop conditions (potential DoS)
    if (stmt.type === 'ForStatement' || stmt.type === 'WhileStatement') {
      for (const taintedVar of this.taintedVars) {
        if (code.includes(taintedVar)) {
          this.addFinding({
            title: 'Taint Analysis: User-Controlled Loop Bound',
            description: `Function '${this.currentFunction}' uses user-controlled variable '${taintedVar}' in loop condition. Attacker could provide large values causing denial of service through gas exhaustion.`,
            location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
            line: stmt.loc ? stmt.loc.start.line : 0,
            column: stmt.loc ? stmt.loc.start.column : 0,
            code: code,
            severity: 'HIGH',
            recommendation: `Add strict upper bounds to loop iterations. Example: require(userValue <= MAX_ITERATIONS, "Too many iterations"); Use a maximum iteration limit that is reasonable for block gas limits.`,
            references: [
              'https://swcregistry.io/docs/SWC-128',
              'https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/'
            ]
          });
          break;
        }
      }
    }
  }
}

module.exports = TaintAnalysisDetector;
