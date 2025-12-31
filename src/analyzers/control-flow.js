/**
 * Control Flow Graph (CFG) Analyzer
 * Tracks execution paths, function calls, and state changes across the contract
 */
class ControlFlowAnalyzer {
  constructor() {
    this.contracts = new Map();
    this.functions = new Map();
    this.modifiers = new Map();
    this.stateVariables = new Map();
    this.callGraph = new Map(); // function -> [called functions]
    this.externalCalls = new Map(); // function -> [external call sites]
    this.stateModifications = new Map(); // function -> [state variable writes]
  }

  /**
   * Build complete control flow graph from AST
   */
  analyze(ast, sourceCode) {
    this.sourceCode = sourceCode;
    this.reset();

    this.visit(ast);
    this.buildCallGraph();
    this.analyzeDataFlow();

    return {
      contracts: this.contracts,
      functions: this.functions,
      modifiers: this.modifiers,
      stateVariables: this.stateVariables,
      callGraph: this.callGraph,
      externalCalls: this.externalCalls,
      stateModifications: this.stateModifications
    };
  }

  reset() {
    this.contracts.clear();
    this.functions.clear();
    this.modifiers.clear();
    this.stateVariables.clear();
    this.callGraph.clear();
    this.externalCalls.clear();
    this.stateModifications.clear();
    this.currentContract = null;
    this.currentFunction = null;
  }

  visit(node) {
    if (!node) return;

    const visitor = `visit${node.type}`;
    if (this[visitor]) {
      this[visitor](node);
    }

    // Traverse children
    if (node.subNodes) {
      node.subNodes.forEach(child => this.visit(child));
    }
    if (node.body) {
      if (node.body.statements) {
        node.body.statements.forEach(stmt => this.visit(stmt));
      } else {
        this.visit(node.body);
      }
    }
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
    const contractInfo = {
      name: node.name,
      kind: node.kind,
      baseContracts: node.baseContracts || [],
      stateVariables: [],
      functions: [],
      modifiers: []
    };
    this.contracts.set(node.name, contractInfo);
  }

  visitStateVariableDeclaration(node) {
    if (!node.variables || !this.currentContract) return;

    node.variables.forEach(variable => {
      const varInfo = {
        name: variable.name,
        type: this.getTypeName(variable.typeName),
        visibility: variable.visibility || 'internal',
        isConstant: variable.isDeclaredConst,
        isImmutable: variable.isImmutable,
        contract: this.currentContract
      };

      this.stateVariables.set(`${this.currentContract}.${variable.name}`, varInfo);
      this.contracts.get(this.currentContract).stateVariables.push(variable.name);
    });
  }

  visitFunctionDefinition(node) {
    if (!this.currentContract) return;

    const funcName = node.name || (node.isConstructor ? 'constructor' : 'fallback');
    const funcKey = `${this.currentContract}.${funcName}`;

    const funcInfo = {
      name: funcName,
      contract: this.currentContract,
      visibility: node.visibility || 'public',
      stateMutability: node.stateMutability,
      modifiers: (node.modifiers || []).map(m => m.name),
      parameters: (node.parameters || []).map(p => ({
        name: p.name,
        type: this.getTypeName(p.typeName)
      })),
      isConstructor: node.isConstructor,
      isFallback: !node.name && !node.isConstructor,
      externalCalls: [],
      stateWrites: [],
      stateReads: [],
      node: node
    };

    this.currentFunction = funcKey;
    this.functions.set(funcKey, funcInfo);
    this.contracts.get(this.currentContract).functions.push(funcName);

    // Analyze function body
    if (node.body) {
      this.analyzeFunctionBody(node.body, funcInfo);
    }

    this.currentFunction = null;
  }

  visitModifierDefinition(node) {
    if (!this.currentContract) return;

    const modKey = `${this.currentContract}.${node.name}`;
    const modInfo = {
      name: node.name,
      contract: this.currentContract,
      parameters: (node.parameters || []).map(p => ({
        name: p.name,
        type: this.getTypeName(p.typeName)
      })),
      checksAccess: false,
      checksOwnership: false,
      checksRole: false,
      requireStatements: [],
      node: node
    };

    // Analyze modifier to determine what it checks
    if (node.body) {
      this.analyzeModifierBody(node.body, modInfo);
    }

    this.modifiers.set(modKey, modInfo);
    this.contracts.get(this.currentContract).modifiers.push(node.name);
  }

  analyzeFunctionBody(body, funcInfo) {
    if (!body || !body.statements) return;

    body.statements.forEach(stmt => {
      this.analyzeStatement(stmt, funcInfo);
    });
  }

  analyzeStatement(stmt, funcInfo) {
    if (!stmt) return;

    // Detect external calls
    if (this.isExternalCall(stmt)) {
      const callInfo = this.extractCallInfo(stmt);
      funcInfo.externalCalls.push(callInfo);
    }

    // Detect state writes
    if (this.isStateWrite(stmt)) {
      const writeInfo = this.extractWriteInfo(stmt);
      funcInfo.stateWrites.push(writeInfo);
    }

    // Detect state reads
    if (this.isStateRead(stmt)) {
      const readInfo = this.extractReadInfo(stmt);
      funcInfo.stateReads.push(readInfo);
    }

    // Recurse into nested statements
    if (stmt.type === 'IfStatement') {
      if (stmt.TrueBody) this.analyzeStatement(stmt.TrueBody, funcInfo);
      if (stmt.FalseBody) this.analyzeStatement(stmt.FalseBody, funcInfo);
    } else if (stmt.type === 'Block' && stmt.statements) {
      stmt.statements.forEach(s => this.analyzeStatement(s, funcInfo));
    } else if (stmt.type === 'WhileStatement' || stmt.type === 'ForStatement') {
      if (stmt.body) this.analyzeStatement(stmt.body, funcInfo);
    }
  }

  analyzeModifierBody(body, modInfo) {
    if (!body || !body.statements) return;

    body.statements.forEach(stmt => {
      // Look for require statements
      if (this.isRequireStatement(stmt)) {
        const condition = this.extractRequireCondition(stmt);
        modInfo.requireStatements.push(condition);

        // Determine what type of check this is
        if (this.checksOwnership(condition)) {
          modInfo.checksOwnership = true;
          modInfo.checksAccess = true;
        } else if (this.checksRole(condition)) {
          modInfo.checksRole = true;
          modInfo.checksAccess = true;
        } else if (this.isAccessCheck(condition)) {
          modInfo.checksAccess = true;
        }
      }
    });
  }

  isExternalCall(stmt) {
    if (!stmt || !stmt.expression) return false;
    const expr = stmt.expression;

    // Check for low-level calls
    if (expr.type === 'FunctionCall' && expr.expression) {
      const memberName = this.getMemberName(expr.expression);
      return ['call', 'delegatecall', 'staticcall', 'send', 'transfer'].includes(memberName);
    }

    return false;
  }

  isStateWrite(stmt) {
    if (!stmt || !stmt.expression) return false;
    const expr = stmt.expression;

    if (expr.type === 'BinaryOperation' && expr.operator === '=') {
      // Check if left side is a state variable
      return this.isStateVariable(expr.left);
    }

    return false;
  }

  isStateRead(stmt) {
    // This is simplified - in production would need full expression traversal
    return false;
  }

  isStateVariable(node) {
    if (!node) return false;

    // Check if this is an identifier that matches a known state variable
    if (node.type === 'Identifier') {
      const varKey = `${this.currentContract}.${node.name}`;
      return this.stateVariables.has(varKey);
    }

    // Check for indexed access or member access
    if (node.type === 'IndexAccess' || node.type === 'MemberAccess') {
      return this.isStateVariable(node.base || node.expression);
    }

    return false;
  }

  isRequireStatement(stmt) {
    if (!stmt || !stmt.expression) return false;
    const expr = stmt.expression;

    if (expr.type === 'FunctionCall' && expr.expression) {
      const funcName = expr.expression.name || '';
      return funcName === 'require' || funcName === 'assert';
    }

    return false;
  }

  extractRequireCondition(stmt) {
    if (!stmt || !stmt.expression || !stmt.expression.arguments) return '';

    const args = stmt.expression.arguments;
    if (args.length === 0) return '';

    // Extract source code for the condition
    const condition = args[0];
    if (condition.loc) {
      return this.getSourceSlice(condition.loc);
    }

    return '';
  }

  checksOwnership(condition) {
    const lower = condition.toLowerCase();
    return lower.includes('msg.sender') &&
           (lower.includes('owner') || lower.includes('admin'));
  }

  checksRole(condition) {
    const lower = condition.toLowerCase();
    return lower.includes('role') || lower.includes('hasrole');
  }

  isAccessCheck(condition) {
    return condition.includes('msg.sender');
  }

  extractCallInfo(stmt) {
    return {
      type: this.getMemberName(stmt.expression?.expression),
      target: 'unknown', // Would need deeper analysis
      loc: stmt.loc
    };
  }

  extractWriteInfo(stmt) {
    const left = stmt.expression.left;
    return {
      variable: left.name || 'unknown',
      loc: stmt.loc
    };
  }

  extractReadInfo(stmt) {
    return { loc: stmt.loc };
  }

  getMemberName(node) {
    if (!node) return '';
    if (node.type === 'MemberAccess') return node.memberName;
    if (node.type === 'Identifier') return node.name;
    return '';
  }

  getTypeName(typeNode) {
    if (!typeNode) return 'unknown';
    if (typeNode.type === 'ElementaryTypeName') return typeNode.name;
    if (typeNode.type === 'UserDefinedTypeName') return typeNode.namePath;
    if (typeNode.type === 'Mapping') return 'mapping';
    return 'complex';
  }

  buildCallGraph() {
    // Build function call relationships
    for (const [funcKey, funcInfo] of this.functions) {
      this.callGraph.set(funcKey, []);

      // Add internal function calls (would need to parse function bodies more deeply)
      // This is a simplified version
    }
  }

  analyzeDataFlow() {
    // Perform data flow analysis to track tainted data
    // This would require implementing a worklist algorithm
    // Simplified for now
  }

  getSourceSlice(loc) {
    if (!loc || !this.sourceCode) return '';

    const lines = this.sourceCode.split('\n');
    if (loc.start.line === loc.end.line) {
      const line = lines[loc.start.line - 1] || '';
      return line.substring(loc.start.column, loc.end.column);
    }

    // Multi-line - return first line for now
    return lines[loc.start.line - 1] || '';
  }

  /**
   * Check if a function can reach another function (transitive closure)
   */
  canReach(fromFunc, toFunc) {
    const visited = new Set();
    const queue = [fromFunc];

    while (queue.length > 0) {
      const current = queue.shift();
      if (current === toFunc) return true;
      if (visited.has(current)) continue;

      visited.add(current);
      const callees = this.callGraph.get(current) || [];
      queue.push(...callees);
    }

    return false;
  }

  /**
   * Get all functions that can be called from a given function
   */
  getReachableFunctions(funcKey) {
    const reachable = new Set();
    const visited = new Set();
    const queue = [funcKey];

    while (queue.length > 0) {
      const current = queue.shift();
      if (visited.has(current)) continue;

      visited.add(current);
      reachable.add(current);

      const callees = this.callGraph.get(current) || [];
      queue.push(...callees);
    }

    return Array.from(reachable);
  }
}

module.exports = ControlFlowAnalyzer;
