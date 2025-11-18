const BaseDetector = require('./base-detector');

/**
 * Dead Code Detector
 * Detects unused functions, variables, and unreachable code
 * Dead code increases attack surface and maintenance burden
 */
class DeadCodeDetector extends BaseDetector {
  constructor() {
    super(
      'Dead Code Detection',
      'Detects unused functions, state variables, and unreachable code that should be removed',
      'INFO'
    );
    this.definedFunctions = new Map(); // functionName -> {node, contract, called}
    this.definedVariables = new Map(); // varName -> {node, contract, used}
    this.currentContract = null;
  }

  async detect(ast, sourceCode, fileName) {
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.findings = [];
    this.definedFunctions.clear();
    this.definedVariables.clear();

    // First pass: collect all definitions
    this.visit(ast);

    // Second pass: analyze for dead code
    this.analyzeDeadCode();

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;

    if (node.subNodes) {
      node.subNodes.forEach(subNode => {
        // Collect state variables
        if (subNode.type === 'StateVariableDeclaration') {
          subNode.variables.forEach(variable => {
            const key = `${this.currentContract}.${variable.name}`;
            this.definedVariables.set(key, {
              node: variable,
              contract: this.currentContract,
              used: false,
              visibility: variable.visibility
            });
          });
        }
      });
    }
  }

  visitFunctionDefinition(node) {
    const funcName = node.name;
    if (!funcName || node.isConstructor) return;

    const key = `${this.currentContract}.${funcName}`;

    // Don't track certain functions that are expected to be called externally
    const isInterface = node.visibility === 'external' || node.visibility === 'public';
    const isOverride = this.getCodeSnippet(node.loc).includes('override');
    const isVirtual = this.getCodeSnippet(node.loc).includes('virtual');

    this.definedFunctions.set(key, {
      node: node,
      contract: this.currentContract,
      called: false,
      visibility: node.visibility,
      isInterface: isInterface,
      isOverride: isOverride,
      isVirtual: isVirtual
    });

    // Check for usage of variables and function calls within this function
    if (node.body && node.body.statements) {
      this.analyzeStatements(node.body.statements);
    }
  }

  analyzeStatements(statements) {
    if (!statements) return;

    statements.forEach(stmt => {
      const code = this.getCodeSnippet(stmt.loc);

      // Mark variables as used
      for (const [key, varInfo] of this.definedVariables) {
        const varName = key.split('.')[1];
        if (code.includes(varName)) {
          varInfo.used = true;
        }
      }

      // Mark functions as called
      for (const [key, funcInfo] of this.definedFunctions) {
        const funcName = key.split('.')[1];
        // Check for function calls
        if (code.includes(funcName + '(')) {
          funcInfo.called = true;
        }
      }

      // Recurse
      if (stmt.trueBody) {
        this.analyzeStatements([stmt.trueBody]);
      }
      if (stmt.falseBody) {
        this.analyzeStatements([stmt.falseBody]);
      }
      if (stmt.body && stmt.body.statements) {
        this.analyzeStatements(stmt.body.statements);
      }
    });
  }

  analyzeDeadCode() {
    // Check for unused internal/private functions
    for (const [key, funcInfo] of this.definedFunctions) {
      const funcName = key.split('.')[1];

      // Only flag private/internal functions that are never called
      if ((funcInfo.visibility === 'private' || funcInfo.visibility === 'internal') &&
          !funcInfo.called &&
          !funcInfo.isVirtual) {

        this.addFinding({
          title: `Dead Code: Unused ${funcInfo.visibility} Function`,
          description: `Function '${funcName}' in contract '${funcInfo.contract}' is declared as ${funcInfo.visibility} but is never called within the contract. This is dead code that increases contract size and maintenance burden.`,
          location: `Contract: ${funcInfo.contract}, Function: ${funcName}`,
          line: funcInfo.node.loc ? funcInfo.node.loc.start.line : 0,
          column: funcInfo.node.loc ? funcInfo.node.loc.start.column : 0,
          code: this.getCodeSnippet(funcInfo.node.loc),
          severity: 'INFO',
          recommendation: `Remove the unused function '${funcName}' to reduce contract size and improve code maintainability. If the function is intended for future use, add a comment explaining this.`,
          references: [
            'https://github.com/crytic/slither/wiki/Detector-Documentation#dead-code'
          ]
        });
      }
    }

    // Check for unused private state variables
    for (const [key, varInfo] of this.definedVariables) {
      const varName = key.split('.')[1];

      if (varInfo.visibility === 'private' && !varInfo.used) {
        this.addFinding({
          title: 'Dead Code: Unused Private State Variable',
          description: `State variable '${varName}' in contract '${varInfo.contract}' is declared as private but is never used. This wastes storage and deployment gas.`,
          location: `Contract: ${varInfo.contract}, Variable: ${varName}`,
          line: varInfo.node.loc ? varInfo.node.loc.start.line : 0,
          column: varInfo.node.loc ? varInfo.node.loc.start.column : 0,
          code: this.getCodeSnippet(varInfo.node.loc),
          severity: 'INFO',
          recommendation: `Remove the unused state variable '${varName}' to save gas and improve code clarity.`,
          references: [
            'https://github.com/crytic/slither/wiki/Detector-Documentation#unused-state-variable'
          ]
        });
      }
    }
  }
}

module.exports = DeadCodeDetector;
