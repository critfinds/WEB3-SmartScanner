const BaseDetector = require('./base-detector');

/**
 * Uninitialized Storage Pointer Detector
 * Detects uninitialized local storage pointers (pre-0.5.0 critical vulnerability)
 * These can overwrite arbitrary storage slots
 */
class UninitializedStorageDetector extends BaseDetector {
  constructor() {
    super(
      'Uninitialized Storage Pointer',
      'Detects uninitialized local storage variables that can corrupt contract storage',
      'CRITICAL'
    );
    this.currentFunction = null;
    this.currentContract = null;
    this.solidityVersion = null;
  }

  async detect(ast, sourceCode, fileName) {
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.findings = [];

    // Extract Solidity version
    this.extractSolidityVersion();

    this.visit(ast);
    return this.findings;
  }

  extractSolidityVersion() {
    const versionMatch = this.sourceCode.match(/pragma\s+solidity\s+[\^><=]*(\d+\.\d+\.\d+)/);
    if (versionMatch) {
      this.solidityVersion = versionMatch[1];
    }
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'fallback';

    if (node.body && node.body.statements) {
      this.analyzeStatements(node.body.statements, node);
    }
  }

  analyzeStatements(statements, functionNode) {
    if (!statements) return;

    statements.forEach(stmt => {
      // Check for variable declarations
      if (stmt.type === 'VariableDeclarationStatement') {
        this.checkVariableDeclaration(stmt, functionNode);
      }

      // Recurse into nested statements
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

  checkVariableDeclaration(stmt, functionNode) {
    if (!stmt.variables || stmt.variables.length === 0) return;

    stmt.variables.forEach(variable => {
      if (!variable) return;

      const code = this.getCodeSnippet(stmt.loc);
      const varName = variable.name;

      // Check if it's a complex type (struct, array, mapping) with storage location
      const isComplexType = variable.typeName &&
        (variable.typeName.type === 'Mapping' ||
         variable.typeName.type === 'ArrayTypeName' ||
         variable.typeName.type === 'UserDefinedTypeName');

      // Check if storage location is explicitly 'storage'
      const hasStorageKeyword = code.includes('storage') && code.includes(varName);

      // Check if variable is initialized
      const isInitialized = stmt.initialValue !== null;

      if (isComplexType && hasStorageKeyword && !isInitialized) {
        const severity = this.getSeverityForVersion();

        this.addFinding({
          title: 'Uninitialized Storage Pointer',
          description: `Local storage variable '${varName}' in function '${this.currentFunction}' is declared but not initialized. In Solidity versions < 0.5.0, this creates a pointer to storage slot 0, which can lead to unintended overwrites of critical state variables. Even in newer versions, this pattern indicates potential logic errors.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: stmt.loc ? stmt.loc.start.line : 0,
          column: stmt.loc ? stmt.loc.start.column : 0,
          code: code,
          severity: severity,
          recommendation: 'Initialize the storage pointer to reference an existing storage variable, or change the data location to memory if a copy is intended. Example: MyStruct storage s = myStructs[id]; or MyStruct memory s;',
          references: [
            'https://swcregistry.io/docs/SWC-109',
            'https://github.com/crytic/slither/wiki/Detector-Documentation#uninitialized-storage-variables',
            'https://blog.ethereum.org/2016/11/01/security-alert-solidity-variables-can-overwritten-storage'
          ]
        });
      }

      // Also check for suspicious patterns in structs
      if (variable.typeName && variable.typeName.type === 'UserDefinedTypeName' && hasStorageKeyword) {
        const lines = this.sourceCode.split('\n');
        const startLine = stmt.loc.start.line - 1;

        // Look ahead a few lines to see if the variable is used before initialization
        let usedBeforeInit = false;
        for (let i = startLine + 1; i < Math.min(startLine + 10, lines.length); i++) {
          const line = lines[i];
          if (line.includes(varName + '.') || line.includes(varName + '[')) {
            // Check if this is an assignment TO the variable (initialization)
            if (!line.includes(`${varName} =`) && !isInitialized) {
              usedBeforeInit = true;
              break;
            }
          }
          // If we hit a return or closing brace, stop looking
          if (line.includes('return') || line.includes('}')) {
            break;
          }
        }

        if (usedBeforeInit && !isInitialized) {
          this.addFinding({
            title: 'Storage Pointer Used Before Initialization',
            description: `Storage variable '${varName}' is used before being initialized in function '${this.currentFunction}'. This will access/modify storage slot 0 or garbage data.`,
            location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
            line: stmt.loc ? stmt.loc.start.line : 0,
            column: stmt.loc ? stmt.loc.start.column : 0,
            code: code,
            severity: 'CRITICAL',
            recommendation: 'Always initialize storage pointers before use.',
            references: [
              'https://swcregistry.io/docs/SWC-109'
            ]
          });
        }
      }
    });
  }

  getSeverityForVersion() {
    if (!this.solidityVersion) return 'CRITICAL';

    const [major, minor] = this.solidityVersion.split('.').map(Number);

    // Solidity >= 0.5.0 prevents this at compile time, but still suspicious
    if (major > 0 || minor >= 5) {
      return 'MEDIUM';
    }

    return 'CRITICAL';
  }
}

module.exports = UninitializedStorageDetector;
