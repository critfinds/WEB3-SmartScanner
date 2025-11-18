const BaseDetector = require('./base-detector');

/**
 * Advanced Shadowing Detector
 * Detects state variable and function shadowing across inheritance hierarchy
 * Similar to Slither's shadowing detectors
 */
class ShadowingDetector extends BaseDetector {
  constructor() {
    super(
      'State Variable and Function Shadowing',
      'Detects shadowed state variables and functions in inheritance hierarchy which can cause unexpected behavior',
      'HIGH'
    );
    this.contracts = new Map(); // contractName -> contract data
    this.inheritanceGraph = new Map(); // contractName -> parent contracts
  }

  async detect(ast, sourceCode, fileName) {
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.findings = [];
    this.contracts.clear();
    this.inheritanceGraph.clear();

    // First pass: collect all contracts and their members
    this.visit(ast);

    // Second pass: analyze inheritance and detect shadowing
    this.analyzeShadowing();

    return this.findings;
  }

  visitContractDefinition(node) {
    const contractName = node.name;

    // Collect state variables
    const stateVars = [];
    const functions = [];

    if (node.subNodes) {
      node.subNodes.forEach(subNode => {
        if (subNode.type === 'StateVariableDeclaration') {
          subNode.variables.forEach(variable => {
            stateVars.push({
              name: variable.name,
              loc: variable.loc,
              visibility: variable.visibility
            });
          });
        } else if (subNode.type === 'FunctionDefinition') {
          functions.push({
            name: subNode.name,
            loc: subNode.loc,
            visibility: subNode.visibility,
            isConstructor: subNode.isConstructor
          });
        }
      });
    }

    this.contracts.set(contractName, {
      name: contractName,
      stateVars,
      functions,
      loc: node.loc
    });

    // Build inheritance graph
    const baseContracts = [];
    if (node.baseContracts && node.baseContracts.length > 0) {
      node.baseContracts.forEach(base => {
        const baseName = base.baseName.namePath;
        baseContracts.push(baseName);
      });
    }
    this.inheritanceGraph.set(contractName, baseContracts);
  }

  analyzeShadowing() {
    // Check each contract for shadowing issues
    for (const [contractName, contract] of this.contracts) {
      const parents = this.getAllParents(contractName);

      // Check state variable shadowing
      contract.stateVars.forEach(stateVar => {
        parents.forEach(parentName => {
          const parent = this.contracts.get(parentName);
          if (parent) {
            const shadowedVar = parent.stateVars.find(v => v.name === stateVar.name);
            if (shadowedVar) {
              this.addFinding({
                title: 'State Variable Shadowing Detected',
                description: `State variable '${stateVar.name}' in contract '${contractName}' shadows the same variable in parent contract '${parentName}'. This can lead to confusion and unexpected behavior as both variables exist but refer to different storage slots.`,
                location: `Contract: ${contractName}`,
                line: stateVar.loc ? stateVar.loc.start.line : 0,
                column: stateVar.loc ? stateVar.loc.start.column : 0,
                code: this.getCodeSnippet(stateVar.loc),
                severity: 'HIGH',
                recommendation: `Rename the state variable '${stateVar.name}' in '${contractName}' to avoid shadowing. Consider using a more specific name or removing the duplicate declaration.`,
                references: [
                  'https://swcregistry.io/docs/SWC-119',
                  'https://github.com/crytic/slither/wiki/Detector-Documentation#state-variable-shadowing'
                ]
              });
            }
          }
        });
      });

      // Check function shadowing (non-overridden functions)
      contract.functions.forEach(func => {
        if (func.isConstructor || !func.name) return;

        parents.forEach(parentName => {
          const parent = this.contracts.get(parentName);
          if (parent) {
            const shadowedFunc = parent.functions.find(f =>
              f.name === func.name && !f.isConstructor && f.name
            );

            if (shadowedFunc) {
              // Check if it's intentional override (has virtual/override keywords)
              const codeSnippet = this.getCodeSnippet(func.loc);
              const isIntentionalOverride = codeSnippet.includes('override') ||
                                           codeSnippet.includes('virtual');

              if (!isIntentionalOverride) {
                this.addFinding({
                  title: 'Function Shadowing Without Override',
                  description: `Function '${func.name}' in contract '${contractName}' shadows function in parent contract '${parentName}' but is not marked with 'override'. This may indicate unintentional shadowing.`,
                  location: `Contract: ${contractName}, Function: ${func.name}`,
                  line: func.loc ? func.loc.start.line : 0,
                  column: func.loc ? func.loc.start.column : 0,
                  code: codeSnippet,
                  severity: 'MEDIUM',
                  recommendation: `If shadowing is intentional, mark the function with 'override' keyword. Otherwise, rename the function to avoid shadowing.`,
                  references: [
                    'https://docs.soliditylang.org/en/latest/contracts.html#function-overriding'
                  ]
                });
              }
            }
          }
        });
      });
    }
  }

  getAllParents(contractName, visited = new Set()) {
    if (visited.has(contractName)) return [];
    visited.add(contractName);

    const parents = this.inheritanceGraph.get(contractName) || [];
    const allParents = [...parents];

    parents.forEach(parent => {
      allParents.push(...this.getAllParents(parent, visited));
    });

    return [...new Set(allParents)];
  }
}

module.exports = ShadowingDetector;
