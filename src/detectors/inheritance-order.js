const BaseDetector = require('./base-detector');

/**
 * Incorrect Inheritance Order Detector
 * Detects incorrect C3 linearization order in multiple inheritance
 * Solidity uses C3 linearization for inheritance resolution
 */
class InheritanceOrderDetector extends BaseDetector {
  constructor() {
    super(
      'Incorrect Inheritance Order',
      'Detects potential issues with multiple inheritance order that may cause unexpected behavior',
      'MEDIUM'
    );
    this.contracts = new Map();
    this.inheritanceGraph = new Map();
  }

  async detect(ast, sourceCode, fileName) {
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.findings = [];
    this.contracts.clear();
    this.inheritanceGraph.clear();

    // Build inheritance graph
    this.visit(ast);

    // Analyze inheritance order
    this.analyzeInheritanceOrder();

    return this.findings;
  }

  visitContractDefinition(node) {
    const contractName = node.name;

    // Store contract info
    this.contracts.set(contractName, {
      name: contractName,
      kind: node.kind, // contract, interface, library
      loc: node.loc,
      baseContracts: []
    });

    // Build inheritance list
    const baseContracts = [];
    if (node.baseContracts && node.baseContracts.length > 0) {
      node.baseContracts.forEach((base, index) => {
        const baseName = base.baseName.namePath;
        baseContracts.push({
          name: baseName,
          index: index,
          loc: base.loc
        });
      });
    }

    this.contracts.get(contractName).baseContracts = baseContracts;
    this.inheritanceGraph.set(contractName, baseContracts.map(b => b.name));
  }

  analyzeInheritanceOrder() {
    for (const [contractName, contract] of this.contracts) {
      // Only check contracts with multiple inheritance
      if (contract.baseContracts.length < 2) continue;

      // Check for common inheritance order issues
      this.checkInheritanceIssues(contractName, contract);
    }
  }

  checkInheritanceIssues(contractName, contract) {
    const bases = contract.baseContracts;

    // Issue 1: Most derived should be last (most specific inheritance first)
    // In Solidity, the order should be: most base -> most derived
    // Example: contract C is A, B (B should be more derived than A)

    // Issue 2: Check if same base appears multiple times in hierarchy
    const baseNames = bases.map(b => b.name);
    const uniqueBases = new Set(baseNames);

    if (baseNames.length !== uniqueBases.size) {
      // Duplicate inheritance
      const duplicates = baseNames.filter((name, index) =>
        baseNames.indexOf(name) !== index
      );

      duplicates.forEach(dupName => {
        const base = bases.find(b => b.name === dupName);
        this.addFinding({
          title: 'Duplicate Inheritance',
          description: `Contract '${contractName}' inherits from '${dupName}' multiple times. This can lead to ambiguity and unexpected behavior in function resolution.`,
          location: `Contract: ${contractName}`,
          line: contract.loc ? contract.loc.start.line : 0,
          column: contract.loc ? contract.loc.start.column : 0,
          code: this.getCodeSnippet(contract.loc),
          severity: 'HIGH',
          recommendation: `Remove duplicate inheritance of '${dupName}'. Each base contract should only be inherited once.`,
          references: [
            'https://docs.soliditylang.org/en/latest/contracts.html#multiple-inheritance-and-linearization'
          ]
        });
      });
    }

    // Issue 3: Check for diamond inheritance without proper handling
    const allAncestors = new Map(); // ancestor -> contracts that inherit from it
    bases.forEach(base => {
      const ancestors = this.getAllAncestors(base.name);
      ancestors.forEach(ancestor => {
        if (!allAncestors.has(ancestor)) {
          allAncestors.set(ancestor, []);
        }
        allAncestors.get(ancestor).push(base.name);
      });
    });

    // Find common ancestors (diamond pattern)
    for (const [ancestor, inheritingContracts] of allAncestors) {
      if (inheritingContracts.length > 1) {
        this.addFinding({
          title: 'Diamond Inheritance Pattern Detected',
          description: `Contract '${contractName}' has a diamond inheritance pattern where '${ancestor}' is inherited through multiple paths: ${inheritingContracts.join(', ')}. This requires careful attention to ensure correct initialization and function resolution.`,
          location: `Contract: ${contractName}`,
          line: contract.loc ? contract.loc.start.line : 0,
          column: contract.loc ? contract.loc.start.column : 0,
          code: this.getCodeSnippet(contract.loc),
          severity: 'MEDIUM',
          recommendation: `Verify that the inheritance order follows C3 linearization correctly. Ensure base contract constructors are called in the correct order. Consider simplifying the inheritance hierarchy if possible.`,
          references: [
            'https://docs.soliditylang.org/en/latest/contracts.html#multiple-inheritance-and-linearization',
            'https://en.wikipedia.org/wiki/C3_linearization'
          ]
        });
      }
    }

    // Issue 4: Check for interface/library positioning
    // Best practice: interfaces first, then libraries, then contracts
    let lastContractType = null;
    let hasOrderIssue = false;

    for (let i = 0; i < bases.length; i++) {
      const baseName = bases[i].name;
      const baseContract = this.contracts.get(baseName);

      if (baseContract) {
        const currentType = baseContract.kind;

        // Check if order is violated
        if (lastContractType === 'contract' &&
            (currentType === 'interface' || currentType === 'library')) {
          hasOrderIssue = true;
          break;
        }

        if (lastContractType === 'library' && currentType === 'interface') {
          hasOrderIssue = true;
          break;
        }

        lastContractType = currentType;
      }
    }

    if (hasOrderIssue) {
      this.addFinding({
        title: 'Suboptimal Inheritance Order',
        description: `Contract '${contractName}' has a suboptimal inheritance order. Best practice is to list base contracts as: interfaces first, then libraries, then contracts (from most general to most specific).`,
        location: `Contract: ${contractName}`,
        line: contract.loc ? contract.loc.start.line : 0,
        column: contract.loc ? contract.loc.start.column : 0,
        code: this.getCodeSnippet(contract.loc),
        severity: 'LOW',
        recommendation: 'Reorder base contracts to follow best practices: interfaces, then libraries, then contracts.',
        references: [
          'https://docs.soliditylang.org/en/latest/style-guide.html#order-of-layout'
        ]
      });
    }
  }

  getAllAncestors(contractName, visited = new Set()) {
    if (visited.has(contractName)) return [];
    visited.add(contractName);

    const ancestors = [];
    const bases = this.inheritanceGraph.get(contractName) || [];

    bases.forEach(base => {
      ancestors.push(base);
      ancestors.push(...this.getAllAncestors(base, visited));
    });

    return ancestors;
  }
}

module.exports = InheritanceOrderDetector;
