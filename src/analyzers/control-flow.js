const parser = require('@solidity-parser/parser');

/**
 * Control Flow Graph (CFG) Analyzer (Rewritten)
 * Tracks execution paths, function calls, and state changes using the official parser visitor
 */
class ControlFlowAnalyzer {
  constructor() {
    this.reset();
  }

  analyze(ast, sourceCode) {
    this.sourceCode = sourceCode;
    this.reset();

    let currentContract = null;
    let currentFunction = null;
    let currentModifier = null;

    parser.visit(ast, {
      ContractDefinition: node => {
        currentContract = {
          name: node.name,
          kind: node.kind,
          baseContracts: node.baseContracts || [],
          stateVariables: [],
          functions: [],
          modifiers: []
        };
        this.contracts.set(node.name, currentContract);
      },

      'ContractDefinition:exit': () => {
        currentContract = null;
      },

      ModifierDefinition: node => {
        if (!currentContract) return;
        const modKey = `${currentContract.name}.${node.name}`;
        currentModifier = {
          name: node.name,
          contract: currentContract.name,
          node: node,
          requireStatements: [],
          checksAccess: false,
          checksOwnership: false,
          checksRole: false
        };
        this.modifiers.set(modKey, currentModifier);
        currentContract.modifiers.push(node.name);
      },

      'ModifierDefinition:exit': () => {
        // Analyze collected require statements to determine access control type
        if (currentModifier) {
          this.analyzeModifierAccessControl(currentModifier);
        }
        currentModifier = null;
      },

      FunctionDefinition: node => {
        if (!currentContract) return;
        const funcName = node.name || (node.isConstructor ? 'constructor' : (node.isReceiveEther ? 'receive' : 'fallback'));
        const funcKey = `${currentContract.name}.${funcName}`;
        currentFunction = {
          name: funcName,
          contract: currentContract.name,
          visibility: node.visibility || 'public',
          stateMutability: node.stateMutability,
          modifiers: (node.modifiers || []).map(m => m.name),
          parameters: (node.parameters || []).map(p => ({
            name: p.name,
            type: this.getTypeName(p.typeName)
          })),
          isConstructor: node.isConstructor,
          isFallback: !node.name && !node.isConstructor && !node.isReceiveEther,
          isReceive: node.isReceiveEther,
          externalCalls: [],
          stateWrites: [],
          stateReads: [],
          node: node
        };
        this.functions.set(funcKey, currentFunction);
        currentContract.functions.push(funcName);
      },

      'FunctionDefinition:exit': () => {
        currentFunction = null;
      },

      StateVariableDeclaration: node => {
        if (!currentContract) return;
        node.variables.forEach(variable => {
          const varInfo = {
            name: variable.name,
            type: this.getTypeName(variable.typeName),
            visibility: variable.visibility || 'internal',
            isConstant: variable.isDeclaredConst,
            isImmutable: variable.isImmutable,
            contract: currentContract.name
          };
          this.stateVariables.set(`${currentContract.name}.${variable.name}`, varInfo);
          currentContract.stateVariables.push(variable.name);
        });
      },

      FunctionCall: node => {
        // Track require/assert statements in modifiers
        if (currentModifier && node.expression && node.expression.type === 'Identifier') {
          const funcName = node.expression.name;
          if (funcName === 'require' || funcName === 'assert') {
            const requireCode = this.getSourceFromNode(node);
            currentModifier.requireStatements.push(requireCode);
          }
        }

        if (!currentFunction) return;

        // Handle direct MemberAccess: .send(), .transfer()
        if (node.expression && node.expression.type === 'MemberAccess') {
          const memberName = node.expression.memberName;
          if (['call', 'delegatecall', 'staticcall', 'send', 'transfer'].includes(memberName)) {
            currentFunction.externalCalls.push({
              type: memberName,
              target: this.getSourceFromNode(node.expression.expression),
              loc: node.loc
            });
          }
        }

        // Handle NameValueExpression: .call{value: x}(), .call{gas: x}()
        if (node.expression && node.expression.type === 'NameValueExpression') {
          const innerExpr = node.expression.expression;
          if (innerExpr && innerExpr.type === 'MemberAccess') {
            const memberName = innerExpr.memberName;
            if (['call', 'delegatecall', 'staticcall'].includes(memberName)) {
              currentFunction.externalCalls.push({
                type: memberName,
                target: this.getSourceFromNode(innerExpr.expression),
                loc: node.loc
              });
            }
          }
        }
      },

      Identifier: node => {
        // Track state variable reads
        if (currentFunction && currentContract && this.isStateVariable(node, currentContract.name)) {
          currentFunction.stateReads.push({
            variable: node.name,
            loc: node.loc
          });
        }
      },

      BinaryOperation: node => {
        if (!currentFunction || !currentContract) return;
        // Track state writes for assignment operators
        if (node.operator === '=' || node.operator === '+=' || node.operator === '-=' ||
            node.operator === '*=' || node.operator === '/=') {
          if (this.isStateVariable(node.left, currentContract.name)) {
            currentFunction.stateWrites.push({
              variable: this.getVariableName(node.left),
              loc: node.loc
            });
          }
        }
      }
    });

    return {
      contracts: this.contracts,
      functions: this.functions,
      modifiers: this.modifiers,
      stateVariables: this.stateVariables
    };
  }

  /**
   * Analyze modifier require statements to determine what kind of access control it provides
   */
  analyzeModifierAccessControl(modInfo) {
    const allRequires = modInfo.requireStatements.join(' ').toLowerCase();

    // Check for ownership patterns
    if (allRequires.includes('msg.sender') &&
        (allRequires.includes('owner') || allRequires.includes('admin'))) {
      modInfo.checksOwnership = true;
      modInfo.checksAccess = true;
    }

    // Check for role-based patterns
    if (allRequires.includes('hasrole') || allRequires.includes('role') ||
        allRequires.includes('isauthorized') || allRequires.includes('onlyrole')) {
      modInfo.checksRole = true;
      modInfo.checksAccess = true;
    }

    // Check for general access control patterns
    if (allRequires.includes('msg.sender') || allRequires.includes('tx.origin')) {
      modInfo.checksAccess = true;
    }

    // Check for reentrancy guard patterns
    if (allRequires.includes('_status') || allRequires.includes('locked') ||
        allRequires.includes('_notentered') || allRequires.includes('reentrancy')) {
      modInfo.checksReentrancy = true;
    }

    // Check modifier name for hints
    const modNameLower = modInfo.name.toLowerCase();
    if (modNameLower.includes('onlyowner') || modNameLower.includes('onlyadmin')) {
      modInfo.checksOwnership = true;
      modInfo.checksAccess = true;
    }
    if (modNameLower.includes('nonreentrant') || modNameLower.includes('lock')) {
      modInfo.checksReentrancy = true;
    }
  }

  reset() {
    this.contracts = new Map();
    this.functions = new Map();
    this.modifiers = new Map();
    this.stateVariables = new Map();
  }

  isStateVariable(node, currentContract) {
    const varName = this.getVariableName(node);
    return this.stateVariables.has(`${currentContract}.${varName}`);
  }

  getVariableName(node) {
    if (node.type === 'Identifier') return node.name;
    if (node.type === 'MemberAccess') return node.memberName;
    if (node.type === 'IndexAccess') return this.getVariableName(node.base);
    return null;
  }

  getSourceFromNode(node) {
    if (!node || !node.range) return '';
    return this.sourceCode.substring(node.range[0], node.range[1] + 1);
  }


  getTypeName(typeNode) {
    if (!typeNode) return 'unknown';
    if (typeNode.type === 'ElementaryTypeName') return typeNode.name;
    if (typeNode.type === 'UserDefinedTypeName') return typeNode.namePath;
    if (typeNode.type === 'Mapping') return 'mapping';
    return 'complex';
  }
}

module.exports = ControlFlowAnalyzer;
