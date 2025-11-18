const BaseDetector = require('./base-detector');

class AccessControlDetector extends BaseDetector {
  constructor() {
    super(
      'Access Control Vulnerability',
      'Detects missing or improper access control modifiers on sensitive functions',
      'CRITICAL'
    );
    this.contractOwner = null;
    this.accessModifiers = new Set();
  }

  visitContractDefinition(node) {
    this.contractOwner = null;
    this.accessModifiers.clear();

    // Check for owner/admin pattern
    if (node.subNodes) {
      node.subNodes.forEach(subNode => {
        if (subNode.type === 'StateVariableDeclaration') {
          this.checkForOwnerVariable(subNode);
        }
        if (subNode.type === 'ModifierDefinition') {
          this.accessModifiers.add(subNode.name);
        }
      });
    }
  }

  checkForOwnerVariable(node) {
    if (node.variables) {
      node.variables.forEach(variable => {
        const varName = variable.name ? variable.name.toLowerCase() : '';
        if (varName.includes('owner') || varName.includes('admin')) {
          this.contractOwner = variable.name;
        }
      });
    }
  }

  visitFunctionDefinition(node) {
    const functionName = node.name || '';
    const visibility = node.visibility || 'public';

    // Check for sensitive operations without access control
    if (this.isSensitiveFunction(functionName, node)) {
      const hasAccessControl = this.checkAccessControl(node);

      if (!hasAccessControl) {
        this.addFinding({
          title: 'Missing Access Control',
          description: `Sensitive function '${functionName}' is ${visibility} but lacks access control modifiers. This allows any address to call critical functionality.`,
          location: `Function: ${functionName}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: this.getCodeSnippet(node.loc),
          recommendation: 'Add access control modifiers (e.g., onlyOwner, onlyAdmin) to restrict who can call this function. Use OpenZeppelin\'s Ownable or AccessControl contracts.',
          references: [
            'https://docs.openzeppelin.com/contracts/4.x/access-control',
            'https://swcregistry.io/docs/SWC-105'
          ]
        });
      }
    }

    // Check for functions that modify owner without proper checks
    if (this.modifiesOwnership(node)) {
      const hasStrictControl = this.hasStrictOwnershipControl(node);

      if (!hasStrictControl) {
        this.addFinding({
          title: 'Unsafe Ownership Transfer',
          description: `Function '${functionName}' can transfer ownership without adequate protection. This could lead to permanent loss of contract control.`,
          location: `Function: ${functionName}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: this.getCodeSnippet(node.loc),
          recommendation: 'Implement two-step ownership transfer: propose new owner, then require new owner to accept. See OpenZeppelin\'s Ownable2Step.',
          references: [
            'https://docs.openzeppelin.com/contracts/4.x/api/access#Ownable2Step'
          ]
        });
      }
    }

    // Check for default visibility
    if (!visibility || visibility === 'public') {
      const bodyCode = node.body ? this.getCodeSnippet(node.body.loc) : '';

      if (this.hasStateModification(bodyCode) && !functionName.startsWith('_')) {
        this.addFinding({
          title: 'Public Function Modifies State',
          description: `Function '${functionName}' has default public visibility and modifies contract state. Ensure this is intentional.`,
          location: `Function: ${functionName}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: this.getCodeSnippet(node.loc),
          recommendation: 'Explicitly specify function visibility. If the function should not be externally callable, mark it as internal or private.',
          references: [
            'https://swcregistry.io/docs/SWC-100'
          ]
        });
      }
    }
  }

  isSensitiveFunction(name, node) {
    const sensitiveFunctionNames = [
      'withdraw', 'transfer', 'send', 'mint', 'burn',
      'destroy', 'kill', 'selfdestruct', 'suicide',
      'setowner', 'transferownership', 'changeowner',
      'pause', 'unpause', 'emergency',
      'upgrade', 'initialize', 'setimplementation',
      'addadmin', 'removeadmin', 'grantRole', 'revokeRole'
    ];

    const lowerName = name.toLowerCase().replace(/[_\s]/g, '');

    if (sensitiveFunctionNames.some(sensitive => lowerName.includes(sensitive))) {
      return true;
    }

    // Check if function body contains sensitive operations
    if (node.body) {
      const code = this.getCodeSnippet(node.body.loc);
      if (code.includes('selfdestruct(') ||
          code.includes('.transfer(') ||
          code.includes('.call{value:') ||
          code.includes('delegatecall(')) {
        return true;
      }
    }

    return false;
  }

  checkAccessControl(node) {
    if (!node.modifiers || node.modifiers.length === 0) {
      return false;
    }

    const accessControlModifiers = [
      'onlyowner', 'onlyadmin', 'onlyauthorized', 'onlyminter',
      'onlygovernance', 'onlycontroller', 'restricted', 'authorized',
      'onlyrole'
    ];

    return node.modifiers.some(modifier => {
      const modifierName = (modifier.name || '').toLowerCase().replace(/[_\s]/g, '');
      return accessControlModifiers.some(acm => modifierName.includes(acm));
    });
  }

  modifiesOwnership(node) {
    const functionName = (node.name || '').toLowerCase();

    if (functionName.includes('transferownership') ||
        functionName.includes('setowner') ||
        functionName.includes('changeowner')) {
      return true;
    }

    if (node.body && this.contractOwner) {
      const code = this.getCodeSnippet(node.body.loc);
      return code.includes(this.contractOwner + ' =') ||
             code.includes(this.contractOwner + '=');
    }

    return false;
  }

  hasStrictOwnershipControl(node) {
    // Check for two-step transfer pattern
    const code = node.body ? this.getCodeSnippet(node.body.loc) : '';

    // Look for pending owner pattern
    return code.includes('pendingOwner') ||
           code.includes('proposedOwner') ||
           code.includes('acceptOwnership');
  }

  hasStateModification(code) {
    // Simple heuristic: contains assignment operator
    return code.includes(' = ') && !code.includes('memory') && !code.includes('calldata');
  }
}

module.exports = AccessControlDetector;
