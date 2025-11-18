const BaseDetector = require('./base-detector');

/**
 * Signature Replay Attack Detector
 * Detects missing nonce, chainId, and domain separator in signature verification
 * Critical for protocols using EIP-712, permits, meta-transactions
 */
class SignatureReplayDetector extends BaseDetector {
  constructor() {
    super(
      'Signature Replay Attack',
      'Detects signature verification vulnerable to replay attacks across chains or transactions',
      'CRITICAL'
    );
    this.currentFunction = null;
    this.currentContract = null;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'fallback';

    if (node.body && node.body.statements) {
      this.analyzeSignatureUsage(node);
    }
  }

  analyzeSignatureUsage(node) {
    const code = this.getCodeSnippet(node.loc);
    const statements = this.getAllStatements(node.body.statements);

    // Check if function uses signature verification
    const hasSignatureVerification = code.match(/ecrecover|v,\s*r,\s*s|ECDSA\.recover/i);

    if (hasSignatureVerification) {
      // Pattern 1: Missing nonce
      const missingNonce = this.checkMissingNonce(statements, code);
      if (missingNonce) {
        this.addFinding({
          title: 'Signature Replay: Missing Nonce',
          description: `Function '${this.currentFunction}' verifies signatures but does not include a nonce in the signed message. This allows attackers to replay the same signature multiple times, potentially draining funds or duplicating operations. This is a CRITICAL vulnerability for any signature-based operation.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: missingNonce.line,
          column: missingNonce.column,
          code: missingNonce.code,
          severity: 'CRITICAL',
          confidence: 'HIGH',
          recommendation: 'Include a nonce in the signed message and increment it after each use. Example: bytes32 hash = keccak256(abi.encodePacked(msg.sender, amount, nonces[msg.sender]++)); Verify the nonce is consumed atomically.',
          references: [
            'https://swcregistry.io/docs/SWC-121',
            'https://eips.ethereum.org/EIPS/eip-2612',
            'https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/EIP712.sol'
          ]
        });
      }

      // Pattern 2: Missing chainId
      const missingChainId = this.checkMissingChainId(statements, code);
      if (missingChainId) {
        this.addFinding({
          title: 'Signature Replay: Missing Chain ID',
          description: `Function '${this.currentFunction}' verifies signatures without including chain ID in the signed message. This allows cross-chain replay attacks where the same signature can be used on different networks (mainnet, testnets, L2s). Attackers can replay transactions on multiple chains.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: missingChainId.line,
          column: missingChainId.column,
          code: missingChainId.code,
          severity: 'CRITICAL',
          confidence: 'HIGH',
          recommendation: 'Include block.chainid in the signed message. Use EIP-712 domain separator. Example: bytes32 domainSeparator = keccak256(abi.encode(TYPE_HASH, name, version, block.chainid, address(this)));',
          references: [
            'https://eips.ethereum.org/EIPS/eip-712',
            'https://eips.ethereum.org/EIPS/eip-155',
            'https://github.com/ethereum/EIPs/issues/1344'
          ]
        });
      }

      // Pattern 3: Missing contract address
      const missingContractAddress = this.checkMissingContractAddress(statements, code);
      if (missingContractAddress) {
        this.addFinding({
          title: 'Signature Replay: Missing Contract Address',
          description: `Function '${this.currentFunction}' verifies signatures without binding them to this contract's address. Signatures can be replayed against other contracts with identical code, potentially affecting protocol forks or clones.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: missingContractAddress.line,
          column: missingContractAddress.column,
          code: missingContractAddress.code,
          severity: 'HIGH',
          confidence: 'MEDIUM',
          recommendation: 'Include address(this) in the signed message or use EIP-712 domain separator which includes the verifying contract address.',
          references: [
            'https://eips.ethereum.org/EIPS/eip-712'
          ]
        });
      }

      // Pattern 4: Signature not invalidated after use
      const signatureNotInvalidated = this.checkSignatureInvalidation(statements, code);
      if (signatureNotInvalidated) {
        this.addFinding({
          title: 'Signature Replay: Signature Not Invalidated',
          description: `Function '${this.currentFunction}' uses signature verification but does not store/invalidate used signatures or nonces. Even with nonce checks, if the nonce isn't properly consumed, signatures could be replayed.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: signatureNotInvalidated.line,
          column: signatureNotInvalidated.column,
          code: signatureNotInvalidated.code,
          severity: 'HIGH',
          confidence: 'MEDIUM',
          recommendation: 'Store used signatures in a mapping or increment nonces in storage. Example: require(!usedSignatures[signatureHash], "Signature already used"); usedSignatures[signatureHash] = true;',
          references: [
            'https://swcregistry.io/docs/SWC-121'
          ]
        });
      }

      // Pattern 5: Weak signature validation
      const weakValidation = this.checkWeakSignatureValidation(statements, code);
      if (weakValidation) {
        this.addFinding({
          title: 'Signature Replay: Weak Signature Validation',
          description: `Function '${this.currentFunction}' may have weak signature validation. Using raw ecrecover without proper checks can lead to signature malleability or accepting invalid signatures.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: weakValidation.line,
          column: weakValidation.column,
          code: weakValidation.code,
          severity: 'MEDIUM',
          confidence: 'LOW',
          recommendation: 'Use OpenZeppelin\'s ECDSA library which includes safety checks. Validate that recovered address is not address(0). Check s value is in lower half to prevent malleability.',
          references: [
            'https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol',
            'https://swcregistry.io/docs/SWC-117'
          ]
        });
      }
    }
  }

  checkMissingNonce(statements, fullCode) {
    const hasNonce = fullCode.match(/nonce/i);
    const hasEcrecover = fullCode.match(/ecrecover|ECDSA/i);

    if (hasEcrecover && !hasNonce) {
      // Find ecrecover statement
      for (const stmt of statements) {
        const code = this.getCodeSnippet(stmt.loc);
        if (code.match(/ecrecover|ECDSA/i)) {
          return {
            line: stmt.loc ? stmt.loc.start.line : 0,
            column: stmt.loc ? stmt.loc.start.column : 0,
            code: code
          };
        }
      }
    }
    return null;
  }

  checkMissingChainId(statements, fullCode) {
    const hasChainId = fullCode.match(/chainid|chainId/);
    const hasEcrecover = fullCode.match(/ecrecover|ECDSA/i);

    if (hasEcrecover && !hasChainId) {
      for (const stmt of statements) {
        const code = this.getCodeSnippet(stmt.loc);
        if (code.match(/ecrecover|ECDSA/i)) {
          return {
            line: stmt.loc ? stmt.loc.start.line : 0,
            column: stmt.loc ? stmt.loc.start.column : 0,
            code: code
          };
        }
      }
    }
    return null;
  }

  checkMissingContractAddress(statements, fullCode) {
    const hasContractAddress = fullCode.match(/address\(this\)|this\)/);
    const hasEcrecover = fullCode.match(/ecrecover|ECDSA/i);
    const hasDomainSeparator = fullCode.match(/DOMAIN_SEPARATOR|domainSeparator/);

    if (hasEcrecover && !hasContractAddress && !hasDomainSeparator) {
      for (const stmt of statements) {
        const code = this.getCodeSnippet(stmt.loc);
        if (code.match(/ecrecover|ECDSA/i)) {
          return {
            line: stmt.loc ? stmt.loc.start.line : 0,
            column: stmt.loc ? stmt.loc.start.column : 0,
            code: code
          };
        }
      }
    }
    return null;
  }

  checkSignatureInvalidation(statements, fullCode) {
    const hasEcrecover = fullCode.match(/ecrecover|ECDSA/i);
    const hasInvalidation = fullCode.match(/nonces\[.*\]\s*\+\+|usedSignatures|signatureUsed|_useNonce/i);

    if (hasEcrecover && !hasInvalidation) {
      for (const stmt of statements) {
        const code = this.getCodeSnippet(stmt.loc);
        if (code.match(/ecrecover|ECDSA/i)) {
          return {
            line: stmt.loc ? stmt.loc.start.line : 0,
            column: stmt.loc ? stmt.loc.start.column : 0,
            code: code
          };
        }
      }
    }
    return null;
  }

  checkWeakSignatureValidation(statements, fullCode) {
    // Check for raw ecrecover without ECDSA library
    if (fullCode.match(/ecrecover\s*\(/) && !fullCode.match(/ECDSA\.recover/)) {
      // Check if there's validation for address(0)
      if (!fullCode.match(/!= address\(0\)|!= 0x0/)) {
        for (const stmt of statements) {
          const code = this.getCodeSnippet(stmt.loc);
          if (code.match(/ecrecover\s*\(/)) {
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

module.exports = SignatureReplayDetector;
