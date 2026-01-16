// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Vulnerable Signature Replay Examples
 */

// VULNERABLE: Missing nonce protection
contract SignatureReplayNoNonce {
    mapping(address => uint256) public balances;
    
    function permitTransfer(
        address from,
        address to,
        uint256 amount,
        bytes memory signature
    ) public {
        // No nonce - signature can be replayed
        address signer = recoverSigner(from, to, amount, signature);
        require(signer == from, "Invalid signature");
        
        balances[from] -= amount;
        balances[to] += amount;
    }
    
    function recoverSigner(
        address from,
        address to,
        uint256 amount,
        bytes memory sig
    ) internal pure returns (address) {
        bytes32 hash = keccak256(abi.encodePacked(from, to, amount));
        // Simplified - real implementation would use ecrecover
        return address(0);
    }
}

// VULNERABLE: Missing expiration
contract SignatureReplayNoExpiration {
    mapping(address => uint256) public balances;
    
    function permitTransfer(
        address from,
        address to,
        uint256 amount,
        bytes memory signature
    ) public {
        // No deadline/expiration - old signatures remain valid
        address signer = recoverSigner(from, to, amount, signature);
        require(signer == from, "Invalid signature");
        
        balances[from] -= amount;
        balances[to] += amount;
    }
    
    function recoverSigner(
        address from,
        address to,
        uint256 amount,
        bytes memory sig
    ) internal pure returns (address) {
        bytes32 hash = keccak256(abi.encodePacked(from, to, amount));
        return address(0);
    }
}

