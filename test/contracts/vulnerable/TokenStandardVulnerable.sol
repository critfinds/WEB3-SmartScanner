// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Vulnerable Token Standard Compliance Examples
 */

// VULNERABLE: ERC20 missing Transfer event
contract ERC20NoTransferEvent {
    mapping(address => uint256) public balances;
    
    function transfer(address to, uint256 amount) public returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        // Missing: emit Transfer(msg.sender, to, amount);
        return true;
    }
}

// VULNERABLE: ERC20 missing Approval event
contract ERC20NoApprovalEvent {
    mapping(address => mapping(address => uint256)) public allowance;
    
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        // Missing: emit Approval(msg.sender, spender, amount);
        return true;
    }
}

// VULNERABLE: ERC721 missing required functions
contract ERC721Incomplete {
    // Missing: ownerOf, safeTransferFrom, setApprovalForAll, etc.
    
    function balanceOf(address owner) public view returns (uint256) {
        return 0;
    }
}

