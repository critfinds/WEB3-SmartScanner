// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Vulnerable TOCTOU Examples
 */

// VULNERABLE: Balance check before external call
contract TOCTOUBalance {
    mapping(address => uint256) public balances;
    
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        
        // External call before state update
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success);
        
        // State update after external call
        balances[msg.sender] = 0;
    }
}

// VULNERABLE: Allowance check before external call
contract TOCTOUAllowance {
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public balances;
    
    function transferFrom(address from, address to, uint256 amount) public {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "Insufficient allowance");
        
        // External call before state update
        (bool success, ) = to.call("");
        require(success);
        
        // State update after external call
        allowance[from][msg.sender] -= amount;
        balances[from] -= amount;
        balances[to] += amount;
    }
}

