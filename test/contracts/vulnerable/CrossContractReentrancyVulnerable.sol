// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Vulnerable Cross-Contract Reentrancy Examples
 */

interface IContractA {
    function withdraw() external;
}

interface IContractB {
    function deposit() external payable;
}

// VULNERABLE: Cross-contract reentrancy
contract CrossContractReentrancy {
    mapping(address => uint256) public balances;
    IContractA public contractA;
    IContractB public contractB;
    
    function setContracts(address _a, address _b) public {
        contractA = IContractA(_a);
        contractB = IContractB(_b);
    }
    
    function withdrawFromBoth() public {
        uint256 balanceA = balances[msg.sender];
        uint256 balanceB = balances[msg.sender];
        
        // External call to contract A
        contractA.withdraw();
        
        // State update after external call - vulnerable
        balances[msg.sender] = 0;
        
        // Another external call
        contractB.deposit{value: balanceB}();
    }
}

// VULNERABLE: Delegatecall reentrancy
contract DelegatecallReentrancy {
    address public implementation;
    mapping(address => uint256) public balances;
    
    function upgradeAndCall(address newImpl, bytes memory data) public {
        implementation = newImpl;
        // Delegatecall can re-enter
        (bool success, ) = implementation.delegatecall(data);
        require(success);
        
        // State update after delegatecall
        balances[msg.sender] = 0;
    }
}

