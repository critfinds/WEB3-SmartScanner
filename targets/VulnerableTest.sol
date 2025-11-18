// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Test contract with multiple vulnerabilities for scanner testing

contract BaseContract {
    uint256 public baseValue;

    function setBaseValue(uint256 _value) public virtual {
        baseValue = _value;
    }
}

contract VulnerableTest is BaseContract {
    // Shadowing issue
    uint256 public baseValue; // Shadows parent's baseValue

    mapping(address => uint256) public balances;
    address public owner;
    uint256 private unusedVariable; // Dead code

    event Transfer(address indexed from, address indexed to, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    // Missing access control modifier
    function setOwner(address newOwner) public {
        owner = newOwner; // Should emit event
    }

    // tx.origin vulnerability
    function authenticate() public {
        require(tx.origin == owner, "Not authorized");
    }

    // Reentrancy vulnerability
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0; // State change after external call
    }

    // User-controlled data to dangerous operation (taint analysis)
    function dangerousCall(address target, bytes memory data) public {
        target.call(data); // User controls both target and data
    }

    // User-controlled loop bound (DoS)
    function massProcess(uint256 iterations) public {
        for (uint256 i = 0; i < iterations; i++) {
            // User controls loop bound - can cause DoS
            balances[msg.sender] += 1;
        }
    }

    // Should be view but isn't (state mutability)
    function getBalance(address user) public returns (uint256) {
        return balances[user];
    }

    // Should be pure but isn't
    function calculateSum(uint256 a, uint256 b) public returns (uint256) {
        return a + b;
    }

    // Inline assembly usage
    function unsafeAssembly(uint256 value) public {
        assembly {
            sstore(0, value) // Direct storage manipulation
        }
    }

    // Unchecked external call
    function uncheckedSend(address payable recipient) public {
        recipient.send(1 ether); // Return value not checked
    }

    // Uninitialized storage pointer (pre-0.5.0 vulnerability pattern)
    struct User {
        address addr;
        uint256 balance;
    }

    mapping(uint256 => User) users;

    function uninitializedStorage() public {
        User storage user; // Uninitialized
        user.addr = msg.sender; // Writes to storage slot 0
    }

    // Missing event for critical operation
    function emergencyWithdraw() public {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
        // Should emit event
    }

    // Dead code - unused private function
    function unusedPrivateFunction() private {
        // Never called
    }

    // Timestamp dependence
    function timeBasedReward() public {
        require(block.timestamp % 15 == 0, "Wrong time");
        balances[msg.sender] += 100;
    }

    // User-controlled array index (taint analysis)
    uint256[] public data;

    function unsafeArrayAccess(uint256 index) public returns (uint256) {
        return data[index]; // No bounds checking
    }

    // Delegatecall to user-controlled address
    function unsafeDelegatecall(address target) public {
        target.delegatecall("");
    }

    receive() external payable {}
}

// Contract with inheritance issues
contract Parent1 {
    uint256 public value1;
}

contract Parent2 {
    uint256 public value2;
}

// Diamond inheritance pattern
contract Child is Parent1, Parent2 {
    // Potential inheritance order issues
}
