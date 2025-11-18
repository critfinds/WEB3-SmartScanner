// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/**
 * @title VulnerableContract
 * @dev Example contract with multiple vulnerabilities for testing WEB3CRIT-Scanner
 * WARNING: DO NOT USE IN PRODUCTION - FOR TESTING ONLY
 */
contract VulnerableContract {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalSupply;

    // Missing access control - anyone can set owner!
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    // Reentrancy vulnerability - external call before state change
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0; // State change AFTER external call - VULNERABLE!
    }

    // Unchecked external call
    function unsafeSend(address payable recipient, uint256 amount) public {
        recipient.send(amount); // Return value not checked!
    }

    // Timestamp dependence for randomness
    function weakRandom() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
    }

    // Integer overflow (Solidity 0.7.0 doesn't have built-in checks)
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b; // No SafeMath!
    }

    // Dangerous delegatecall with user input
    function execute(address target, bytes memory data) public {
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    // Unprotected selfdestruct
    function destroy(address payable recipient) public {
        selfdestruct(recipient); // No access control!
    }

    // Missing zero address validation
    function transferOwnership(address newOwner) public {
        owner = newOwner; // Should check newOwner != address(0)
    }

    // Division before multiplication - precision loss
    function calculateReward(uint256 amount, uint256 rate, uint256 multiplier)
        public
        pure
        returns (uint256)
    {
        return (amount / rate) * multiplier; // Should be (amount * multiplier) / rate
    }

    // Strict equality with balance
    function checkBalance() public view returns (bool) {
        return address(this).balance == 10 ether; // Vulnerable to forceful ether sending
    }

    // Front-runnable price update
    function setPrice(uint256 newPrice) public {
        totalSupply = newPrice; // Can be front-run
    }

    // Receive function without restrictions
    receive() external payable {
        // Accepts all ether without validation
    }

    // Potential unbounded loop
    address[] public users;

    function distributeRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            // Could run out of gas if users array is too large
            balances[users[i]] += 100;
        }
    }
}
