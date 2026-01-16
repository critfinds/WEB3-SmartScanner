// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DeprecatedFunctionsVulnerable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function changeOwner(address _newOwner) public {
        // Insecure authorization using tx.origin
        if (tx.origin == owner) {
            owner = _newOwner;
        }
    }

    function close() public {
        // Usage of selfdestruct
        selfdestruct(payable(owner));
    }

    function insecureRandomness() public view returns (uint) {
        // Insecure randomness from block.timestamp
        return uint(keccak256(abi.encodePacked(block.timestamp)));
    }
}
