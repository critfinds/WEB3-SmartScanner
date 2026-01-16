// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Vulnerable Proxy Contract Examples
 * These contracts demonstrate common proxy vulnerabilities
 */

// VULNERABLE: Unprotected initializer
contract UnprotectedInitializer {
    address public owner;
    bool public initialized;

    function initialize(address _owner) public {
        owner = _owner;  // No protection - can be called multiple times
        initialized = true;
    }
}

// VULNERABLE: UUPS without _authorizeUpgrade
contract UUPSWithoutAuthorization {
    address public implementation;
    
    function upgradeTo(address newImpl) public {
        // Missing _authorizeUpgrade check
        implementation = newImpl;
    }
}

// VULNERABLE: Unauthorized upgrade
contract UnauthorizedUpgrade {
    address public implementation;
    
    function upgrade(address newImpl) public {
        // No access control - anyone can upgrade
        implementation = newImpl;
    }
}

