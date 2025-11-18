// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Production-grade vulnerability test contract
 * Tests flash loan, signature replay, precision loss, and DoS detectors
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract VulnerableDeFiProtocol {
    mapping(address => uint256) public stakes;
    mapping(address => uint256) public rewards;
    address[] public stakers;

    IERC20 public token;
    address public admin;

    uint256 public totalStaked;
    uint256 public rewardRate = 5; // 5%

    constructor(address _token) {
        token = IERC20(_token);
        admin = msg.sender;
    }

    // VULNERABILITY: Balance-based access control (Flash Loan Attack)
    function governanceVote(address proposal) public {
        require(token.balanceOf(msg.sender) > 1000 ether, "Insufficient balance");
        // Attacker can use flash loan to temporarily boost balance
        // Execute privileged governance action
    }

    // VULNERABILITY: Spot price manipulation
    function calculateReward(address user, uint256 reserve0, uint256 reserve1) public view returns (uint256) {
        // Using spot price from DEX reserves - vulnerable to flash loan manipulation
        uint256 price = (reserve0 * 1e18) / reserve1;
        return stakes[user] * price / 1e18;
    }

    // VULNERABILITY: Signature replay - missing nonce and chainId
    function permitWithdraw(uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, amount));
        address signer = ecrecover(hash, v, r, s);
        require(signer == admin, "Invalid signature");
        // Missing nonce - signature can be replayed!
        // Missing chainId - can be replayed on other chains!
        payable(msg.sender).transfer(amount);
    }

    // VULNERABILITY: Division before multiplication (Precision Loss)
    function distributeFees(uint256 totalFees) public {
        for (uint256 i = 0; i < stakers.length; i++) {
            // WRONG: divides first, loses precision
            uint256 share = (stakes[stakers[i]] / totalStaked) * totalFees;
            rewards[stakers[i]] += share;
        }
    }

    // VULNERABILITY: Percentage calculation without scaling
    function calculateFee(uint256 amount) public view returns (uint256) {
        // Division by 100 causes precision loss for small amounts
        return (amount * rewardRate) / 100;
    }

    // VULNERABILITY: Unsafe downcasting
    function setSmallValue(uint256 largeValue) public {
        uint64 small = uint64(largeValue); // Can overflow silently!
        // Use small value...
    }

    // VULNERABILITY: Unbounded loop over storage (DoS)
    function distributeRewardsToAll() public {
        // As stakers array grows, this becomes impossible to execute
        for (uint256 i = 0; i < stakers.length; i++) {
            uint256 reward = calculateReward(stakers[i], 0, 0);
            rewards[stakers[i]] += reward;
        }
    }

    // VULNERABILITY: External calls in loop (Gas Griefing)
    function batchTransfer(address[] memory recipients, uint256[] memory amounts) public {
        for (uint256 i = 0; i < recipients.length; i++) {
            // External call in loop - one failure reverts all
            token.transfer(recipients[i], amounts[i]);
        }
    }

    // VULNERABILITY: Unbounded array growth
    function addStaker(address staker) public {
        stakers.push(staker); // No size limit - can grow unbounded
        stakes[staker] = msg.value;
    }

    // VULNERABILITY: Balance manipulation
    function depositBasedOnBalance() public payable {
        // Calculates based on contract balance - can be manipulated
        uint256 bonus = address(this).balance / 100;
        stakes[msg.sender] += msg.value + bonus;
    }

    // VULNERABILITY: Owner-dependent critical function
    function emergencyShutdown() public {
        require(msg.sender == admin, "Only admin");
        // If admin key is lost, contract is bricked forever
        selfdestruct(payable(admin));
    }

    // Production-grade exploit scenario
    function flashLoanExploit() external {
        // 1. Attacker takes flash loan of 10M tokens
        // 2. Calls governanceVote() with inflated balance
        // 3. Executes malicious proposal
        // 4. Repays flash loan
        // Total cost: only flash loan fee (~0.09%)
    }

    receive() external payable {}
}

/**
 * Example Flash Loan Attack Vector:
 *
 * 1. Attacker borrows 10,000,000 USDC via flash loan
 * 2. Attacker's balanceOf() temporarily shows 10M USDC
 * 3. Calls governanceVote() which checks balanceOf()
 * 4. Passes governance check and executes privileged action
 * 5. Repays flash loan (cost: 0.09% = $9,000)
 * 6. Profit: Gained governance control for $9k
 *
 * Fix: Use snapshot-based voting or time-weighted balances
 */

/**
 * Example Signature Replay Attack:
 *
 * 1. Admin signs a permitWithdraw for Alice: 100 ETH
 * 2. Alice uses signature to withdraw 100 ETH
 * 3. Alice replays same signature multiple times (no nonce!)
 * 4. Alice drains the contract
 * 5. Alice also uses same signature on testnet, L2s (no chainId!)
 *
 * Fix: Include nonce and chainId in signed message
 */

/**
 * Example Precision Loss Exploit:
 *
 * Contract has 1000 ETH in fees to distribute
 * Alice has 1 wei staked, Bob has 1000 ETH staked
 * Total staked: 1000 ETH + 1 wei
 *
 * Alice's share = (1 / 1000000000000000000001) * 1000 ETH
 *                = 0 (rounds down to zero!)
 *
 * Alice receives nothing due to precision loss
 * Multiply first: (1 * 1000 ETH) / total = correct tiny amount
 */
