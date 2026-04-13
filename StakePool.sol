// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// CONTRACT 3: StakePool
// Stale value pattern — userStake is a cached local variable
// captured before the external call and used in the post-call
// state write. Also has a classic balances window.
// Expected:
//   balances     — WRITTEN WINDOW risk
//   userStake    — STALE VALUE risk

contract StakePool {

    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;
    uint256 public totalStaked;

    function stake() external payable {
        balances[msg.sender] += msg.value;
        totalStaked          += msg.value;
    }

    function addReward(address user, uint256 amount) external {
        rewards[user] += amount;
    }

    function claim() external {
        require(balances[msg.sender] > 0, "no stake");

        uint256 userStake  = balances[msg.sender];
        uint256 userReward = rewards[msg.sender];
        uint256 payout     = userStake + userReward;

        // EXTERNAL CALL
        (bool ok, ) = msg.sender.call{value: payout}("");
        require(ok, "failed");

        // state updates AFTER call — vulnerability
        balances[msg.sender] = 0;
        rewards[msg.sender]  = 0;
        totalStaked          -= userStake;
    }
}
