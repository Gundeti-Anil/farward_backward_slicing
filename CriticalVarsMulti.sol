// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CriticalVarsMulti {
    struct Account {
        uint256 credit;
        uint256 debt;
        uint256 nonce;
    }

    mapping(address => Account) public accounts;
    mapping(address => uint256) public pendingRewards;
    mapping(address => bool) public locked;
    uint256 public totalOutstanding;
    uint256 public globalNonce;

    function seed(
        uint256 credit,
        uint256 debt,
        uint256 reward
    ) external {
        accounts[msg.sender].credit = credit;
        accounts[msg.sender].debt = debt;
        pendingRewards[msg.sender] = reward;
    }

    // Intentionally vulnerable layout for analysis:
    // Reads before external call:
    // - accounts[msg.sender].credit
    // - accounts[msg.sender].debt
    // - pendingRewards[msg.sender]
    // - totalOutstanding
    // - globalNonce
    //
    // Writes after external call:
    // - accounts[msg.sender].credit
    // - accounts[msg.sender].debt
    // - pendingRewards[msg.sender]
    // - totalOutstanding
    // - globalNonce
    // - accounts[msg.sender].nonce
    function claimAndWithdraw(uint256 amount) external {
        require(!locked[msg.sender], "reentrant");
        require(accounts[msg.sender].credit >= amount, "insufficient credit");
        require(totalOutstanding >= amount, "insufficient pool");

        uint256 debtBefore = accounts[msg.sender].debt;
        uint256 rewardBefore = pendingRewards[msg.sender];
        uint256 nonceBefore = globalNonce;

        locked[msg.sender] = true;

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        accounts[msg.sender].credit -= amount;
        accounts[msg.sender].debt = debtBefore + amount / 10;
        pendingRewards[msg.sender] = rewardBefore / 2;
        totalOutstanding -= amount;
        globalNonce = nonceBefore + 1;
        accounts[msg.sender].nonce += 1;
        locked[msg.sender] = false;
    }
}