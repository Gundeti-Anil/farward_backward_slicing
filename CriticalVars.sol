// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CriticalVars {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lastWithdrawBlock;

    function deposit() external payable {
        require(msg.value > 0, "no value");
        balances[msg.sender] += msg.value;
    }

    // Intentionally vulnerable shape for analysis:
    // - read balances[msg.sender] before external call
    // - write balances[msg.sender] after external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        uint256 previousBalance = balances[msg.sender];

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");

        balances[msg.sender] = previousBalance - amount;
        lastWithdrawBlock[msg.sender] = block.number;
    }
}