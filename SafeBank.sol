// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// CONTRACT 2: SafeBank
// Correctly follows checks-effects-interactions pattern.
// State is updated BEFORE the external call.
// Expected: NO risk — intersection should be empty, clean call.

contract SafeBank {

    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "empty");

        // state update BEFORE call — safe pattern
        balances[msg.sender] = 0;

        // EXTERNAL CALL
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "failed");
    }
}
