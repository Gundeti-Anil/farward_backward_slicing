// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// CONTRACT 1: SimpleBank
// Classic reentrancy — balances read before call, zeroed after.
// Expected: balances flagged as WRITTEN WINDOW risk.

contract SimpleBank {

    mapping(address => uint256) public balances;
    bool public locked;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function setLock(bool _locked) external {
        locked = _locked;
    }

    function withdraw() external {
        require(!locked,                  "locked");
        require(balances[msg.sender] > 0, "empty");

        uint256 amount = balances[msg.sender];

        // EXTERNAL CALL
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "failed");

        // state update AFTER call — vulnerability
        balances[msg.sender] = 0;
    }
}
