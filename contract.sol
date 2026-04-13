// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Test {
    mapping(address => uint) public balances;

    function withdraw() public {
        uint amount = balances[msg.sender];
        uint fee = amount / 10;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);

        balances[msg.sender] = 0;
    }
}
