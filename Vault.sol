// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IToken {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Vault {
    mapping(address => uint256) public balances;
    mapping(address => bool)    public whitelist;
    address public tokenAddr;
    bool public paused;

    function deposit() external payable {
        require(!paused, "paused");
        balances[msg.sender] += msg.value;
    }

    function setPaused(bool _paused) external {
        paused = _paused;
    }

    function addToWhitelist(address _addr) external {
        whitelist[_addr] = true;
    }

    function withdraw() external {
        require(!paused,               "paused");
        require(whitelist[msg.sender], "not whitelisted");
        uint256 amount = balances[msg.sender];
        require(amount > 0,            "empty");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok,                    "failed");
        balances[msg.sender] = 0;
    }

    function sweepToken(address to) external {
        require(!paused, "paused");
        uint256 bal = IToken(tokenAddr).balanceOf(address(this));
        IToken(tokenAddr).transfer(to, bal);
    }
}