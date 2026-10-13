// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @title            Decompiled Contract
/// @author           Jonathan Becker <jonathan@jbecker.dev>
/// @custom:version   heimdall-rs v0.9.2
///
/// @notice           This contract was decompiled using the heimdall-rs decompiler.
///                     It was generated directly by tracing the EVM opcodes from this contract.
///                     As a result, it may not compile or even be valid solidity code.
///                     Despite this, it should be obvious what each function does. Overall
///                     logic should have been preserved throughout decompiling.
///
/// @custom:github    You can find the open-source decompiler here:
///                       https://heimdall.rs

contract DecompiledContract {
    uint256 public constant unresolved_56e5a013 = 1122244638390741109362005007655194708950436130625;
    uint256 public constant usd = 1067607685111676961967872763715441634734290642427;
    
    bytes32 store_a; // storage slot: 0x00
    bytes32 store_b; // storage slot: 0x01
    
    
    /// @custom:selector    0x054d50d4
    /// @custom:signature   getAmountOut(uint256 arg0, uint256 arg1, uint256 arg2) public pure returns (uint256)
    /// @param              arg0 ["uint256", "bytes32", "int256"]
    /// @param              arg1 ["uint256", "bytes32", "int256"]
    /// @param              arg2 ["uint256", "bytes32", "int256"]
    function getAmountOut(uint256 arg0, uint256 arg1, uint256 arg2) public pure returns (uint256) {
        if (arg0 == arg0 * 0x03e5 / 0x03e5 | !0x03e5 && (arg2 == arg2 * (arg0 * 0x03e5) / (arg0 * 0x03e5) | !(arg0 * 0x03e5) && (arg1 == arg1 * 0x03e8 / 0x03e8 | !0x03e8 && (arg1 * 0x03e8 <= arg0 * 0x03e5 + arg1 * 0x03e8 && arg0 * 0x03e5 + arg1 * 0x03e8)))) {
            return arg2 * (arg0 * 0x03e5) / (arg0 * 0x03e5 + arg1 * 0x03e8);
        }
    }
    
    /// @custom:selector    0x166a00e4
    /// @custom:signature   seed(uint256 arg0, uint256 arg1) public payable
    /// @param              arg0 ["uint256", "bytes32", "int256"]
    /// @param              arg1 ["uint256", "bytes32", "int256"]
    function seed(uint256 arg0, uint256 arg1) public payable {
        if (msg.data.length - 0x04 >= 0x40) {
            require(!store_a, "already seeded");
            (bool success, bytes memory ret0) = address(0xc49330a5ac1b5d0cbdfe9f86a9b091a81591af41).Unresolved_23b872dd(msg.sender); // call
            if (success) {
                uint256 var_e = var_e + (ret0.length + 0x1f & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0);
                if (var_e + ret0.length - var_e >= 0x20) {
                    require(var_f, "hik");
                    (bool success, bytes memory ret0) = address(0xbb012f2edbabc303e5c3795cc4430fa57d0a25fb).Unresolved_23b872dd(msg.sender); // call
                    revert();
                }
            }
        }
        revert();
    }
    
    /// @custom:selector    0x1518a0ec
    /// @custom:signature   Unresolved_1518a0ec(uint256 arg0, uint256 arg1) public payable
    /// @param              arg0 ["uint256", "bytes32", "int256"]
    /// @param              arg1 ["uint256", "bytes32", "int256"]
    function Unresolved_1518a0ec(uint256 arg0, uint256 arg1) public payable {
        if (arg0 == arg0 * 0x03e5 / 0x03e5 | !0x03e5 && (store_b == store_b * (arg0 * 0x03e5) / (arg0 * 0x03e5) | !(arg0 * 0x03e5) && (store_a == store_a * 0x03e8 / 0x03e8 | !0x03e8 && (store_a * 0x03e8 <= arg0 * 0x03e5 + store_a * 0x03e8 && arg0 * 0x03e5 + store_a * 0x03e8)))) {
            require(store_b * (arg0 * 0x03e5) / (arg0 * 0x03e5 + store_a * 0x03e8) >= arg1, "slippage");
            (bool success, bytes memory ret0) = address(0xc49330a5ac1b5d0cbdfe9f86a9b091a81591af41).Unresolved_23b872dd(msg.sender); // call
            if (success) {
                uint256 var_e = var_e + (ret0.length + 0x1f & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0);
                if (var_e + ret0.length - var_e >= 0x20) {
                    require(var_f, "hik in");
                }
            }
            revert();
        }
    }
    
    /// @custom:selector    0x5fad8f7c
    /// @custom:signature   Unresolved_5fad8f7c() public view returns (uint256)
    function Unresolved_5fad8f7c() public view returns (uint256) {
        return store_a;
    }
    
    /// @custom:selector    0x8ac326bd
    /// @custom:signature   Unresolved_8ac326bd(uint256 arg0, uint256 arg1) public payable
    /// @param              arg0 ["uint256", "bytes32", "int256"]
    /// @param              arg1 ["uint256", "bytes32", "int256"]
    function Unresolved_8ac326bd(uint256 arg0, uint256 arg1) public payable {
        if (arg0 == arg0 * 0x03e5 / 0x03e5 | !0x03e5 && (store_a == store_a * (arg0 * 0x03e5) / (arg0 * 0x03e5) | !(arg0 * 0x03e5) && (store_b == store_b * 0x03e8 / 0x03e8 | !0x03e8 && (store_b * 0x03e8 <= arg0 * 0x03e5 + store_b * 0x03e8 && arg0 * 0x03e5 + store_b * 0x03e8)))) {
            require(store_a * (arg0 * 0x03e5) / (arg0 * 0x03e5 + store_b * 0x03e8) >= arg1, "slippage");
            (bool success, bytes memory ret0) = address(0xbb012f2edbabc303e5c3795cc4430fa57d0a25fb).Unresolved_23b872dd(msg.sender); // call
            if (success) {
                uint256 var_e = var_e + (ret0.length + 0x1f & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0);
                if (var_e + ret0.length - var_e >= 0x20) {
                    require(var_f, "usd in");
                }
            }
            revert();
        }
    }
    
    /// @custom:selector    0xecc77da9
    /// @custom:signature   usdReserve() public view returns (uint256)
    function usdReserve() public view returns (uint256) {
        return store_b;
    }
}