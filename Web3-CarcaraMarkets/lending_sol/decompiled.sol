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
    uint256 public constant LTV_BPS = 9000;
    uint256 public constant oracle = 840021288910506909912546474519590695525911741041;
    uint256 public constant unresolved_56e5a013 = 1122244638390741109362005007655194708950436130625;
    uint256 public constant usd = 1067607685111676961967872763715441634734290642427;
    
    mapping(address => uint256) public unresolved_edad830b; // storage slot: 0x00
    mapping(address => uint256) public debtUsd; // storage slot: 0x01
    
    
    /// @custom:selector    0xc5ebeaec
    /// @custom:signature   borrow(uint256 arg0) public payable
    /// @param              arg0 ["uint256", "bytes32", "int256"]
    function borrow(uint256 arg0) public payable {
        (bool success, bytes memory ret0) = address(0x9323db7b363eace9bd7e8ae166b6ce3f325dc271).Unresolved_50e308f6(var_b); // staticcall
        require(success);
        uint256 var_c = var_c + (ret0.length + 0x1f & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0);
        require(var_c + ret0.length - var_c >= 0x20);
        if (var_f == var_f * unresolved_edad830b[msg.sender] / unresolved_edad830b[msg.sender] | !unresolved_edad830b[msg.sender] && (0x2328 == 0x2328 * (var_f * unresolved_edad830b[msg.sender] / 0x0de0b6b3a7640000) / (var_f * unresolved_edad830b[msg.sender] / 0x0de0b6b3a7640000) | !(var_f * unresolved_edad830b[msg.sender] / 0x0de0b6b3a7640000) && debtUsd[msg.sender] <= arg0 + debtUsd[msg.sender])) {
            require(arg0 + debtUsd[msg.sender] <= 0x2328 * (var_f * debtUsd[msg.sender] / 0x0de0b6b3a7640000) / 0x2710, "ltv");
            if (debtUsd[msg.sender] <= arg0 + debtUsd[msg.sender]) {
                debtUsd[msg.sender] += arg0;
                (bool success, bytes memory ret0) = address(0xbb012f2edbabc303e5c3795cc4430fa57d0a25fb).Unresolved_a9059cbb(msg.sender); // call
                require(success);
                uint256 var_c = var_c + (ret0.length + 0x1f & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0);
                require(var_c + ret0.length - var_c >= 0x20);
                require(var_f, "borrow");
            }
        }
    }
    
    /// @custom:selector    0xbad4a01f
    /// @custom:signature   depositCollateral(uint256 arg0) public payable
    /// @param              arg0 ["uint256", "bytes32", "int256"]
    function depositCollateral(uint256 arg0) public payable {
        (bool success, bytes memory ret0) = address(0xc49330a5ac1b5d0cbdfe9f86a9b091a81591af41).Unresolved_23b872dd(msg.sender); // call
        require(success);
        uint256 var_e = var_e + (ret0.length + 0x1f & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0);
        require(var_e + ret0.length - var_e >= 0x20);
        require(var_f, "collateral");
        if (unresolved_edad830b[msg.sender] <= arg0 + unresolved_edad830b[msg.sender]) {
            unresolved_edad830b[msg.sender] += arg0;
        }
    }
}