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
    uint256 public constant token = 1067607685111676961967872763715441634734290642427;
    
    
    /// @custom:selector    0x2bd94e9c
    /// @custom:signature   Unresolved_2bd94e9c(uint256 arg0, address arg1, uint256 arg2) public payable
    /// @param              arg0 ["uint256", "bytes32", "int256"]
    /// @param              arg1 ["address", "uint160", "bytes20", "int160"]
    /// @param              arg2 ["uint256", "bytes32", "int256"]
    function Unresolved_2bd94e9c(uint256 arg0, address arg1, uint256 arg2) public payable {
        require(true);
        require(arg2 <= 0xffffffffffffffff);
        require(msg.data[0x04 + arg2] <= 0xffffffffffffffff);
        (bool success, bytes memory ret0) = address(0xbb012f2edbabc303e5c3795cc4430fa57d0a25fb).Unresolved_70a08231(address(this)); // staticcall
        require(success);
        uint256 var_c = var_c + (ret0.length + 0x1f & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0);
        require(var_c + ret0.length - var_c >= 0x20);
        (bool success, bytes memory ret0) = address(0xbb012f2edbabc303e5c3795cc4430fa57d0a25fb).Unresolved_a9059cbb(arg1); // call
        require(success);
        uint256 var_c = var_c + (ret0.length + 0x1f & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0);
        require(var_c + ret0.length - var_c >= 0x20);
        require(var_g, "loan");
        require(arg1.code.length);
        (bool success, bytes memory ret0) = address(arg1).Unresolved_79b2fae8(arg0); // call
        require(success);
        (bool success, bytes memory ret0) = address(0xbb012f2edbabc303e5c3795cc4430fa57d0a25fb).Unresolved_70a08231(address(this)); // staticcall
        require(success);
        uint256 var_c = var_c + (ret0.length + 0x1f & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0);
        require(var_c + ret0.length - var_c >= 0x20);
        require(var_g >= var_g, "unpaid");
    }
}