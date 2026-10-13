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
    bytes32 store_d; // storage slot: 0x00
    uint256 public unresolved_f9a72093; // storage slot: 0x01
    uint256 public unresolved_d96d7c17; // storage slot: 0x02
    bytes32 store_a; // storage slot: 0x03
    bytes32 store_e; // storage slot: 0x04
    bytes32[] store_f; // storage slot: 0x05
    
    
    /// @custom:selector    0x0c340a24
    /// @custom:signature   Unresolved_0c340a24() public view returns (uint256)
    function Unresolved_0c340a24() public view returns (uint256) {
        return store_a;
    }
    
    /// @custom:selector    0x20c69c89
    /// @custom:signature   Unresolved_20c69c89(uint256 arg0) public payable
    /// @param              arg0 ["uint256", "bytes32", "int256"]
    function Unresolved_20c69c89(uint256 arg0) public payable {
        require(0 - arg0, "zero limit");
        unresolved_d96d7c17 = arg0;
        if (0x01 <= arg0 + 0x01) {
            unresolved_f9a72093 = arg0 + 0x01;
        }
    }
    
    /// @custom:selector    0xb858daff
    /// @custom:signature   Unresolved_b858daff() public view returns (uint256)
    function Unresolved_b858daff() public view returns (uint256) {
        return store_d;
    }
    
    /// @custom:selector    0xd3a7b7d3
    /// @custom:signature   Unresolved_d3a7b7d3() public view returns (uint256)
    function Unresolved_d3a7b7d3() public view returns (uint256) {
        return store_e;
    }
    
    /// @custom:selector    0xf83ba31c
    /// @custom:signature   Unresolved_f83ba31c(address arg0) public payable
    /// @param              arg0 ["address", "uint160", "bytes20", "int160"]
    function Unresolved_f83ba31c(address arg0) public payable {
        require(true);
        require(0 - unresolved_d96d7c17, "not armed");
        if (0 < store_f) {
            store_f[0] = arg0 | 0xffffffffffffffffffffffff0000000000000000000000000000000000000000 & store_f[0];
            store_e = block.timestamp;
        }
    }
}