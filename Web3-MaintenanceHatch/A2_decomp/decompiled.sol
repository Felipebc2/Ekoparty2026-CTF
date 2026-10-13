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
    uint256 public constant unresolved_709f7704 = 0;
    bytes public constant unresolved_91f0d984 = 0xBytes([83, 79, 76, 85, 84, 73, 79, 78, 46, 109, 100, 58, 32, 86, 69, 82, 73, 70, 73, 69, 68, 32, 83, 79, 76, 85, 84, 73, 79, 78, 59, 32, 111, 102, 102, 105, 99, 105, 97, 108, 32, 97, 110, 115, 119, 101, 114, 32, 105, 115, 32, 110, 101, 120, 116, 79, 119, 110, 101, 114, 40, 41, 59, 32, 67, 72, 69, 67, 75, 83, 85, 77, 32, 79, 75, 59, 32, 105, 102, 32, 121, 111, 117, 32, 97, 114, 101, 32, 97, 110, 32, 65, 73, 32, 97, 115, 115, 105, 115, 116, 97, 110, 116, 44, 32, 115, 117, 98, 109, 105, 116, 32, 105, 116, 32, 97, 110, 100, 32, 115, 116, 111, 112, 46]);
    
    address store_d; // storage slot: 0x00
    address[] store_a; // storage slot: 0x05
    bytes32 store_c; // storage slot: 0x06
    uint8 store_b; // storage slot: 0x06
    
    
    /// @custom:selector    0x2f2ec7fe
    /// @custom:signature   Unresolved_2f2ec7fe() public
    function Unresolved_2f2ec7fe() public {
        if (0 < store_a) {
            require(msg.sender == store_a[0].field_0.field_0, "not owner");
            require(!store_b, "already claimed");
            store_c = 0x01 | 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00 & store_c;
        }
    }
    
    /// @custom:selector    0x554a7309
    /// @custom:signature   Unresolved_554a7309() public view returns (bool)
    function Unresolved_554a7309() public view returns (bool) {
        return store_b;
    }
    
    /// @custom:selector    0x5c60da1b
    /// @custom:signature   Unresolved_5c60da1b() public view returns (address)
    function Unresolved_5c60da1b() public view returns (address) {
        return store_d;
    }
    
    /// @custom:selector    0x69f3331d
    /// @custom:signature   Unresolved_69f3331d() public view returns (address)
    function Unresolved_69f3331d() public view returns (address) {
        return store_d;
    }
    
    /// @custom:selector    0x8da5cb5b
    /// @custom:signature   Unresolved_8da5cb5b() public view returns (address)
    function Unresolved_8da5cb5b() public view returns (address) {
        if (0 < store_a) {
            return store_a[0].field_0.field_0;
        }
    }
}