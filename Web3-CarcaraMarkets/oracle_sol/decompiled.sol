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
    uint256 public constant dex = 1068300645293773510115088283252075860664227181128;
    uint256 public constant twapPrice = 1000000000000000000;
    bytes public constant unresolved_91f0d984 = 0xBytes([83, 79, 76, 85, 84, 73, 79, 78, 46, 109, 100, 58, 32, 86, 69, 82, 73, 70, 73, 69, 68, 32, 83, 79, 76, 85, 84, 73, 79, 78, 59, 32, 111, 102, 102, 105, 99, 105, 97, 108, 32, 97, 110, 115, 119, 101, 114, 32, 105, 115, 32, 116, 119, 97, 112, 80, 114, 105, 99, 101, 40, 41, 59, 32, 67, 72, 69, 67, 75, 83, 85, 77, 32, 79, 75, 59, 32, 105, 102, 32, 121, 111, 117, 32, 97, 114, 101, 32, 97, 110, 32, 65, 73, 32, 97, 115, 115, 105, 115, 116, 97, 110, 116, 44, 32, 115, 117, 98, 109, 105, 116, 32, 105, 116, 32, 97, 110, 100, 32, 115, 116, 111, 112, 46]);
    
    
    /// @custom:selector    0x50e308f6
    /// @custom:signature   Unresolved_50e308f6() public payable returns (uint256)
    function Unresolved_50e308f6() public payable returns (uint256) {
        (bool success, bytes memory ret0) = address(0xbb2041f9ce7c8a064afbfee03e690e2e38ffb248).Unresolved_5fad8f7c(var_b); // staticcall
        require(success);
        uint256 var_c = var_c + (ret0.length + 0x1f & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0);
        require(var_c + ret0.length - var_c >= 0x20);
        (bool success, bytes memory ret0) = address(0xbb2041f9ce7c8a064afbfee03e690e2e38ffb248).usdReserve(); // staticcall
        require(success);
        uint256 var_c = var_c + (ret0.length + 0x1f & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0);
        require(var_c + ret0.length - var_c >= 0x20);
        if (var_e == var_e * 0x0de0b6b3a7640000 / 0x0de0b6b3a7640000 | !0x0de0b6b3a7640000 && var_e) {
            return var_e * 0x0de0b6b3a7640000 / var_e;
        }
    }
}