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
    uint256 public constant flash = 354226657493871947801549874466175745358177865957;
    uint256 public constant lending = 46956235160735269553645095476156009532562889934;
    uint256 public constant oracle = 840021288910506909912546474519590695525911741041;
    uint256 public constant player = 299797715171752356669035809471400371527049683736;
    uint256 public constant unresolved_56e5a013 = 1122244638390741109362005007655194708950436130625;
    uint256 public constant unresolved_a61d892f = 10000000000000000000000;
    uint256 public constant unresolved_ddf6b66e = 2000000000000000000000;
    uint256 public constant usd = 1067607685111676961967872763715441634734290642427;
    
    
    /// @custom:selector    0x64d98f6e
    /// @custom:signature   isSolved() public payable returns (bool)
    function isSolved() public payable returns (bool) {
        if (true | !0x0a) {
            (bool success, bytes memory ret0) = address(0xbb012f2edbabc303e5c3795cc4430fa57d0a25fb).Unresolved_70a08231(0x08399724eb16e2783831a1708e792cf3ca4c5cce); // staticcall
            require(success);
            uint256 var_c = var_c + (ret0.length + 0x1f & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0);
            require(var_c + ret0.length - var_c >= 0x20);
            (bool success, bytes memory ret0) = address(0xbb012f2edbabc303e5c3795cc4430fa57d0a25fb).Unresolved_70a08231(0x3e0c129afc9cec9cb660f0c87a40a1168c6590e5); // staticcall
            require(success);
            uint256 var_c = var_c + (ret0.length + 0x1f & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0);
            require(var_c + ret0.length - var_c >= 0x20);
            if (var_f >= 0x3635c9adc5dea00000) {
                return var_f < 0x3635c9adc5dea00000;
            } else {
                return var_f >= 0x6c6b935b8bbd400000;
            }
        }
    }
}