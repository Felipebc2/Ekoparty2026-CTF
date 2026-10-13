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
    uint256 public constant bank = 298239552627611392644077127463613275584834878616;
    uint256 public constant player = 314803203281644946918830899377739855173668173557;
    
    
    /// @custom:selector    0x64d98f6e
    /// @custom:signature   isSolved() public view returns (bool)
    function isSolved() public view returns (bool) {
        return !address(0x343d86294388f892932d125452ac776b63bcbc98).balance;
    }
}