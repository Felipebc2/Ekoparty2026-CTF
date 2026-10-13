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
    string public constant name = "Night Deposit Note";
    
    mapping(address => uint256) public balanceOf; // storage slot: 0x00
    
    
    /// @custom:selector    0x9dc29fac
    /// @custom:signature   burn(address arg0, uint256 arg1) public payable
    /// @param              arg0 ["address", "uint160", "bytes20", "int160"]
    /// @param              arg1 ["uint256", "bytes32", "int256"]
    function burn(address arg0, uint256 arg1) public payable {
        require(true);
        require(0x343d86294388f892932d125452ac776b63bcbc98 == msg.sender, "not bank");
        if (balanceOf[arg0] - arg1 <= balanceOf[arg0]) {
            balanceOf[arg0] -= arg1;
        }
    }
    
    /// @custom:selector    0x40c10f19
    /// @custom:signature   mint(address arg0, uint256 arg1) public payable
    /// @param              arg0 ["address", "uint160", "bytes20", "int160"]
    /// @param              arg1 ["uint256", "bytes32", "int256"]
    function mint(address arg0, uint256 arg1) public payable {
        require(true);
        require(0x343d86294388f892932d125452ac776b63bcbc98 == msg.sender, "not bank");
        if (balanceOf[arg0] <= arg1 + balanceOf[arg0]) {
            balanceOf[arg0] += arg1;
            if (arg0.code.length) {
                require(arg0.code.length);
                (bool success, bytes memory ret0) = address(arg0).Unresolved_410593e3(0x343d86294388f892932d125452ac776b63bcbc98); // call
                require(success);
            }
        }
    }
}