// SPDX-License-Identifier: MIT
pragma solidity >=0.8.4;

// solhint-disable-next-line
import "@openzeppelin/contracts/access/Ownable.sol";

contract Deployer is Ownable {
    // solhint-disable-next-line
    constructor() Ownable() {}

    function getAddress(bytes memory bytecode, uint256 salt) external view returns (address) {
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(bytecode)));

        // NOTE: cast last 20 bytes of hash to address
        return address(uint160(uint(hash)));
    }

    function deploy(
        bytes memory bytecode,
        bytes calldata initData,
        uint256 salt
    ) external onlyOwner returns (address addr) {
        assembly {
            addr := create2(
                callvalue(), // wei sent with current call
                // Actual code starts after skipping the first 32 bytes
                add(bytecode, 0x20),
                mload(bytecode), // Load the size of code contained in the first 32 bytes
                salt // Salt from function arguments
            )

            // revert if create fail
            if iszero(extcodesize(addr)) {
                revert(0, 0)
            }

            if iszero(eq(initData.length, 0)) {
                let emptyPtr := mload(0x40)
                calldatacopy(add(emptyPtr, 0x20), initData.offset, initData.length)

                if iszero(call(gas(), addr, 0, emptyPtr, initData.length, 0x0, 0x0)) {
                    returndatacopy(emptyPtr, 0, returndatasize())
                    revert(emptyPtr, returndatasize())
                }
            }
        }
    }
}
