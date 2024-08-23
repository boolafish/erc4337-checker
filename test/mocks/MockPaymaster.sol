// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "account-abstraction/core/BasePaymaster.sol";
import {console2} from "forge-std/Test.sol";

/**
 * test paymaster, that pays for everything, without any check.
 */
contract MockPaymaster is BasePaymaster {
    uint storedDummyMaxCost = 9999999;

    enum AttackType {
        NONE,
        UseStorage
    }

    constructor(IEntryPoint _entryPoint) BasePaymaster(_entryPoint) {}

    function _validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
    internal virtual override view
    returns (bytes memory context, uint256 validationData) {
        AttackType attackType = _decodeAttackType(userOp.paymasterAndData);
        uint dummyMaxCost = 12345;
        if (attackType == AttackType.UseStorage) {
            // force accessing the storage
            dummyMaxCost = storedDummyMaxCost;
            console2.log("access paymaster storage:", dummyMaxCost);
        }

        (userOp, userOpHash, maxCost);
        return ("", maxCost == 12345 ? 1 : 0);
    }

    function _decodeAttackType(bytes calldata paymasterAndData) private pure returns (AttackType) {
        // Convert the value to AttackType enum
        if (paymasterAndData.length <= 20) {
            return AttackType.NONE;
        }
        return abi.decode(paymasterAndData[20:], (AttackType));
    }
}

