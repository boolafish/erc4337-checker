// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Vm} from "forge-std/Vm.sol";

import {Test, console2} from "forge-std/Test.sol";

import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IStakeManager} from "account-abstraction/interfaces/IStakeManager.sol";
import {Strings} from "openzeppelin-contracts/contracts/utils/Strings.sol";
import "forge-std/console2.sol";

contract ERC4337Checker {
    struct StorageSlot {
        address account;
        bytes32 slot;
    }

    struct FailureLog {
        string errorMsg;
        address contractAddr;
    }

    FailureLog[] public failureLogs;

    Vm private vm;

    // This is the hardcoded memory allocation size for a single debug trace.
    // 32 * 6: there are six fields, each using 32 bytes.
    // 32 * 10: reserve 10 element spaces for the `stack` field.
    // 32 * 1024: reserve 1024 element spaces for the `memoryData` field.
    // this is most likely to be over-allocated but we will reuse this.
    // the cheatcode will also filter out unrelated stack and memory data of the opcode.
    uint256 constant private DEBUG_STEP_ALLOCATION_SIZE = 32 * 6 + 32 * 10 + 32 * 1024;

    // This is the pointer that will always be used to collect the debug trace data.
    // We aim to reuse the same pointer to avoid out-of-memory for the EVM when running test.
    uint256 private debugStepPtr;

    function printFailureLogs() public view {
        console2.log("--------ERC4337Checker Failure Logs-----------");
        for (uint i = 0; i < failureLogs.length; i++) {
            console2.log("Failed in contract address", failureLogs[i].contractAddr);
            console2.log(failureLogs[i].errorMsg);
        }
    }


    function simulateAndVerifyUserOp(Vm _vm, UserOperation memory userOp, EntryPoint entryPoint) external returns (bool) {
        vm = _vm;

        // this starts the recording of the debug trace that will later be analyzed
        vm.startDebugTraceRecording();

        try entryPoint.simulateValidation(userOp) {
            // the simulateValidation function will always revert.
            // in this test, we do not really care if it is revert in an expected output or not.
        } catch (bytes memory reason) {
            // if not fail with ValidationResult error, it is likely to be something unexpected.
            if (reason.length < 4 || bytes4(reason) != IEntryPoint.ValidationResult.selector) {
                revert(string(abi.encodePacked(
                    "simulateValidation call failed unexpectedly: ", reason
                )));
            }
        }

        // collect the recorded opcodes, stack and memory inputs.
        uint256 size = vm.stopDebugTraceRecording();

        console2.log("--------ERC4337Checker SIIIIZZZZZEEEE-----------");
        console2.log(size);

        // allocate a space in memory for the debug step to reuse the memory slot
        debugStepPtr = allocateDebugStepMemory();

        // verify that the user operation fulfills the spec's limitation
        return validateUserOp(size, userOp, entryPoint);
    }

    function simulateAndVerifyBundle(Vm _vm, UserOperation[] memory userOps, EntryPoint entryPoint) external returns (bool) {
        vm = _vm;

        // this starts the recording of the debug trace that will later be analyzed
        vm.startDebugTraceRecording();

        for (uint i = 0 ; i < userOps.length; ++i) {
            try entryPoint.simulateValidation(userOps[i]) {
                // the simulateValidation function will always revert.
                // in this test, we do not really care if it is revert in an expected output or not.
            } catch (bytes memory reason) {
                // if not fail with ValidationResult error, it is likely to be something unexpected.
                if (reason.length < 4 || bytes4(reason) != IEntryPoint.ValidationResult.selector) {
                    revert(string(abi.encodePacked(
                        "simulateValidation call failed unexpectedly: ", reason
                    )));
                }
            }
        }

        // collect the recorded opcodes, stack and memory inputs.
        uint256 size = vm.stopDebugTraceRecording();

        // allocate a space in memory for the debug step to reuse the memory slot
        debugStepPtr = allocateDebugStepMemory();

        console2.log("--------ERC4337Checker SIIIIZZZZZEEEE-----------");
        console2.log(size);

        // verify that the user operation fulfills the spec's limitation
        return validateBundle(size, userOps, entryPoint);
    }


    function validateBundle(uint256 debugStepsSize, UserOperation[] memory userOps, EntryPoint entryPoint)
        public
        returns (bool)
    {
        bool result = true;

        if (!validateBundleStorageNoRepeat(debugStepsSize, userOps, entryPoint)) {
            result = false;
        }

        for (uint i = 0; i < userOps.length; i++) {
            if (!validateUserOp(debugStepsSize, userOps[i], entryPoint)) {
                result = false;
            }
        }

        return result;
    }

    function validateUserOp(uint256 stepsSize, UserOperation memory userOp, EntryPoint entryPoint)
        public
        returns (bool)
    {
        (uint256[] memory senderStepsIndexes,
         uint256[] memory paymasterStepsIndexes) = getRelativeDebugSteps(stepsSize, userOp, entryPoint);

        bool result = true;

        console2.log("senderStepsIndexes length", senderStepsIndexes.length);
        // Validate the opcodes and storages for `validateUserOp()`
        if (!validateSteps(senderStepsIndexes, userOp, entryPoint)) {
            result = false;
        }

        console2.log("payment master steps length", paymasterStepsIndexes.length);
        // Validate the opcodes and storages for `validatePaymasterUserOp()`
        if (!validateSteps(paymasterStepsIndexes, userOp, entryPoint)) {
            result = false;
        }

        return result;
    }

    /**
     * in any case, may not use storage used by another UserOp sender in the same bundle
     * (that is, paymaster and factory are not allowed as senders)
     */
    function validateBundleStorageNoRepeat(
        uint256 debugStepsSize,
        UserOperation[] memory userOps,
        EntryPoint entryPoint
    )
        private
        returns (bool)
    {
        uint slotMaxLen = debugStepsSize * userOps.length;
        StorageSlot[] memory slots = new StorageSlot[](slotMaxLen);
        uint slotsLen = 0;
        bool result = true;

        for (uint i = 0; i < userOps.length; i++) {
            UserOperation memory userOp = userOps[i];
            (uint256[] memory senderStepsIndexes, ) = getRelativeDebugSteps(debugStepsSize, userOp, entryPoint);

            assembly {
                mstore(slots, slotsLen)
            }
            (bool validateResult, StorageSlot[] memory accessSlots) =
                validateNoRepeatWithNewAccessSlots(slots, senderStepsIndexes);
            if (!validateResult) {
                result = validateResult;
            }
            assembly {
                mstore(slots, slotMaxLen)
            }

            for (uint j = 0; j < accessSlots.length; j++) {
                slots[slotsLen++] = accessSlots[j];
            }
        }

        return result;
    }

    function validateNoRepeatWithNewAccessSlots(
        StorageSlot[] memory slots,
        uint256[] memory senderStepsIndexes
    )
        private
        returns (bool, StorageSlot[] memory)
    {
        bool result = true;
        // a temporary slots, will merge with the main slots after checking
        // no duplicated storage access from this userOP.
        StorageSlot[] memory tmpSlots = new StorageSlot[](senderStepsIndexes.length);
        uint tmpSlotsLen = 0;
        for (uint i = 0; i < senderStepsIndexes.length; i++) {
            uint256 index = senderStepsIndexes[i];
            Vm.DebugStep memory debugStep = getDebugTraceByIndex(index);

            uint8 opcode = debugStep.opcode;
            if (opcode != 0x54 /*SLOAD*/ && opcode != 0x55 /*SSTORE*/ ) {
                continue;
            }

            address account = debugStep.contractAddr;
            bytes32 slot = bytes32(debugStep.stack[0]);
            bool isDuplicated = false;

            for (uint j = 0; j < slots.length; j++) {
                // check if there is duplicated storage
                if (slots[j].account == account && slots[j].slot == slot) {
                    failureLogs.push(FailureLog({
                        errorMsg: string(abi.encodePacked(
                            "The bundle have duplicate storage access. Account: [", Strings.toHexString(account),
                            "], slot: [", Strings.toHexString(uint256(slot)), "]"
                        )),
                        contractAddr: debugStep.contractAddr
                    }));
                    isDuplicated = true;
                    result = false;
                    break;
                }
            }

            if (!isDuplicated) {
                // if no duplication, put in tmpSlots
                // and will merge it back to slots later
                tmpSlots[tmpSlotsLen++] = StorageSlot({
                    account: account,
                    slot: slot
                });
            }
        }

        assembly ("memory-safe") {
            mstore(tmpSlots, tmpSlotsLen)
        }

        return (result, tmpSlots);
    }

    function validateSteps(
        uint256[] memory debugStepsIndexes,
        UserOperation memory userOp,
        EntryPoint entryPoint
    )
        private
        returns (bool)
    {
        if (debugStepsIndexes.length == 0) {
            return true; // nothing to verify
        }

        bool result = true;
        if (!validateForbiddenOpcodes(debugStepsIndexes)) {
            result = false;
        }
        if (!validateCall(debugStepsIndexes, address(entryPoint), true)) {
            result = false;
        }
        if (!validateExtcodeMayNotAccessAddressWithoutCode(debugStepsIndexes)) {
            result = false;
        }
        if (!validateCreate2(debugStepsIndexes, userOp)) {
            result = false;
        }
        if (!validateStorage(debugStepsIndexes, userOp, entryPoint)) {
            result = false;
        }

        return result;
    }

    function validateStorage(uint256[] memory debugStepsIndexes, UserOperation memory userOp, EntryPoint entryPoint)
        private
        returns (bool)
    {
        address factory = getFactoryAddr(userOp);
        IStakeManager.StakeInfo memory factoryStakeInfo = getStakeInfo(factory, entryPoint);

        address paymaster = getPaymasterAddr(userOp);
        IStakeManager.StakeInfo memory paymasterStakeInfo = getStakeInfo(paymaster, entryPoint);

        bytes32[] memory associatedSlots = findAddressAssociatedSlots(userOp.sender, debugStepsIndexes);

        bool result = true;

        for (uint256 i = 0; i < debugStepsIndexes.length; i++) {
            uint256 index = debugStepsIndexes[i];
            Vm.DebugStep memory debugStep = getDebugTraceByIndex(index);
            uint8 opcode = debugStep.opcode;

            if (opcode != 0x54 /*SLOAD*/ && opcode != 0x55 /*SSTORE*/ ) {
                continue;
            }

            // self storage (of factory/paymaster, respectively) is allowed,
            // but only if self entity is staked
            //
            // note: this implementation only take into the original EIP-4337 spec.
            // There are slight difference with the draft spec from eth-infinitism:
            // https://github.com/eth-infinitism/account-abstraction/blob/develop/eip/EIPS/eip-aa-rules.md#storage-rules
            // see: STO-032, and STO-033
            if (debugStep.contractAddr == factory && factoryStakeInfo.stake > 0 && factoryStakeInfo.unstakeDelaySec > 0)
            {
                continue;
            }
            if (
                debugStep.contractAddr == paymaster && paymasterStakeInfo.stake > 0
                    && paymasterStakeInfo.unstakeDelaySec > 0
            ) {
                continue;
            }

            address sender = userOp.sender;

            // account storage access is allowed, including address associated storage
            if (debugStep.contractAddr == sender) {
                // Slots of contract A address itself
                continue;
            }

            bytes32 key = bytes32(debugStep.stack[0]);

            bool isAssociated;
            for (uint256 j = 0; j < associatedSlots.length; j++) {
                if (key == associatedSlots[j]) {
                    isAssociated = true;
                    break;
                }
            }
            if (isAssociated) {
                continue;
            }

            failureLogs.push(FailureLog({
                errorMsg: string(abi.encodePacked(
                    "non-associated slot: key: [", Strings.toHexString(uint256(key)),
                    "], sender address: [", Strings.toHexString(sender), "]"
                )),
                contractAddr: debugStep.contractAddr
            }));

            result = false;
        }

        return result;
    }


    /**
     * May not invokes any forbidden opcodes
     * Must not use GAS opcode (unless followed immediately by one of { CALL, DELEGATECALL, CALLCODE, STATICCALL }.)
     */
    function validateForbiddenOpcodes(uint256[] memory debugStepsIndexes) private returns (bool) {
        bool result = true;
        for (uint256 i = 0; i < debugStepsIndexes.length; i++) {
            uint256 index = debugStepsIndexes[i];
            Vm.DebugStep memory debugStep = getDebugTraceByIndex(index);
            uint8 opcode = debugStep.opcode;
            if (isForbiddenOpcode(opcode)) {
                // exception case for GAS opcode
                if (opcode == 0x5A && i < debugStepsIndexes.length - 1) {
                    uint256 nextIndex = debugStepsIndexes[i+1];
                    Vm.DebugStep memory nextDebugStep = getDebugTraceByIndex(nextIndex);
                    if (!isValidNextOpcodeOfGas(nextDebugStep.opcode)) {
                        failureLogs.push(FailureLog({
                            errorMsg: string(abi.encodePacked(
                                "forbidden GAS op-code usage, next opcode after GAS: [", Strings.toHexString(nextDebugStep.opcode), "]"
                            )),
                            contractAddr: debugStep.contractAddr
                        }));
                        result = false;
                    }
                } else {
                    failureLogs.push(FailureLog({
                        errorMsg: string(abi.encodePacked(
                            "forbidden op-code usage. opcode: [", Strings.toHexString(opcode), "]"
                        )),
                        contractAddr: debugStep.contractAddr
                    }));
                    result = false;
                }
            }
        }
        return result;
    }

    /**
     * Limitation on “CALL” opcodes (CALL, DELEGATECALL, CALLCODE, STATICCALL):
     * ✅ 1. must not use value (except from account to the entrypoint)
     * ✅ 2. must not revert with out-of-gas
     * ✅ 3. destination address must have code (EXTCODESIZE>0) or be a standard Ethereum precompile defined at addresses from 0x01 to 0x09
     * ✅ 4. cannot call EntryPoint’s methods, except depositTo (to avoid recursion)
     */
    function validateCall(uint256[] memory debugStepsIndexes, address entryPoint, bool isFromAccount)
        private
        returns (bool)
    {
        bool result = true;
        for (uint256 i = 0; i < debugStepsIndexes.length; i++) {
            uint256 index = debugStepsIndexes[i];
            Vm.DebugStep memory debugStep = getDebugTraceByIndex(index);

            // the current mechanism will only record the instruction result on the last opcode
            // that failed. It will not go all the way back to the call related opcode so
            // need to call this before filtering
            if (debugStep.isOutOfGas) {
                failureLogs.push(FailureLog({
                    errorMsg: "CALL must not revert with out-of-gas",
                    contractAddr:  debugStep.contractAddr
                }));
                result = false;
            }

            // we only care about OPCODES related to calls, so filter out those unrelated.
            uint8 op = debugStep.opcode;
            if (
                op != 0xF1 /*CALL*/ && op != 0xF2 /*CALLCODE*/ && op != 0xF4 /*DELEGATECALL*/ && op != 0xFA /*STATICCALL*/
            ) {
                continue;
            }

            if (isCallWithValue(debugStep, entryPoint, isFromAccount)) {
                failureLogs.push(FailureLog({
                    errorMsg: "CALL must not use value (except from account to the entrypoint)",
                    contractAddr: debugStep.contractAddr
                }));
                result = false;
            }
            if (!isPrecompile(debugStep) && isCallWithEmptyCode(debugStep)) {
                address dest = address(uint160(debugStep.stack[1]));

                failureLogs.push(FailureLog({
                    errorMsg: string(abi.encodePacked(
                        "CALL destination address must have code or be precompile. ",
                        "Dest: [", Strings.toHexString(dest), "]", "OP: [", Strings.toHexString(op), "]"
                    )),
                    contractAddr: debugStep.contractAddr
                }));

                result = false;
            }
            if (isCallToEntryPoint(debugStep, entryPoint)) {
                failureLogs.push(FailureLog({
                    errorMsg: "cannot call EntryPoint methods, except depositTo",
                    contractAddr: debugStep.contractAddr
                }));

                result = false;
            }
        }
        return result;
    }

    function validateExtcodeMayNotAccessAddressWithoutCode(uint256[] memory debugStepsIndexes)
        private
        returns (bool)
    {
        bool result = true;
        for (uint256 i = 0; i < debugStepsIndexes.length; i++) {
            uint256 index = debugStepsIndexes[i];
            Vm.DebugStep memory debugStep = getDebugTraceByIndex(index);

            uint8 op = debugStep.opcode;
            // EXTCODEHASH, EXTCODELENGTH, EXTCODECOPY
            if (op != 0x3B && op != 0x3C && op != 0x3F) {
                continue;
            }

            address addr = address(uint160(debugStep.stack[0]));
            if (isEmptyCodeAddress(addr)) {
                failureLogs.push(FailureLog({
                    errorMsg: string(abi.encodePacked(
                        "Access address with no code. "
                        "EXT OP: [", Strings.toHexString(op), "]"
                    )),

                    contractAddr: debugStep.contractAddr
                }));
                result = false;
            }
        }
        return result;
    }

    function validateCreate2(uint256[] memory debugStepsIndexes, UserOperation memory userOp)
        private
        returns (bool)
    {
        uint256 create2Cnt = 0;
        bool result = true;
        for (uint256 i = 0; i < debugStepsIndexes.length; i++) {
            uint256 index = debugStepsIndexes[i];
            Vm.DebugStep memory debugStep = getDebugTraceByIndex(index);


            if (debugStep.opcode == 0xF5 /*CREATE2*/ ) {
                create2Cnt += 1;
            }

            if (create2Cnt == 1 && userOp.initCode.length == 0) {
                failureLogs.push(FailureLog({
                    errorMsg: "Has CREATE2 opcode call but op.initcode.length == 0",
                    contractAddr: debugStep.contractAddr
                }));
                result = false;
            }

            if (create2Cnt > 1) {
                failureLogs.push(FailureLog({
                    errorMsg: "Allow at most one CREATE2 opcode call only when op.initcode.length != 0",
                    contractAddr: debugStep.contractAddr
                }));
                result = false;
            }
        }
        return result;
    }

    function isForbiddenOpcode(uint8 opcode) private pure returns (bool) {
        return opcode == 0x3A // GASPRICE
            || opcode == 0x45 // GASLIMIT
            || opcode == 0x44 // DIFFICULTY
            || opcode == 0x42 // TIMESTAMP
            || opcode == 0x48 // BASEFEE
            || opcode == 0x40 // BLOCKHASH
            || opcode == 0x43 // NUMBER
            || opcode == 0x47 // SELFBALANCE
            || opcode == 0x31 // BALANCE
            || opcode == 0x32 // ORIGIN
            || opcode == 0x5A // GAS
            || opcode == 0xF0 // CREATE
            || opcode == 0x41 // COINBASE
            || opcode == 0xFF; // SELFDESTRUCT
    }

    function isValidNextOpcodeOfGas(uint8 nextOpcode) private pure returns (bool) {
        return nextOpcode == 0xF1 // CALL
            || nextOpcode == 0xF4 // DELEGATECALL
            || nextOpcode == 0xF2 // CALLCODE
            || nextOpcode == 0xFA; // STATICCALL
    }

    function isCallWithValue(Vm.DebugStep memory debugStep, address entryPoint, bool isFromAccount)
        private
        pure
        returns (bool)
    {
        uint8 op = debugStep.opcode;
        // only the following two has value, delegate call and static call does not have
        if (op == 0xF1 /*CALL*/ || op == 0xF2 /*CALLCODE*/ ) {
            address dest = address(uint160(debugStep.stack[1]));
            uint256 value = debugStep.stack[2];
            // exception, allow account to call entrypoint with value
            if (value > 0 && (isFromAccount && dest != entryPoint)) {
                return true;
            }
        }
        return false;
    }

    function isCallWithEmptyCode(Vm.DebugStep memory debugStep) private view returns (bool) {
        address dest = address(uint160(debugStep.stack[1]));

        return isEmptyCodeAddress(dest);
    }

    function isPrecompile(Vm.DebugStep memory debugStep) private pure returns (bool) {
        address dest = address(uint160(debugStep.stack[1]));

        // precompile contracts
        if (dest >= address(0x01) && dest <= address(0x09)) {
            return true;
        }

        // address used for console and console2 for debugging
        // this is not of the original spec, but just for forge test convinience.
        if (dest == address(0x000000000000000000636F6e736F6c652e6c6f67)) {
            return true;
        }

        return false;
    }

    function isCallToEntryPoint(Vm.DebugStep memory debugStep, address entryPoint) private pure returns (bool) {
        address dest = address(uint160(debugStep.stack[1]));
        uint8[] memory memoryData = debugStep.memoryData;
        bytes4 selector;

        if (memoryData.length >= 4) {
            selector = bytes4(abi.encodePacked(memoryData[0], memoryData[1], memoryData[2], memoryData[3]));
        }

        // note: the check againts selector != bytes4(0) is not really from the spec, but the BaseAccount will return fund
        // not sure if it is an implementation issue but intention wise, it is fine.
        if (dest == entryPoint && selector != bytes4(0) && selector != bytes4(keccak256("depositTo(address)"))) {
            return true;
        }

        return false;
    }

    function isEmptyCodeAddress(address addr) private view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }

        return size == 0;
    }


    function getRelativeDebugSteps(
        uint256 stepsSize,
        UserOperation memory userOp,
        EntryPoint entryPoint
    )   private
        returns (uint256[] memory, uint256[] memory)
    {
        uint256[] memory senderStepsIndexes = new uint256[](stepsSize);
        uint128 senderStepsLen = 0;

        address paymaster = getPaymasterAddr(userOp);
        uint256[] memory paymasterStepsIndexes = new uint256[](stepsSize);
        uint128 paymasterStepsLen = 0;

        // We only cares the steps from Entrypoint -> validateUserOp() and validatePaymasterUserOp()
        // The implementation here filter out those steps not in these call by checking the depth and the contract being called.
        // The `baseDepth` here uses the first "depth" observed when calling the entrypoint.
        uint256 baseDepth = 0;
        for (uint256 i = 0; i < stepsSize; i++) {
            Vm.DebugStep memory step = getDebugTraceByIndex(i);
            if (step.contractAddr == address(entryPoint)) {
                baseDepth = step.depth;
                break;
            }
        }
        require(baseDepth != 0, "does not call the entrypoint"); // sanity check

        address currentAddr;
        for (uint256 i = 0; i < stepsSize; i++) {
            Vm.DebugStep memory step = getDebugTraceByIndex(i);

            // Filter out those steps where we do not need to apply the ERC4337 restriction.
            //
            // The current implementation assumes that there is only one call to the account (sender) address and
            // only one call to the paymaster during the simuate validation call (depth == 2), which matches the
            // current reference entrypoint contract implementation.
            if (step.depth == baseDepth && step.contractAddr == address(entryPoint)) {
                uint8 opcode = step.opcode;
                if (opcode == 0xF1 || opcode == 0xFA) {
                    // CALL and STATICCALL
                    currentAddr = address(uint160(step.stack[1]));
                }

                // ignore all opcodes on baseDepth and do not add to the mapping
                continue;
            }

            if (step.depth > baseDepth && currentAddr == userOp.sender) {
                senderStepsIndexes[senderStepsLen++] = i;
            }

            if (step.depth > baseDepth && currentAddr == paymaster) {
                paymasterStepsIndexes[paymasterStepsLen++] = i;
            }
        }

        // Reset the steps arrays to correct length
        assembly {
            mstore(senderStepsIndexes, senderStepsLen)
        }
        assembly {
            mstore(paymasterStepsIndexes, paymasterStepsLen)
        }

        return (senderStepsIndexes, paymasterStepsIndexes);
    }

    function findAddressAssociatedSlots(address addr, uint256[] memory debugStepsIndexes)
        private
        returns (bytes32[] memory)
    {
        bytes32[] memory associatedSlots = new bytes32[](debugStepsIndexes.length * 128);
        uint256 slotLen = 0;

        for (uint256 i = 0; i < debugStepsIndexes.length; i++) {
            uint256 index = debugStepsIndexes[i];
            Vm.DebugStep memory debugStep = getDebugTraceByIndex(index);

            uint8 opcode = debugStep.opcode;

            if (opcode != 0x20 /*SHA3*/ ) {
                continue;
            }

            // find the inputs for the KECCAK256
            bytes memory input = new bytes(debugStep.memoryData.length);
            for (uint256 j = 0; j < debugStep.memoryData.length; j++) {
                input[j] = bytes1(debugStep.memoryData[j]);
            }

            address inputStartAddr = address(uint160(uint256(bytes32(input))));
            if (input.length >= 20 && inputStartAddr == addr) {
                // Slots of type keccak256(A || X) + n, n in range [0, 128]
                for (uint256 j = 0; j < 128; j++) {
                    unchecked {
                        associatedSlots[slotLen++] = bytes32(uint256(keccak256(input)) + j);
                    }
                }
            }
        }

        // Reset to correct length
        assembly {
            mstore(associatedSlots, slotLen)
        }

        return associatedSlots;
    }

    function getStakeInfo(address addr, EntryPoint entryPoint) internal view returns (IStakeManager.StakeInfo memory) {
        IStakeManager.DepositInfo memory depositInfo = entryPoint.getDepositInfo(addr);

        return IStakeManager.StakeInfo({stake: depositInfo.stake, unstakeDelaySec: depositInfo.unstakeDelaySec});
    }

    function getFactoryAddr(UserOperation memory userOp) private pure returns (address) {
        bytes memory initCode = userOp.initCode;
        return initCode.length >= 20 ? address(bytes20(initCode)) : address(0);
    }

    function getPaymasterAddr(UserOperation memory userOp) private pure returns (address) {
        bytes memory pData = userOp.paymasterAndData;
        return pData.length >= 20 ? address(bytes20(pData)) : address(0);
    }


    function allocateDebugStepMemory() private pure returns (uint256) {
        uint256 stepMemPtr;

        assembly {
            // Get the current free memory pointer
            stepMemPtr := mload(0x40)

            // Update free memory pointer to reserve memory for the struct
            mstore(0x40, add(stepMemPtr, DEBUG_STEP_ALLOCATION_SIZE))
        }

        return stepMemPtr;
    }


    // This function attemps to do the following call:
    // `Vm.DebugStep memory step = vm.getDebugTraceByIndex(i);`
    // but enforcing the `step` to reuse the same EVM memory allocation slot to avoid
    // out of memory error.
    function getDebugTraceByIndex(uint256 index) private returns (Vm.DebugStep memory step) {
        // step = vm.getDebugTraceByIndex(index);
        // return step;

        address vmAddress = address(vm);
        bytes4 selector = bytes4(keccak256("getDebugTraceByIndex(uint256)"));

        uint256 outputPtr = debugStepPtr;

        // Fetch the DebugStep into the preallocated memory
        assembly {
            // Allocate memory for the function selector and argument (i)
            // let ptr := mload(0x40) // Get the free memory pointer

            // Function selector for getDebugTraceByIndex(uint256)
            mstore(outputPtr, selector)

            // Store the argument 'index' (which is a uint256) right after the selector
            mstore(add(outputPtr, 0x04), index)

            // Make the call to vm.getDebugTraceByIndex(i)
            let success := call(
                gas(),
                vmAddress,
                0,                              // zero ETH
                outputPtr,                           // Input data starts at `ptr`
                0x24,                          // Input data size (4 bytes for selector + 32 bytes for i)
                outputPtr,                     // Output will be written to fixed pointer
                DEBUG_STEP_ALLOCATION_SIZE     // Output size
            )

            // Check if the call was successful
            if iszero(success) {
                revert(0, 0)
            }

            // Read where the struct pointer is in
            step := add(outputPtr, mload(outputPtr))

            // the returned "pointer" value will be based on zero
            // so need to shift to where the "step" data starts
            // override for `stack` field
            // stack is a uint256[] array and is the first field
            mstore(step, add(step, mload(step)))
            // override for `memoryData` field
            // `memoryData` is `uint8[]` and is the second field
            mstore(add(step, 0x20), add(step, mload(add(step, 0x20))))
        }

        return step;
    }
}
