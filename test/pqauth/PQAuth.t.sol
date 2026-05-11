// SPDX-License-Identifier: BSD-3-Clause
// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {PQAuth, PQVerify} from "../../src/pqauth/PQAuth.sol";
import {IPQVerify} from "../../src/pqauth/IPQVerify.sol";

/// @dev Mock precompile that mirrors the wire format the native ML-DSA
///      precompile expects, but returns a deterministic accept/reject
///      based on the first byte of the signature. Used to drive
///      PQAuth tests without needing an end-to-end signed vector.
contract MockMLDSAPrecompile {
    fallback(bytes calldata input) external returns (bytes memory) {
        // Minimum size: mode(1) + pubkey(1952) + msgLen(32) + sig(3309) + digest(32) = 5326.
        // We accept iff signature[0] == 0xAA. The signature starts at offset 1 + 1952 + 32 = 1985.
        require(input.length >= 1985 + 1, "MockMLDSAPrecompile: short calldata");
        bool accept = input[1985] == 0xAA;
        return abi.encode(accept ? uint256(1) : uint256(0));
    }
}

contract MockSLHDSAPrecompile {
    fallback(bytes calldata input) external returns (bytes memory) {
        // Same convention: accept iff input[0] == 0xAA.
        require(input.length > 0, "MockSLHDSAPrecompile: empty calldata");
        bool accept = input[0] == 0xAA;
        return abi.encode(accept ? uint256(1) : uint256(0));
    }
}

contract PQAuthTest is Test {
    PQVerify internal verifier;

    bytes internal pubkey65;
    bytes internal validSig65;
    bytes internal invalidSig65;
    bytes32 internal msgDigest;

    function setUp() public {
        // Etch our mock at the canonical ML-DSA precompile address so
        // PQAuth.verifyMLDSA65's staticcall hits the mock.
        MockMLDSAPrecompile mldsaMock = new MockMLDSAPrecompile();
        vm.etch(PQAuth.MLDSA_PRECOMPILE, address(mldsaMock).code);

        MockSLHDSAPrecompile slhdsaMock = new MockSLHDSAPrecompile();
        vm.etch(PQAuth.SLHDSA_PRECOMPILE, address(slhdsaMock).code);

        verifier = new PQVerify();

        pubkey65 = new bytes(PQAuth.ML_DSA_65_PUBKEY_LEN);
        validSig65 = new bytes(PQAuth.ML_DSA_65_SIG_LEN);
        invalidSig65 = new bytes(PQAuth.ML_DSA_65_SIG_LEN);
        // Mark valid signature with the mock's accept byte.
        validSig65[0] = 0xAA;
        // invalidSig65 stays all zero -> rejected by mock.
        msgDigest = keccak256("LUX_PQ_PERMIT_V1_TEST_DIGEST");
    }

    // -----------------------------------------------------------------
    // verifyMLDSA65
    // -----------------------------------------------------------------

    function test_VerifyMLDSA65_ValidSignature_ReturnsTrue() public view {
        bool ok = verifier.verifyMLDSA65(pubkey65, msgDigest, validSig65);
        assertTrue(ok, "valid signature must verify");
    }

    function test_VerifyMLDSA65_InvalidSignature_ReturnsFalse() public view {
        bool ok = verifier.verifyMLDSA65(pubkey65, msgDigest, invalidSig65);
        assertFalse(ok, "invalid signature must NOT verify");
    }

    function test_VerifyMLDSA65_WrongPubkeyLength_Reverts() public {
        bytes memory badPubkey = new bytes(PQAuth.ML_DSA_65_PUBKEY_LEN - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                PQAuth.InvalidPubkeyLength.selector,
                PQAuth.ML_DSA_65,
                PQAuth.ML_DSA_65_PUBKEY_LEN,
                PQAuth.ML_DSA_65_PUBKEY_LEN - 1
            )
        );
        verifier.verifyMLDSA65(badPubkey, msgDigest, validSig65);
    }

    function test_VerifyMLDSA65_WrongSignatureLength_Reverts() public {
        bytes memory badSig = new bytes(PQAuth.ML_DSA_65_SIG_LEN + 7);
        badSig[0] = 0xAA;
        vm.expectRevert(
            abi.encodeWithSelector(
                PQAuth.InvalidSignatureLength.selector,
                PQAuth.ML_DSA_65,
                PQAuth.ML_DSA_65_SIG_LEN,
                PQAuth.ML_DSA_65_SIG_LEN + 7
            )
        );
        verifier.verifyMLDSA65(pubkey65, msgDigest, badSig);
    }

    // -----------------------------------------------------------------
    // verifyPermit (revert on invalid)
    // -----------------------------------------------------------------

    function test_VerifyPermit_ValidSignature_NoRevert() public {
        PermitHelper helper = new PermitHelper();
        helper.runPermit(pubkey65, msgDigest, validSig65);
    }

    function test_VerifyPermit_InvalidSignature_Reverts() public {
        PermitHelper helper = new PermitHelper();
        vm.expectRevert(PQAuth.SignatureInvalid.selector);
        helper.runPermit(pubkey65, msgDigest, invalidSig65);
    }

    // -----------------------------------------------------------------
    // verifySLHDSA
    // -----------------------------------------------------------------

    function test_VerifySLHDSA_ValidSignature_ReturnsTrue() public view {
        bytes memory slhPubkey = new bytes(64);
        slhPubkey[0] = 0xAA; // mock looks at input[0] = pubkey[0]
        bytes memory slhSig = new bytes(7856);
        bool ok = verifier.verifySLHDSA(slhPubkey, msgDigest, slhSig);
        assertTrue(ok, "valid SLH-DSA signature must verify");
    }

    function test_VerifySLHDSA_InvalidSignature_ReturnsFalse() public view {
        bytes memory slhPubkey = new bytes(64);
        // pubkey[0] = 0x00 -> mock rejects
        bytes memory slhSig = new bytes(7856);
        bool ok = verifier.verifySLHDSA(slhPubkey, msgDigest, slhSig);
        assertFalse(ok, "invalid SLH-DSA signature must NOT verify");
    }

    // -----------------------------------------------------------------
    // verifyZAuthProof — deferred per F102/F103
    // -----------------------------------------------------------------

    function test_VerifyZAuthProof_Reverts() public {
        vm.expectRevert(bytes("PQVerify: zAuth proof path reserved for F102/F103 (tx-type 0x05) - not yet wired"));
        verifier.verifyZAuthProof(bytes32(0), bytes32(0), bytes32(0), hex"");
    }

    // -----------------------------------------------------------------
    // Address constants — sanity (canonical addresses)
    // -----------------------------------------------------------------

    function test_CanonicalAddresses() public pure {
        assertEq(PQAuth.MLDSA_PRECOMPILE, address(uint160(0x012202)), "MLDSA addr");
        assertEq(PQAuth.SLHDSA_PRECOMPILE, address(uint160(0x012203)), "SLHDSA addr");
        assertEq(PQAuth.MLKEM_PRECOMPILE, address(uint160(0x012201)), "MLKEM addr");
        assertEq(PQAuth.CORONA_PRECOMPILE, address(uint160(0x012204)), "Corona addr");
        assertEq(PQAuth.XWING_PRECOMPILE, address(uint160(0x002221)), "XWing addr");
    }
}

/// @dev Helper that exposes the PQAuth library's verifyPermit (internal
///      linkage) through an external entry point so tests can drive it
///      with calldata-typed arguments.
contract PermitHelper {
    function runPermit(
        bytes calldata pubkey,
        bytes32 msgDigest,
        bytes calldata signature
    ) external view {
        PQAuth.verifyPermit(pubkey, msgDigest, signature);
    }
}

