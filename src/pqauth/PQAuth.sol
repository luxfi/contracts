// SPDX-License-Identifier: BSD-3-Clause
// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
pragma solidity ^0.8.27;

import {IPQVerify} from "./IPQVerify.sol";

/// @title PQAuth
/// @notice Canonical Solidity helpers for post-quantum signature
///         verification on the Lux EVM. PQAuth is the single
///         implementation of IPQVerify; contracts that need to verify
///         post-quantum signatures import this library and call the
///         static functions.
///
///         Native precompile addresses (luxfi/precompile, canonical):
///         - 0x012201  ML-KEM-768           (FIPS 203, key encapsulation)
///         - 0x012202  ML-DSA verify        (FIPS 204, signatures)
///         - 0x012203  SLH-DSA verify       (FIPS 205, hash-based)
///         - 0x012204  Ringtail threshold   (lattice threshold verify)
///         - 0x002221  X-Wing hybrid KEM    (X25519 + ML-KEM-768)
///
///         The ML-DSA precompile dispatches on a mode byte:
///         - 0x44 = ML-DSA-44 (NIST L2, 75k base gas)
///         - 0x65 = ML-DSA-65 (NIST L3, 100k base gas)   <-- default
///         - 0x87 = ML-DSA-87 (NIST L5, 150k base gas)
///         All three add 10 gas per message byte.
///
///         The SLH-DSA precompile dispatches on a mode byte encoded in
///         the signature; gas ranges from ~15k (SLH-DSA-128s, large sig)
///         to ~250k (SLH-DSA-256f, fast).
///
///         Gas comparison vs Solidity-only ETHDILITHIUM (LGPL-3.0,
///         vendored ML-DSA in YUL):
///           ETHDILITHIUM verify: ~8,100,000 gas
///           PQAuth ML-DSA-65 verify (32-byte digest): 100,000 + 320 = 100,320 gas
///         => Native precompile is ~80x cheaper. Do not vendor or
///            re-implement ML-DSA in user contracts.
library PQAuth {
    // -----------------------------------------------------------------
    // Precompile addresses (canonical Lux EVM, single source of truth)
    // -----------------------------------------------------------------

    /// @dev Native ML-DSA verify precompile (FIPS 204).
    address internal constant MLDSA_PRECOMPILE = address(uint160(0x012202));

    /// @dev Native SLH-DSA verify precompile (FIPS 205).
    address internal constant SLHDSA_PRECOMPILE = address(uint160(0x012203));

    /// @dev Native ML-KEM-768 encapsulate/decapsulate (FIPS 203).
    address internal constant MLKEM_PRECOMPILE = address(uint160(0x012201));

    /// @dev Native Ringtail threshold lattice verify.
    address internal constant RINGTAIL_PRECOMPILE = address(uint160(0x012204));

    /// @dev Native X-Wing hybrid KEM (X25519 + ML-KEM-768).
    address internal constant XWING_PRECOMPILE = address(uint160(0x002221));

    // -----------------------------------------------------------------
    // ML-DSA wire constants (mirror luxfi/precompile/mldsa)
    // -----------------------------------------------------------------

    uint8 internal constant ML_DSA_44 = 0x44;
    uint8 internal constant ML_DSA_65 = 0x65;
    uint8 internal constant ML_DSA_87 = 0x87;

    uint256 internal constant ML_DSA_44_PUBKEY_LEN = 1312;
    uint256 internal constant ML_DSA_44_SIG_LEN = 2420;

    uint256 internal constant ML_DSA_65_PUBKEY_LEN = 1952;
    uint256 internal constant ML_DSA_65_SIG_LEN = 3309;

    uint256 internal constant ML_DSA_87_PUBKEY_LEN = 2592;
    uint256 internal constant ML_DSA_87_SIG_LEN = 4627;

    /// @notice TupleHash256 customisation string for the canonical
    ///         permit digest. Off-chain signers MUST recompute the digest
    ///         as TupleHash256([accountID, chainID, txTarget, nonce, deadline],
    ///         32, "LUX_PQ_PERMIT_V1") before signing. The on-chain
    ///         contract receives the 32-byte digest already computed.
    ///         There is no on-chain TupleHash256 implementation — the
    ///         EVM lacks cSHAKE256 and we refuse to fake it in pure
    ///         Solidity (~200k gas, easy to get wrong). See
    ///         luxfi/consensus/protocol/auth/hash.go for the reference
    ///         off-chain implementation.
    string internal constant PERMIT_CUSTOMIZATION = "LUX_PQ_PERMIT_V1";

    // -----------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------

    /// @dev Pubkey length does not match the mode's expected size.
    error InvalidPubkeyLength(uint8 mode, uint256 want, uint256 got);

    /// @dev Signature length does not match the mode's expected size.
    error InvalidSignatureLength(uint8 mode, uint256 want, uint256 got);

    /// @dev The precompile returned no bytes (call failed entirely).
    error PrecompileCallFailed(address precompile);

    /// @dev The signature did not verify under (pubkey, msgDigest).
    error SignatureInvalid();

    // -----------------------------------------------------------------
    // ML-DSA verification
    // -----------------------------------------------------------------

    /// @notice Verify an ML-DSA-65 signature via the native precompile.
    /// @param pubkey 1952-byte ML-DSA-65 public key.
    /// @param msgDigest 32-byte canonical message digest.
    /// @param signature 3309-byte ML-DSA-65 signature.
    /// @return ok true iff the signature verifies.
    function verifyMLDSA65(
        bytes calldata pubkey,
        bytes32 msgDigest,
        bytes calldata signature
    ) internal view returns (bool ok) {
        return _verifyMLDSA(ML_DSA_65, ML_DSA_65_PUBKEY_LEN, ML_DSA_65_SIG_LEN, pubkey, msgDigest, signature);
    }

    /// @notice Verify an ML-DSA-87 signature via the native precompile.
    function verifyMLDSA87(
        bytes calldata pubkey,
        bytes32 msgDigest,
        bytes calldata signature
    ) internal view returns (bool ok) {
        return _verifyMLDSA(ML_DSA_87, ML_DSA_87_PUBKEY_LEN, ML_DSA_87_SIG_LEN, pubkey, msgDigest, signature);
    }

    /// @notice Verify an ML-DSA-44 signature via the native precompile.
    /// @dev    L2 mode — use only where L3 is too expensive. Most
    ///         deployments should default to ML-DSA-65.
    function verifyMLDSA44(
        bytes calldata pubkey,
        bytes32 msgDigest,
        bytes calldata signature
    ) internal view returns (bool ok) {
        return _verifyMLDSA(ML_DSA_44, ML_DSA_44_PUBKEY_LEN, ML_DSA_44_SIG_LEN, pubkey, msgDigest, signature);
    }

    /// @notice Verify a permit. Convenience wrapper around
    ///         verifyMLDSA65 with the canonical permit digest semantics
    ///         documented for PERMIT_CUSTOMIZATION. Reverts on failure.
    /// @dev    The msgDigest MUST be computed off-chain as
    ///         TupleHash256(parts, 32, PERMIT_CUSTOMIZATION). The
    ///         function reverts SignatureInvalid on verify failure so
    ///         the caller can rely on a successful return for control
    ///         flow without an extra bool check.
    function verifyPermit(
        bytes calldata pubkey,
        bytes32 msgDigest,
        bytes calldata signature
    ) internal view {
        if (!verifyMLDSA65(pubkey, msgDigest, signature)) {
            revert SignatureInvalid();
        }
    }

    // -----------------------------------------------------------------
    // SLH-DSA verification
    // -----------------------------------------------------------------

    /// @notice Verify an SLH-DSA signature via the native precompile.
    /// @dev    The SLH-DSA precompile auto-detects the mode from the
    ///         signature header; no mode byte is needed at this layer.
    ///         Pubkey/signature lengths are mode-dependent and validated
    ///         inside the precompile.
    function verifySLHDSA(
        bytes calldata pubkey,
        bytes32 msgDigest,
        bytes calldata signature
    ) internal view returns (bool ok) {
        // SLH-DSA precompile expects: pubkey || uint256(msgLen) || signature || message.
        // For a 32-byte digest, msgLen = 32 and message = abi.encodePacked(msgDigest).
        bytes memory input = abi.encodePacked(pubkey, uint256(32), signature, msgDigest);
        (bool success, bytes memory ret) = SLHDSA_PRECOMPILE.staticcall(input);
        if (!success) revert PrecompileCallFailed(SLHDSA_PRECOMPILE);
        if (ret.length != 32) return false;
        // Safe: we just verified ret.length == 32, so casting the first
        // 32 bytes of `ret` to bytes32 cannot truncate.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint256(bytes32(ret)) == 1;
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// @dev Pack the ML-DSA precompile calldata per the wire format
    ///      documented in luxfi/precompile/mldsa/contract.go:
    ///        [0]                       = mode byte
    ///        [1 : 1+pubLen]            = public key
    ///        [1+pubLen : 1+pubLen+32]  = message length as uint256
    ///        [1+pubLen+32 : ...+sigLen] = signature
    ///        [...]                     = message
    ///      For our digest-only path message = abi.encodePacked(digest)
    ///      and message length = 32.
    function _verifyMLDSA(
        uint8 mode,
        uint256 pubLen,
        uint256 sigLen,
        bytes calldata pubkey,
        bytes32 msgDigest,
        bytes calldata signature
    ) private view returns (bool) {
        if (pubkey.length != pubLen) revert InvalidPubkeyLength(mode, pubLen, pubkey.length);
        if (signature.length != sigLen) revert InvalidSignatureLength(mode, sigLen, signature.length);

        bytes memory input = abi.encodePacked(
            mode,
            pubkey,
            uint256(32), // message length
            signature,
            msgDigest
        );

        (bool success, bytes memory ret) = MLDSA_PRECOMPILE.staticcall(input);
        if (!success) revert PrecompileCallFailed(MLDSA_PRECOMPILE);
        if (ret.length != 32) return false;
        // Safe: we just verified ret.length == 32, so casting the first
        // 32 bytes of `ret` to bytes32 cannot truncate.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint256(bytes32(ret)) == 1;
    }
}

/// @title PQVerify
/// @notice Concrete IPQVerify implementation. Contracts that want to
///         depend only on an address (not a library) can deploy this
///         once per chain and pass its address around. For typical
///         single-contract use, importing the PQAuth library and
///         calling the static functions directly is cheaper (no
///         external call) and is the recommended path.
contract PQVerify is IPQVerify {
    /// @inheritdoc IPQVerify
    function verifyMLDSA65(
        bytes calldata pubkey,
        bytes32 msgDigest,
        bytes calldata signature
    ) external view returns (bool ok) {
        return PQAuth.verifyMLDSA65(pubkey, msgDigest, signature);
    }

    /// @inheritdoc IPQVerify
    function verifyMLDSA87(
        bytes calldata pubkey,
        bytes32 msgDigest,
        bytes calldata signature
    ) external view returns (bool ok) {
        return PQAuth.verifyMLDSA87(pubkey, msgDigest, signature);
    }

    /// @inheritdoc IPQVerify
    function verifySLHDSA(
        bytes calldata pubkey,
        bytes32 msgDigest,
        bytes calldata signature
    ) external view returns (bool ok) {
        return PQAuth.verifySLHDSA(pubkey, msgDigest, signature);
    }

    /// @inheritdoc IPQVerify
    /// @dev zAuth proof verification is reserved for the F102/F103
    ///      tx-type 0x05 path. Until that path is wired (Option B in
    ///      the strict-PQ rollout plan), this method reverts. Do not
    ///      depend on it returning a value.
    function verifyZAuthProof(
        bytes32, /*accountID*/
        bytes32, /*txHash*/
        bytes32, /*zAuthRoot*/
        bytes calldata /*proofRef*/
    ) external pure returns (bool) {
        revert("PQVerify: zAuth proof path reserved for F102/F103 (tx-type 0x05) - not yet wired");
    }
}
