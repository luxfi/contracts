// SPDX-License-Identifier: BSD-3-Clause
// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
pragma solidity ^0.8.27;

/// @title IPQVerify
/// @notice Canonical post-quantum signature verification interface for the
///         Lux EVM. Every L1 contract that needs to authenticate a
///         post-quantum signer imports this interface and calls one
///         function. The chain ships native precompiles at the addresses
///         documented in PQAuth.sol; this interface is the smallest
///         possible surface a contract should depend on.
///
///         There is exactly one canonical implementation: PQAuth.sol.
///         Re-implementing this interface in user code is a category
///         error — it would re-serialise inputs the precompile already
///         knows how to parse and would burn 50× the gas of the native
///         path.
interface IPQVerify {
    /// @notice Verify an ML-DSA-65 signature (FIPS 204, NIST Level 3).
    /// @param pubkey  1952-byte ML-DSA-65 public key.
    /// @param msgDigest 32-byte canonical message digest (see PQAuth for
    ///                  the recommended TupleHash256 customization).
    /// @param signature 3309-byte ML-DSA-65 signature.
    /// @return ok true iff the signature verifies under (pubkey, msgDigest).
    function verifyMLDSA65(
        bytes calldata pubkey,
        bytes32 msgDigest,
        bytes calldata signature
    ) external view returns (bool ok);

    /// @notice Verify an ML-DSA-87 signature (FIPS 204, NIST Level 5).
    /// @dev Use this for high-value paths where ML-DSA-65 is not sufficient.
    /// @param pubkey  2592-byte ML-DSA-87 public key.
    /// @param msgDigest 32-byte canonical message digest.
    /// @param signature 4627-byte ML-DSA-87 signature.
    /// @return ok true iff the signature verifies.
    function verifyMLDSA87(
        bytes calldata pubkey,
        bytes32 msgDigest,
        bytes calldata signature
    ) external view returns (bool ok);

    /// @notice Verify an SLH-DSA signature (FIPS 205, hash-based).
    /// @dev    Hash-based fallback for accounts that pin the SLH-DSA
    ///         recovery scheme. Signature size and verify cost depend
    ///         on the SLH-DSA mode encoded in the signature header; the
    ///         precompile dispatches internally.
    /// @param pubkey  SLH-DSA public key (mode-dependent length).
    /// @param msgDigest 32-byte canonical message digest.
    /// @param signature SLH-DSA signature (mode-dependent length).
    /// @return ok true iff the signature verifies.
    function verifySLHDSA(
        bytes calldata pubkey,
        bytes32 msgDigest,
        bytes calldata signature
    ) external view returns (bool ok);

    /// @notice Verify a zAuth proof binding accountID to txHash under a
    ///         zAuth merkle root.
    /// @dev    This is the L1-zAuth verification entry point. The proof
    ///         format is opaque to the caller; the implementation knows
    ///         how to dispatch to the underlying ZK verifier precompile
    ///         (see luxfi/precompile/zk). Reserved for the zAuth tx-type
    ///         path documented in F102 / F103.
    /// @param accountID 32-byte canonical account ID.
    /// @param txHash    32-byte transaction hash being authorised.
    /// @param zAuthRoot 32-byte zAuth merkle root the proof verifies against.
    /// @param proofRef  Opaque proof reference (calldata-resident).
    /// @return ok true iff the proof verifies.
    function verifyZAuthProof(
        bytes32 accountID,
        bytes32 txHash,
        bytes32 zAuthRoot,
        bytes calldata proofRef
    ) external view returns (bool ok);
}
