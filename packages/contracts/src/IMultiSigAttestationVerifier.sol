// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

/// @title IMultiSigAttestationVerifier
/// @notice Interface for the multi-signer ECDSA attestation verifier.
///
/// @dev Sprint 15: Service-layer threshold attestation execution layer.
///
///      This verifier handles the ECDSA recovery and authorization check
///      for multi-signer attestations. The TransferVault calls recoverSigners()
///      and enforces the threshold count returned.
///
///      Security model:
///        - Only authorized signers (addSigner/removeSigner allowlist) contribute
///          to the recovered count.
///        - Duplicate signatures from the same address are de-duplicated and
///          counted as one (prevents signature stuffing).
///        - Unauthorized recovered addresses are silently excluded from the return set.
///
///      Honest framing (Sprint 13 oracle position unchanged):
///        - This is Phase 3 service-layer multi-sig — not on-chain contract enforcement.
///        - attestationModel remains 'SINGLE_SIGNER_PER_ATTEST' for the existing
///          attest() / AttestationVerifier path.
///        - attestMultiSig() uses this verifier for ECDSA threshold enforcement.
interface IMultiSigAttestationVerifier {
    // ── Events ───────────────────────────────────────────────────────────────

    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);

    // ── Core ─────────────────────────────────────────────────────────────────

    /// @notice Recover authorized signers from a set of ECDSA signatures over payloadHash.
    ///
    /// @param payloadHash The 32-byte hash that was signed (plain keccak256 or EIP-191 prefixed —
    ///                    callers must use a consistent scheme; no prefix is added here).
    /// @param signatures  Array of 65-byte signatures in abi.encodePacked(r, s, v) format.
    ///                    v must be 27 or 28 (compact-format 0/1 is normalised).
    ///                    High-s signatures are rejected per EIP-2.
    ///
    /// @return recovered Ordered array of UNIQUE authorized signer addresses recovered from
    ///                   the provided signatures. Length == number of valid authorized signers.
    ///                   Unauthorized addresses and duplicates are excluded.
    function recoverSigners(
        bytes32 payloadHash,
        bytes[] calldata signatures
    ) external view returns (address[] memory recovered);

    // ── Signer management ────────────────────────────────────────────────────

    function isAuthorizedSigner(address signer) external view returns (bool);
    function addSigner(address signer) external;
    function removeSigner(address signer) external;
}
