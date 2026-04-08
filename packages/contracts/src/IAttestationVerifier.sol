// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

/// @title IAttestationVerifier
/// @notice Validates oracle-signed attestation payloads.
/// @dev Checks: signer authorization, chain binding, vault binding, expiry, payload integrity.
interface IAttestationVerifier {
    // ── Structs ──────────────────────────────────────────────────────────────

    struct DecodedAttestation {
        bytes32 id;
        address vault;
        uint256 chainId;
        uint256 issuedAt;
        uint256 expiresAt;
        bytes32 templateId;
        bytes32 evidenceHash;
        address signer;
    }

    /// @notice Returned by decodeAttestation() for off-chain/inspection use.
    struct AttestationInspection {
        bool sigValid;    /// Signature recovered and signer is authorized
        bool expired;     /// block.timestamp >= decoded.expiresAt
        bool chainMatch;  /// decoded.chainId == block.chainid
        DecodedAttestation decoded;
    }

    // ── Events ───────────────────────────────────────────────────────────────

    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);

    // ── Functions ────────────────────────────────────────────────────────────

    /// @notice VAULT-ONLY ON-CHAIN VALIDATION PATH.
    /// @dev Intended to be called exclusively by TransferVault.attest(). Enforces vault
    ///      binding by checking decoded.vault == msg.sender. When called by any other
    ///      address, returns (false, empty) because msg.sender will not match the vault
    ///      address encoded in the attestation. Do NOT use for off-chain inspection —
    ///      use decodeAttestation() instead.
    /// @param encodedAttestation ABI-encoded attestation payload (224 bytes, 7 × 32-byte fields)
    /// @param signature          65-byte ECDSA signature: abi.encodePacked(r, s, v)
    /// @return valid    True iff: signer authorized, not expired, chainId matches, vault == msg.sender
    /// @return decoded  Decoded attestation fields (only meaningful when valid == true)
    function verify(
        bytes calldata encodedAttestation,
        bytes calldata signature
    ) external view returns (bool valid, DecodedAttestation memory decoded);

    /// @notice READ-ONLY INSPECTION PATH for off-chain tooling, monitoring, and operator consoles.
    /// @dev Does NOT enforce vault binding (no msg.sender check). Returns individual validity flags
    ///      so callers can distinguish the failure reason. Safe to call from any context.
    /// @param encodedAttestation ABI-encoded attestation payload
    /// @param signature          65-byte ECDSA signature
    /// @return inspection        Struct with sigValid, expired, chainMatch flags plus decoded fields
    function decodeAttestation(
        bytes calldata encodedAttestation,
        bytes calldata signature
    ) external view returns (AttestationInspection memory inspection);

    /// @notice Check whether an address is an authorized oracle signer.
    function isAuthorizedSigner(address signer) external view returns (bool);

    /// @notice Add an authorized oracle signer (owner only).
    function addSigner(address signer) external;

    /// @notice Remove an authorized oracle signer (owner only).
    function removeSigner(address signer) external;
}
