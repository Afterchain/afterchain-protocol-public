// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "./IAttestationVerifier.sol";

/// @title AttestationVerifier — governance-controlled, multisig-capable.
/// @notice Validates oracle-signed attestation payloads. Sprint SEC-10
///         migrates this contract from the legacy owner() pattern to the
///         AfterchainGovernance multisig+timelock pattern that already
///         governs FeeTermsVerifier.
///
/// @dev Attestation payload encoding (7 fields × 32 bytes = 224 bytes):
///        abi.encode(bytes32 id, address vault, uint256 chainId,
///                   uint256 issuedAt, uint256 expiresAt,
///                   bytes32 templateId, bytes32 evidenceHash)
///
///      Signature: 65-byte ECDSA over the EIP-712 typed data digest.
///
///      EIP-712 domain binds signatures to this verifier instance + chain.
///
///      Sprint SEC-10 — TWO production paths:
///        verify()              — single-signer (sandbox / threshold == 1)
///        verifyMultiSig()      — bytes[] threshold path (production)
///        verifyMultiSigForVault() — vault-only multisig path; enforces
///                                   decoded.vault == msg.sender
///
///      The signer roster + threshold are governed by AfterchainGovernance.
///      No owner() authority remains.
contract AttestationVerifier is IAttestationVerifier {
    // ── EIP-712 domain constants ─────────────────────────────────────────────

    bytes32 public constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 public constant ATTESTATION_TYPE_HASH =
        keccak256(
            "AttestationPayload(bytes32 id,address vault,uint256 chainId,uint256 issuedAt,"
            "uint256 expiresAt,bytes32 templateId,bytes32 evidenceHash)"
        );

    bytes32 public immutable DOMAIN_SEPARATOR;

    // ── Governance state (Sprint SEC-10) ─────────────────────────────────────
    //
    // Mirrors FeeTermsVerifier (Sprint SEC-8). Every mutation to the signer
    // roster or threshold MUST originate from AfterchainGovernance, which
    // enforces its own multisig + timelock pipeline.

    address public immutable governance;
    mapping(address => bool) private _authorizedSigners;
    address[] private _signerList;
    /// @notice Threshold of unique authorized signatures required by
    ///         verifyMultiSig. Governance may raise or lower this within
    ///         1 <= threshold <= signerCount.
    uint256 public threshold;

    uint256 private constant PAYLOAD_LENGTH = 224; // 7 × 32-byte ABI fields

    // ── Errors ───────────────────────────────────────────────────────────────
    error NotGovernance(address caller);
    error ZeroAddress();
    error AlreadySigner(address signer);
    error NotASigner(address signer);
    error InvalidThreshold(uint256 proposed, uint256 signerCount);

    // ── Events ───────────────────────────────────────────────────────────────
    event ThresholdChanged(uint256 oldThreshold, uint256 newThreshold);

    // ── Constructor ──────────────────────────────────────────────────────────

    /// @param governance_      AfterchainGovernance contract address.
    /// @param initialSigners   Initial signer roster (seeded once at deploy).
    /// @param initialThreshold Minimum unique signers required by verifyMultiSig.
    constructor(
        address governance_,
        address[] memory initialSigners,
        uint256 initialThreshold
    ) {
        if (governance_ == address(0))   revert ZeroAddress();
        if (initialSigners.length == 0)  revert InvalidThreshold(initialThreshold, 0);
        if (initialThreshold == 0 || initialThreshold > initialSigners.length) {
            revert InvalidThreshold(initialThreshold, initialSigners.length);
        }
        governance = governance_;
        threshold  = initialThreshold;
        for (uint256 i = 0; i < initialSigners.length; i++) {
            address s = initialSigners[i];
            if (s == address(0))       revert ZeroAddress();
            if (_authorizedSigners[s]) revert AlreadySigner(s);
            _authorizedSigners[s] = true;
            _signerList.push(s);
            emit SignerAdded(s);
        }
        emit ThresholdChanged(0, initialThreshold);

        DOMAIN_SEPARATOR = keccak256(abi.encode(
            DOMAIN_TYPE_HASH,
            keccak256("Afterchain AttestationVerifier"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        _;
    }

    function signerCount() external view returns (uint256) {
        return _signerList.length;
    }

    function signerAt(uint256 i) external view returns (address) {
        return _signerList[i];
    }

    // ── IAttestationVerifier: vault-only path (single-sig) ───────────────────

    /// @inheritdoc IAttestationVerifier
    /// @dev VAULT-ONLY. Enforces decoded.vault == msg.sender. When threshold > 1
    ///      this path will only succeed for sandbox-grade single-sig flows; the
    ///      production path is verifyMultiSigForVault().
    function verify(
        bytes calldata encodedAttestation,
        bytes calldata signature
    ) external view returns (bool valid, DecodedAttestation memory decoded) {
        if (encodedAttestation.length != PAYLOAD_LENGTH) return (false, decoded);
        if (signature.length != 65) return (false, decoded);

        decoded = _decode(encodedAttestation);

        if (decoded.vault != msg.sender)        return (false, decoded);
        if (decoded.chainId != block.chainid)    return (false, decoded);
        if (block.timestamp >= decoded.expiresAt) return (false, decoded);

        bytes32 digest = _buildDigest(decoded);
        address signer = _recoverSigner(digest, signature);
        if (!_authorizedSigners[signer]) return (false, decoded);

        // Sprint SEC-10 — single-signer accept ONLY when governance threshold
        // is 1. With threshold > 1 the single-sig path is closed; callers
        // must use verifyMultiSigForVault.
        if (threshold > 1) return (false, decoded);

        decoded.signer = signer;
        return (true, decoded);
    }

    // ── Sprint SEC-10: vault-only multisig path ──────────────────────────────

    /// @notice VAULT-ONLY threshold-multisig attestation verification.
    /// @dev Enforces decoded.vault == msg.sender. Returns valid only when the
    ///      array contains a number of UNIQUE authorized signers >= threshold.
    ///      Duplicate / unauthorized / malleable signatures are silently
    ///      dropped from the count.
    function verifyMultiSigForVault(
        bytes calldata encodedAttestation,
        bytes[] calldata signatures
    ) external view returns (bool valid, DecodedAttestation memory decoded, uint256 uniqueAuthorized) {
        if (encodedAttestation.length != PAYLOAD_LENGTH) return (false, decoded, 0);
        if (signatures.length < threshold)               return (false, decoded, 0);

        decoded = _decode(encodedAttestation);
        if (decoded.vault != msg.sender)        return (false, decoded, 0);
        if (decoded.chainId != block.chainid)    return (false, decoded, 0);
        if (block.timestamp >= decoded.expiresAt) return (false, decoded, 0);

        bytes32 digest = _buildDigest(decoded);

        address[] memory seen = new address[](signatures.length);
        uint256 count = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = _recoverSigner(digest, signatures[i]);
            if (signer == address(0) || !_authorizedSigners[signer]) continue;
            bool dup = false;
            for (uint256 j = 0; j < count; j++) {
                if (seen[j] == signer) { dup = true; break; }
            }
            if (dup) continue;
            seen[count] = signer;
            count += 1;
        }

        uniqueAuthorized = count;
        if (count < threshold) return (false, decoded, count);

        decoded.signer = seen[0];
        return (true, decoded, count);
    }

    /// @notice Pure multisig digest verification — no vault binding check.
    ///         Useful for off-chain inspection and the service-layer
    ///         attestation submission path.
    function verifyMultiSig(
        bytes32 digest,
        bytes[] calldata signatures
    ) external view returns (bool valid, uint256 uniqueAuthorized) {
        if (signatures.length < threshold) return (false, 0);
        address[] memory seen = new address[](signatures.length);
        uint256 count = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = _recoverSigner(digest, signatures[i]);
            if (signer == address(0) || !_authorizedSigners[signer]) continue;
            bool dup = false;
            for (uint256 j = 0; j < count; j++) {
                if (seen[j] == signer) { dup = true; break; }
            }
            if (dup) continue;
            seen[count] = signer;
            count += 1;
        }
        return (count >= threshold, count);
    }

    // ── IAttestationVerifier: inspection path ────────────────────────────────

    /// @inheritdoc IAttestationVerifier
    function decodeAttestation(
        bytes calldata encodedAttestation,
        bytes calldata signature
    ) external view returns (AttestationInspection memory inspection) {
        if (encodedAttestation.length != PAYLOAD_LENGTH) return inspection;
        if (signature.length != 65) return inspection;

        inspection.decoded = _decode(encodedAttestation);
        inspection.expired = block.timestamp >= inspection.decoded.expiresAt;
        inspection.chainMatch = inspection.decoded.chainId == block.chainid;

        bytes32 digest = _buildDigest(inspection.decoded);
        address signer = _recoverSigner(digest, signature);
        inspection.sigValid = _authorizedSigners[signer];

        if (inspection.sigValid) {
            inspection.decoded.signer = signer;
        }
        return inspection;
    }

    // ── IAttestationVerifier: signer management (governance only) ────────────

    /// @inheritdoc IAttestationVerifier
    function isAuthorizedSigner(address signer) external view returns (bool) {
        return _authorizedSigners[signer];
    }

    /// @inheritdoc IAttestationVerifier
    function addSigner(address signer) external onlyGovernance {
        if (signer == address(0))       revert ZeroAddress();
        if (_authorizedSigners[signer]) revert AlreadySigner(signer);
        _authorizedSigners[signer] = true;
        _signerList.push(signer);
        emit SignerAdded(signer);
    }

    /// @inheritdoc IAttestationVerifier
    function removeSigner(address signer) external onlyGovernance {
        if (!_authorizedSigners[signer]) revert NotASigner(signer);
        if (_signerList.length - 1 < threshold) {
            revert InvalidThreshold(threshold, _signerList.length - 1);
        }
        _authorizedSigners[signer] = false;
        for (uint256 i = 0; i < _signerList.length; i++) {
            if (_signerList[i] == signer) {
                _signerList[i] = _signerList[_signerList.length - 1];
                _signerList.pop();
                break;
            }
        }
        emit SignerRemoved(signer);
    }

    function setThreshold(uint256 newThreshold) external onlyGovernance {
        if (newThreshold == 0 || newThreshold > _signerList.length) {
            revert InvalidThreshold(newThreshold, _signerList.length);
        }
        uint256 old = threshold;
        threshold = newThreshold;
        emit ThresholdChanged(old, newThreshold);
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    function _decode(bytes calldata payload) internal pure returns (DecodedAttestation memory d) {
        (d.id, d.vault, d.chainId, d.issuedAt, d.expiresAt, d.templateId, d.evidenceHash) =
            abi.decode(payload, (bytes32, address, uint256, uint256, uint256, bytes32, bytes32));
    }

    function _buildDigest(DecodedAttestation memory d) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            ATTESTATION_TYPE_HASH,
            d.id,
            d.vault,
            d.chainId,
            d.issuedAt,
            d.expiresAt,
            d.templateId,
            d.evidenceHash
        ));
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    function _recoverSigner(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        return ecrecover(digest, v, r, s);
    }
}
