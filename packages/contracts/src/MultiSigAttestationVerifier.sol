// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "./IMultiSigAttestationVerifier.sol";

/// @title MultiSigAttestationVerifier — governance-controlled multi-signer ECDSA verifier
/// @notice ECDSA multi-signer recovery and authorization for threshold attestations.
///
/// @dev DD Sprint F — Perplexity audit High finding remediation:
///        The legacy single-key `owner()` pattern has been replaced with the
///        AfterchainGovernance multisig+timelock pattern that already governs
///        AttestationVerifier (Sprint SEC-10) and FeeTermsVerifier (Sprint SEC-8).
///        addSigner / removeSigner are now `onlyGovernance` — every signer
///        roster mutation requires a 3-of-5 governance multisig action +
///        24h on-chain timelock. No single key has any authority over the
///        verifier roster.
///
///      Design principles (preserved from Sprint 15):
///        - Pure ECDSA recovery via ecrecover — no external dependencies.
///        - Authorized signer allowlist controlled by AfterchainGovernance.
///        - Duplicate recovery de-duplication: same address from multiple sigs = 1 vote.
///        - High-s signature rejection per EIP-2 (prevents malleability).
///        - v normalisation: compact-format 0/1 → 27/28.
///        - Unauthorized recovered addresses are excluded, not reverted.
///        - Revocation: removeSigner does NOT invalidate existing ATTESTED vaults; it only
///          prevents that address from contributing to future thresholds.
///
///      This contract does NOT enforce thresholds — that responsibility lies with
///      TransferVault.attestMultiSig(), which compares recovered.length >= threshold.
contract MultiSigAttestationVerifier is IMultiSigAttestationVerifier {
    // ── Governance state ─────────────────────────────────────────────────────
    //
    // DD Sprint F — every signer-roster mutation must originate from
    // AfterchainGovernance. There is no `owner()` getter and no single-key
    // mutation path.

    address public immutable governance;
    mapping(address => bool) private _authorizedSigners;

    // ── Errors ───────────────────────────────────────────────────────────────

    error NotGovernance(address caller);
    error ZeroAddress();
    error AlreadySigner(address signer);
    error NotASigner(address signer);

    // ── Constructor ──────────────────────────────────────────────────────────

    /// @param governance_     AfterchainGovernance contract — sole authority
    ///                        for signer roster changes after construction.
    /// @param initialSigners  Optional initial signer roster, seeded
    ///                        atomically at construction. Pass an empty array
    ///                        to defer all roster setup to a governance
    ///                        action. Duplicates and the zero address are
    ///                        rejected.
    constructor(address governance_, address[] memory initialSigners) {
        if (governance_ == address(0)) revert ZeroAddress();
        governance = governance_;
        for (uint256 i = 0; i < initialSigners.length; i++) {
            address s = initialSigners[i];
            if (s == address(0))         revert ZeroAddress();
            if (_authorizedSigners[s])   revert AlreadySigner(s);
            _authorizedSigners[s] = true;
            emit SignerAdded(s);
        }
    }

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        _;
    }

    // ── IMultiSigAttestationVerifier: core ───────────────────────────────────

    /// @inheritdoc IMultiSigAttestationVerifier
    ///
    /// @dev Algorithm:
    ///        For each signature:
    ///          1. Recover address from (payloadHash, sig).
    ///          2. If address(0) or not authorized → skip.
    ///          3. If already in result set → skip (de-duplicate).
    ///          4. Add to result set.
    ///        Return result set.
    ///
    ///      Gas: O(n²) de-duplication using an in-memory seen array.
    ///           Acceptable for n ≤ 10 (governance_config.roster_capacity = 5).
    function recoverSigners(
        bytes32 payloadHash,
        bytes[] calldata signatures
    ) external view override returns (address[] memory recovered) {
        address[] memory tmp = new address[](signatures.length);
        uint256 count = 0;

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = _recoverSigner(payloadHash, signatures[i]);

            // Exclude zero address (ecrecover failure or invalid sig)
            if (signer == address(0)) continue;

            // Exclude unauthorized signers
            if (!_authorizedSigners[signer]) continue;

            // De-duplicate: skip if signer already in result set
            bool duplicate = false;
            for (uint256 j = 0; j < count; j++) {
                if (tmp[j] == signer) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) continue;

            tmp[count] = signer;
            count++;
        }

        // Trim to actual count
        recovered = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            recovered[i] = tmp[i];
        }
    }

    // ── IMultiSigAttestationVerifier: signer management (governance only) ───

    /// @inheritdoc IMultiSigAttestationVerifier
    function isAuthorizedSigner(address signer) external view override returns (bool) {
        return _authorizedSigners[signer];
    }

    /// @inheritdoc IMultiSigAttestationVerifier
    /// @dev DD Sprint F — onlyGovernance. Production callers must queue an
    ///      AfterchainGovernance action targeting this contract; the action
    ///      requires 3-of-5 multisig approval and a 24h on-chain timelock
    ///      before execution.
    function addSigner(address signer) external override onlyGovernance {
        if (signer == address(0))       revert ZeroAddress();
        if (_authorizedSigners[signer]) revert AlreadySigner(signer);
        _authorizedSigners[signer] = true;
        emit SignerAdded(signer);
    }

    /// @inheritdoc IMultiSigAttestationVerifier
    /// @dev DD Sprint F — onlyGovernance.
    function removeSigner(address signer) external override onlyGovernance {
        if (!_authorizedSigners[signer]) revert NotASigner(signer);
        _authorizedSigners[signer] = false;
        emit SignerRemoved(signer);
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    /// @dev Recover the ECDSA signer from a 65-byte signature over payloadHash.
    ///      Signature format: abi.encodePacked(r, s, v), v ∈ {27, 28}.
    ///      Normalises compact v (0/1 → 27/28).
    ///      Rejects high-s (malleable) signatures per EIP-2.
    ///      Returns address(0) on any invalid input — never reverts.
    function _recoverSigner(bytes32 payloadHash, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }

        // Normalise compact-format v (0/1 → 27/28)
        if (v < 27) v += 27;

        // Reject v values other than 27 or 28
        if (v != 27 && v != 28) return address(0);

        // Reject high-s (malleable) signatures — secp256k1 group order n/2
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }

        return ecrecover(payloadHash, v, r, s);
    }
}
