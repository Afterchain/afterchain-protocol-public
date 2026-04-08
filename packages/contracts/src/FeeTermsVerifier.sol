// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "./IFeeTermsVerifier.sol";

/// @title FeeTermsVerifier — EIP-712 fee-terms signature verifier (SEC-6).
/// @notice Mirror of AttestationVerifier's pattern but for FeeTermsPayload.
///         Owner-controlled allow-list of authorized oracle signers. The
///         TransferVault uses this to bind the official commercial fee flow
///         to oracle signatures — a fork of the open rail cannot forge a
///         signature from this roster.
contract FeeTermsVerifier is IFeeTermsVerifier {
    // ── EIP-712 domain ───────────────────────────────────────────────────────

    bytes32 public constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @inheritdoc IFeeTermsVerifier
    bytes32 public immutable override DOMAIN_SEPARATOR;

    /// @notice Immutable protocol treasury for Afterchain licensing fee enforcement.
    /// @dev    Set at deployment time and can never be changed. TransferVault reads
    ///         this value and uses it as a fallback when a signed fee-terms payload
    ///         does not supply an explicit `feeRecipientAfterchain`. The treasury
    ///         address is bound to this verifier — forking the open rail is possible
    ///         but cannot redirect fees to a different treasury without forging an
    ///         Afterchain oracle signature over the alternative address.
    address public immutable PROTOCOL_TREASURY;

    // ── Governance state (Sprint SEC-8) ──────────────────────────────────────
    //
    // The owner() pattern is GONE. Every mutation to the signer roster or
    // the threshold must flow through AfterchainGovernance, which enforces
    // its own multisig + timelock pipeline. This contract only exposes
    // governance-gated mutators and pure verification functions.

    address public immutable governance;
    mapping(address => bool) private _authorizedSigners;
    address[] private _signerList;
    /// @notice Threshold of unique authorized signatures required by
    ///         verifyDigestMultiSig. Governance may raise or lower this
    ///         within the bounds 1 <= threshold <= signerCount.
    uint256 public threshold;

    // ── Errors ───────────────────────────────────────────────────────────────

    error NotGovernance(address caller);
    error ZeroAddress();
    error AlreadySigner(address signer);
    error NotASigner(address signer);
    error InvalidThreshold(uint256 proposed, uint256 signerCount);
    error ThresholdNotMet(uint256 recovered, uint256 threshold);

    // ── Events ───────────────────────────────────────────────────────────────

    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ThresholdChanged(uint256 oldThreshold, uint256 newThreshold);

    /// @param governance_       AfterchainGovernance contract address. Zero is rejected.
    /// @param protocolTreasury_ Immutable treasury fallback. Zero is rejected.
    /// @param initialSigners    Initial signer roster. Seeded once at deploy time;
    ///                          future changes require a governance action.
    /// @param initialThreshold  Minimum unique signers required by verifyDigestMultiSig.
    constructor(
        address governance_,
        address protocolTreasury_,
        address[] memory initialSigners,
        uint256 initialThreshold
    ) {
        if (governance_ == address(0))       revert ZeroAddress();
        if (protocolTreasury_ == address(0)) revert ZeroAddress();
        if (initialSigners.length == 0)      revert InvalidThreshold(initialThreshold, 0);
        if (initialThreshold == 0 || initialThreshold > initialSigners.length) {
            revert InvalidThreshold(initialThreshold, initialSigners.length);
        }
        governance        = governance_;
        PROTOCOL_TREASURY = protocolTreasury_;
        threshold         = initialThreshold;
        for (uint256 i = 0; i < initialSigners.length; i++) {
            address s = initialSigners[i];
            if (s == address(0))     revert ZeroAddress();
            if (_authorizedSigners[s]) revert AlreadySigner(s);
            _authorizedSigners[s] = true;
            _signerList.push(s);
            emit SignerAdded(s);
        }
        emit ThresholdChanged(0, initialThreshold);
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            DOMAIN_TYPE_HASH,
            keccak256("Afterchain FeeTermsVerifier"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        _;
    }

    /// @notice Current signer count. Governance maintains signerCount >= threshold.
    function signerCount() external view returns (uint256) {
        return _signerList.length;
    }

    function signerAt(uint256 i) external view returns (address) {
        return _signerList[i];
    }

    // ── Verification ─────────────────────────────────────────────────────────

    /// @inheritdoc IFeeTermsVerifier
    function verifyDigest(
        bytes32 digest,
        bytes calldata signature
    ) external view override returns (bool valid, address signer) {
        if (signature.length != 65) return (false, address(0));
        signer = _recoverSigner(digest, signature);
        if (signer == address(0) || !_authorizedSigners[signer]) return (false, signer);
        return (true, signer);
    }

    // ── Multisig verification (Sprint SEC-8) ────────────────────────────────

    /// @notice Verify a threshold of unique authorized signatures over the
    ///         same EIP-712 digest. Duplicate signers and malleable-s
    ///         signatures are rejected.
    function verifyDigestMultiSig(
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

    // ── Signer roster (governance-controlled) ───────────────────────────────

    /// @inheritdoc IFeeTermsVerifier
    function isAuthorizedSigner(address signer) external view override returns (bool) {
        return _authorizedSigners[signer];
    }

    function addSigner(address signer) external onlyGovernance {
        if (signer == address(0)) revert ZeroAddress();
        if (_authorizedSigners[signer]) revert AlreadySigner(signer);
        _authorizedSigners[signer] = true;
        _signerList.push(signer);
        emit SignerAdded(signer);
    }

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

    // ── Internal: ECDSA recover ──────────────────────────────────────────────

    function _recoverSigner(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        // Assembly copy from calldata
        assembly ("memory-safe") {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        // Reject malleable signatures (EIP-2) — same rule as AttestationVerifier.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        if (v != 27 && v != 28) return address(0);
        return ecrecover(digest, v, r, s);
    }
}
