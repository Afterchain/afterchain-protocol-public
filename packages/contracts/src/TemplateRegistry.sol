// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "./ITemplateRegistry.sol";

/// @title TemplateRegistry — governance-controlled template registry
/// @notice Stores authorized template IDs, their config hashes, and the fee
///         mode pinned to each template. Templates bind vault configurations
///         to protocol versions; the factory validates template activity at
///         vault creation time.
///
/// @dev DD Sprint A — Finding 2.1: removes the single-key `_owner` /
///      Ownable pattern. The registry is now governed by AfterchainGovernance
///      (3-of-5 on-chain multisig + 24h timelock). The constructor accepts
///      an optional initial template so the deploy script can wire the demo
///      template atomically; every subsequent registration or revocation
///      must originate from AfterchainGovernance.
contract TemplateRegistry is ITemplateRegistry {
    /// @notice AfterchainGovernance contract — sole authority for template
    ///         registration and revocation after construction.
    address public immutable governance;

    /// @dev templateId → configHash (zero = not registered or revoked)
    mapping(bytes32 => bytes32) private _configHashes;
    mapping(bytes32 => bool) private _active;

    // ── Sprint SEC-7 Task 4 — template → fee mode binding ───────────────────
    //
    // Governance pins each template to a single fee mode at registration
    // time. TransferVault.executeWithFees() reads this value and rejects any
    // signed fee-terms payload whose feeModel does not match. This prevents
    // a LICENSED_SPLIT template from being "downgraded" to DIRECT_PROTOCOL
    // at execution time even if an oracle signed such a payload.
    //
    // Encoding mirrors FeeTerms.FEE_MODEL_* constants:
    //   0 = LICENSED_SPLIT
    //   1 = DIRECT_PROTOCOL
    //   2 = LOW_BALANCE
    //   255 = UNSET — legacy templates registered before SEC-7. executeWithFees
    //                 accepts any mode when the template is UNSET.
    uint8 public constant FEE_MODE_UNSET = 255;
    mapping(bytes32 => uint8) private _feeMode;

    event TemplateFeeModeSet(bytes32 indexed templateId, uint8 feeMode);

    // ── Errors ───────────────────────────────────────────────────────────────
    error ZeroAddress();
    error NotGovernance(address caller);
    error TemplateNotFound(bytes32 templateId);
    error TemplateAlreadyRegistered(bytes32 templateId);
    error TemplateFeeModeInvalid(uint8 feeMode);

    /// @param governance_       AfterchainGovernance contract — sole authority
    ///                          after construction.
    /// @param initialTemplateId Optional template to register atomically at
    ///                          construction. Pass bytes32(0) to skip.
    /// @param initialConfigHash Config hash for the initial template.
    /// @param initialFeeMode    Pinned fee mode for the initial template.
    constructor(
        address governance_,
        bytes32 initialTemplateId,
        bytes32 initialConfigHash,
        uint8   initialFeeMode
    ) {
        if (governance_ == address(0)) revert ZeroAddress();
        governance = governance_;

        if (initialTemplateId != bytes32(0)) {
            if (initialFeeMode > 2 && initialFeeMode != FEE_MODE_UNSET) {
                revert TemplateFeeModeInvalid(initialFeeMode);
            }
            _configHashes[initialTemplateId] = initialConfigHash;
            _active[initialTemplateId]       = true;
            _feeMode[initialTemplateId]      = initialFeeMode;
            emit TemplateRegistered(initialTemplateId, initialConfigHash);
            emit TemplateFeeModeSet(initialTemplateId, initialFeeMode);
        }
    }

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        _;
    }

    // ── ITemplateRegistry ────────────────────────────────────────────────────

    /// @inheritdoc ITemplateRegistry
    /// @dev DD Sprint A — Finding 2.1: governance-only. Legacy entry point
    ///      that registers the template with FEE_MODE_UNSET. SEC-7-aware
    ///      governance actions should use registerTemplateWithFeeMode().
    function registerTemplate(bytes32 templateId, bytes32 configHash) external onlyGovernance {
        if (_active[templateId]) revert TemplateAlreadyRegistered(templateId);
        _configHashes[templateId] = configHash;
        _active[templateId]       = true;
        _feeMode[templateId]      = FEE_MODE_UNSET;
        emit TemplateRegistered(templateId, configHash);
    }

    /// @notice Register a template with a fee mode binding (SEC-7 Task 4).
    /// @dev DD Sprint A — Finding 2.1: governance-only. The bound fee mode
    ///      is enforced on-chain at executeWithFees() time.
    function registerTemplateWithFeeMode(
        bytes32 templateId,
        bytes32 configHash,
        uint8   feeMode
    ) external onlyGovernance {
        if (_active[templateId]) revert TemplateAlreadyRegistered(templateId);
        if (feeMode > 2 && feeMode != FEE_MODE_UNSET) revert TemplateFeeModeInvalid(feeMode);
        _configHashes[templateId] = configHash;
        _active[templateId]       = true;
        _feeMode[templateId]      = feeMode;
        emit TemplateRegistered(templateId, configHash);
        emit TemplateFeeModeSet(templateId, feeMode);
    }

    /// @notice Fee mode pinned to a template (255 = UNSET, see FEE_MODE_UNSET).
    function feeModeOf(bytes32 templateId) external view returns (uint8) {
        return _feeMode[templateId];
    }

    /// @inheritdoc ITemplateRegistry
    /// @dev DD Sprint A — Finding 2.1: governance-only.
    function revokeTemplate(bytes32 templateId) external onlyGovernance {
        if (!_active[templateId]) revert TemplateNotFound(templateId);
        _active[templateId] = false;
        emit TemplateRevoked(templateId);
    }

    /// @inheritdoc ITemplateRegistry
    function isActive(bytes32 templateId) external view returns (bool) {
        return _active[templateId];
    }

    /// @inheritdoc ITemplateRegistry
    function configHashOf(bytes32 templateId) external view returns (bytes32) {
        return _configHashes[templateId];
    }
}
