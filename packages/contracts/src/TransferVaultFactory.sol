// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "./ITransferVaultFactory.sol";
import "./ITemplateRegistry.sol";
import "./INullifierRegistry.sol";
import "./TransferVault.sol";

/// @title TransferVaultFactory
/// @notice Deploys TransferVault instances and wires them into the protocol.
///
/// @dev On createVault():
///        1. Validates templateId is active in TemplateRegistry.
///        2. Enforces minimum challenge window duration (MINIMUM_CHALLENGE_WINDOW).
///        3. Deploys a new TransferVault with the caller-supplied config.
///        4. Calls nullifierRegistry.authorizeVault(newVault) atomically.
///        5. Records vault → owner mapping.
///        6. Emits VaultCreated.
///
///      All infrastructure dependencies are immutable after deployment.
///      To upgrade infrastructure, deploy a new factory and set it as the
///      NullifierRegistry operator via owner.setOperator(newFactory).
///
///      Challenge window minimum (Sprint 8 — A3):
///        The factory enforces MINIMUM_CHALLENGE_WINDOW at vault creation time.
///        This is an architectural hardening measure — it keeps the vault contract
///        simple and non-custodial while ensuring no vault can be created with a
///        window so short that proof-of-life is practically impossible.
///        MVP minimum: 1 hour. Production target per architecture review: 7+ days.
contract TransferVaultFactory is ITransferVaultFactory {
    // ── Minimum challenge window ─────────────────────────────────────────────

    /// @notice Minimum allowed challenge window duration for new vault deployments.
    /// @dev MVP minimum: 1 hour. This is enforced at the factory boundary only.
    ///      The vault contract itself accepts any duration passed in the constructor —
    ///      the minimum is a factory-level policy, not an on-chain invariant inside the vault.
    ///
    ///      Production target: 7+ days to give vault owners meaningful time to submit
    ///      proof-of-life before a challenged attestation becomes irrevocable.
    ///      Increasing this constant requires deploying a new factory.
    uint256 public constant MINIMUM_CHALLENGE_WINDOW = 1 hours;

    // ── Immutable dependencies ───────────────────────────────────────────────

    address public immutable attestationVerifier;
    address public immutable nullifierRegistry;
    address public immutable groth16Verifier;
    address public immutable templateRegistry;
    /// @notice Multi-sig attestation verifier. address(0) = disabled for all vaults from this factory.
    address public immutable multiSigVerifier;
    /// @notice Sprint SEC-6 — signed fee-terms verifier. address(0) =
    ///         executeWithFees() is disabled for all vaults from this factory
    ///         (sandbox / legacy deploy). Factories deployed via
    ///         DeployProduction.s.sol supply a real FeeTermsVerifier instance.
    address public immutable feeTermsVerifier;
    /// @notice Sprint SEC-7 — template registry reference threaded into each
    ///         vault for template → fee mode binding. Uses the same address
    ///         as `templateRegistry` above but is stored under a distinct
    ///         public slot so off-chain tools can inspect the binding wiring.
    address public immutable templateRegistryForFeeMode;

    // ── State ────────────────────────────────────────────────────────────────

    /// @dev owner → vault deployed by that owner. One vault per owner is enforced.
    mapping(address => address) private _vaultOf;

    // ── Errors ───────────────────────────────────────────────────────────────

    error InactiveTemplate(bytes32 templateId);
    error OwnerAlreadyHasVault(address owner, address existingVault);
    error ZeroAddress();
    /// @dev challengeWindowDuration < MINIMUM_CHALLENGE_WINDOW.
    error ChallengeWindowTooShort(uint256 given, uint256 minimum);

    // ── Constructor ──────────────────────────────────────────────────────────

    constructor(
        address attestationVerifier_,
        address nullifierRegistry_,
        address groth16Verifier_,
        address templateRegistry_,
        address multiSigVerifier_,  // address(0) = multi-sig disabled for all vaults
        address feeTermsVerifier_   // address(0) = fee-terms enforcement disabled (sandbox)
    ) {
        if (
            attestationVerifier_ == address(0) ||
            nullifierRegistry_ == address(0) ||
            groth16Verifier_ == address(0) ||
            templateRegistry_ == address(0)
        ) revert ZeroAddress();
        require(multiSigVerifier_ != address(0), "TransferVaultFactory: zero multiSigVerifier");
        require(feeTermsVerifier_ != address(0), "TransferVaultFactory: zero feeTermsVerifier");

        attestationVerifier = attestationVerifier_;
        nullifierRegistry = nullifierRegistry_;
        groth16Verifier = groth16Verifier_;
        templateRegistry = templateRegistry_;
        multiSigVerifier = multiSigVerifier_;
        feeTermsVerifier = feeTermsVerifier_;
        // SEC-7: template registry is already wired for isActive() checks;
        // pass the same address through to vaults so they can query
        // feeModeOf() at executeWithFees() time.
        templateRegistryForFeeMode = templateRegistry_;
    }

    // ── ITransferVaultFactory ────────────────────────────────────────────────

    /// @inheritdoc ITransferVaultFactory
    function createVault(VaultConfig calldata config) external returns (address vault) {
        // Validate template is active
        if (!ITemplateRegistry(templateRegistry).isActive(config.templateId)) {
            revert InactiveTemplate(config.templateId);
        }

        // Enforce minimum challenge window (Sprint 8 hardening)
        if (config.challengeWindowDuration < MINIMUM_CHALLENGE_WINDOW) {
            revert ChallengeWindowTooShort(config.challengeWindowDuration, MINIMUM_CHALLENGE_WINDOW);
        }

        // Enforce one vault per owner before deployment
        if (_vaultOf[config.owner] != address(0)) {
            revert OwnerAlreadyHasVault(config.owner, _vaultOf[config.owner]);
        }

        // Deploy vault
        TransferVault.Deps memory deps = TransferVault.Deps({
            attestationVerifier: attestationVerifier,
            nullifierRegistry:   nullifierRegistry,
            groth16Verifier:     groth16Verifier,
            multiSigVerifier:    multiSigVerifier,
            feeTermsVerifier:    feeTermsVerifier,
            templateRegistry:    templateRegistryForFeeMode
        });
        vault = address(
            new TransferVault(
                config.owner,
                config.templateId,
                config.beneficiaryRoot,
                config.challengeWindowDuration,
                config.assets,
                deps
            )
        );

        // Authorize vault in nullifier registry (operator-only call via interface)
        INullifierRegistry(nullifierRegistry).authorizeVault(vault);

        _vaultOf[config.owner] = vault;

        emit VaultCreated(vault, config.owner, config.templateId);
    }

    /// @inheritdoc ITransferVaultFactory
    function vaultOf(address owner_) external view returns (address) {
        return _vaultOf[owner_];
    }
}
