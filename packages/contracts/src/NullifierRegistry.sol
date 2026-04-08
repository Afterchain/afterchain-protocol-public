// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "./INullifierRegistry.sol";

/// @title NullifierRegistry — governance-controlled spent-nullifier registry
/// @notice Records spent nullifiers and prevents replay attacks across all
///         vaults deployed by the factory.
///
/// @dev DD Sprint A — Finding 2.1: removes the single-key `_owner` /
///      Ownable pattern. The registry is now governed by AfterchainGovernance
///      (3-of-5 on-chain multisig + 24h timelock). The only single-key
///      authority that remains is a ONE-SHOT bootstrap call that lets the
///      deploying account wire the initial operator (the factory) atomically
///      from the deploy script. After that single call, every operator
///      rotation must flow through AfterchainGovernance.
///
///      Authority model:
///        governance ─────────onlyGovernance──► setOperator (post-bootstrap)
///        deployer   ──one-shot bootstrap────► setOperator (first call only)
///        operator   ──authorizeVault(vault)─► authorizedVault
///        authorizedVault ──spend(nullifier)─► nullifier marked spent
///
///      DD Sprint A — Finding 3.1: spend() is gated by `_authorizedVaults`
///      so only an authorized TransferVault can mark a nullifier as spent.
///      An MEV bot or any external EOA cannot pre-spend a legitimate
///      beneficiary's nullifier — the on-chain check rejects the call before
///      any state mutation.
contract NullifierRegistry is INullifierRegistry {
    /// @notice AfterchainGovernance contract — sole authority for operator
    ///         rotation after the construction-time bootstrap is sealed.
    address public immutable governance;

    /// @dev The deploying account, captured in the constructor. May call
    ///      setOperator EXACTLY ONCE to seed the initial operator. After
    ///      the first call, the bootstrap is sealed and only `governance`
    ///      can rotate the operator. The bootstrap window is closed by
    ///      design: the deployer never has a second chance to mutate state.
    address private immutable _bootstrapDeployer;

    address private _operator;
    bool private _operatorBootstrapSealed;

    /// @dev nullifier → vault address that spent it (zero = unspent)
    mapping(bytes32 => address) private _spentBy;
    mapping(address => bool) private _authorizedVaults;

    // ── Errors ───────────────────────────────────────────────────────────────

    error ZeroAddress();
    error NotGovernance(address caller);
    error NotBootstrapDeployer(address caller);
    error NotOperator(address caller);

    // ── Events ───────────────────────────────────────────────────────────────

    event OperatorSet(address indexed operator);
    event VaultAuthorized(address indexed vault);

    constructor(address governance_) {
        if (governance_ == address(0)) revert ZeroAddress();
        governance = governance_;
        _bootstrapDeployer = msg.sender;
    }

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance(msg.sender);
        _;
    }

    // ── Administration ───────────────────────────────────────────────────────

    /// @notice Set the operator address (typically the TransferVaultFactory).
    /// @dev DD Sprint A — Finding 2.1. Two authority paths, never overlapping:
    ///        1. ONE-SHOT BOOTSTRAP: the deploying account may call this
    ///           exactly once, atomically wiring the factory immediately
    ///           after the deploy script creates it. After the first call,
    ///           the bootstrap is sealed forever.
    ///        2. GOVERNANCE: every subsequent rotation must originate from
    ///           AfterchainGovernance (submitAction → approve (3-of-5) →
    ///           24h on-chain timelock → executeAction).
    function setOperator(address operator_) external {
        if (_operatorBootstrapSealed) {
            if (msg.sender != governance) revert NotGovernance(msg.sender);
        } else {
            if (msg.sender != _bootstrapDeployer) revert NotBootstrapDeployer(msg.sender);
            _operatorBootstrapSealed = true;
        }
        _operator = operator_;
        emit OperatorSet(operator_);
    }

    /// @notice Authorize a vault to call spend(). Operator only.
    /// @dev Called atomically inside TransferVaultFactory.createVault().
    ///      Neither governance nor the deployer can authorize a vault
    ///      directly — only the live operator (the factory) can. This
    ///      forecloses the protocol-override vector identified in the prior
    ///      audit (Sprint 6 review).
    function authorizeVault(address vault) external {
        if (msg.sender != _operator) revert NotOperator(msg.sender);
        _authorizedVaults[vault] = true;
        emit VaultAuthorized(vault);
    }

    /// @notice Return whether a vault is authorized to spend nullifiers.
    function isAuthorizedVault(address vault) external view returns (bool) {
        return _authorizedVaults[vault];
    }

    function operator() external view returns (address) {
        return _operator;
    }

    /// @notice Whether the construction-time bootstrap window is closed.
    ///         Once true, only `governance` can call `setOperator`.
    function operatorBootstrapSealed() external view returns (bool) {
        return _operatorBootstrapSealed;
    }

    // ── INullifierRegistry ───────────────────────────────────────────────────

    /// @inheritdoc INullifierRegistry
    /// @dev DD Sprint A — Finding 3.1: explicit access-control gate. Only an
    ///      authorized TransferVault may call spend(). MEV bots, EOAs, and
    ///      arbitrary contracts are rejected with `UnauthorizedCaller`
    ///      BEFORE any state mutation, so a front-runner cannot pre-spend
    ///      a legitimate beneficiary's nullifier.
    function spend(bytes32 nullifier) external {
        if (!_authorizedVaults[msg.sender]) revert UnauthorizedCaller(msg.sender);
        if (_spentBy[nullifier] != address(0)) revert NullifierAlreadySpent(nullifier);
        _spentBy[nullifier] = msg.sender;
        emit NullifierSpent(nullifier, msg.sender);
    }

    /// @inheritdoc INullifierRegistry
    function isSpent(bytes32 nullifier) external view returns (bool) {
        return _spentBy[nullifier] != address(0);
    }
}
