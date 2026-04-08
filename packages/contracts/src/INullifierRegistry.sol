// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

/// @title INullifierRegistry
/// @notice Records spent nullifiers and prevents replay.
/// @dev Only authorized vaults may call spend(). isSpent() is public.
interface INullifierRegistry {
    // ── Events ───────────────────────────────────────────────────────────────

    event NullifierSpent(bytes32 indexed nullifier, address indexed vault);

    // ── Errors ───────────────────────────────────────────────────────────────

    error NullifierAlreadySpent(bytes32 nullifier);
    error UnauthorizedCaller(address caller);

    // ── Functions ────────────────────────────────────────────────────────────

    /// @notice Record a nullifier as spent. Reverts if already spent.
    /// @dev Must be called atomically inside TransferVault.execute() before external calls.
    function spend(bytes32 nullifier) external;

    /// @notice Authorize a vault to call spend(). Only callable by the operator (factory).
    function authorizeVault(address vault) external;

    /// @notice Return whether a nullifier has been spent.
    function isSpent(bytes32 nullifier) external view returns (bool);
}
