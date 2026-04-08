// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

/// @title ITransferVaultFactory
/// @notice Deploys TransferVault instances and records vault-to-owner mapping.
/// @dev Sprint 2 provides the implementation. This interface is the public surface.
interface ITransferVaultFactory {
    // ── Structs ──────────────────────────────────────────────────────────────

    struct VaultConfig {
        address owner;
        bytes32 templateId;
        bytes32 beneficiaryRoot;
        /// @dev Duration in seconds for the challenge/proof-of-life window
        uint256 challengeWindowDuration;
        /// @dev ERC-20 token addresses whose balances are governed by this vault
        address[] assets;
    }

    // ── Events ───────────────────────────────────────────────────────────────

    event VaultCreated(
        address indexed vault,
        address indexed owner,
        bytes32 indexed templateId
    );

    // ── Functions ────────────────────────────────────────────────────────────

    /// @notice Deploy a new TransferVault with the given configuration.
    /// @return vault Address of the newly deployed vault
    function createVault(VaultConfig calldata config) external returns (address vault);

    /// @notice Return the vault address for a given owner (first vault only, for demo).
    function vaultOf(address owner) external view returns (address vault);
}
