// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

/// @title ITemplateRegistry
/// @notice Stores authorized template IDs and their configuration hashes.
/// @dev Templates bind vault configurations to protocol versions.
interface ITemplateRegistry {
    // ── Events ───────────────────────────────────────────────────────────────

    event TemplateRegistered(bytes32 indexed templateId, bytes32 configHash);
    event TemplateRevoked(bytes32 indexed templateId);

    // ── Functions ────────────────────────────────────────────────────────────

    /// @notice Register a new template.
    function registerTemplate(bytes32 templateId, bytes32 configHash) external;

    /// @notice Revoke an existing template.
    function revokeTemplate(bytes32 templateId) external;

    /// @notice Return whether a template is currently active.
    function isActive(bytes32 templateId) external view returns (bool);

    /// @notice Return the config hash for a template.
    function configHashOf(bytes32 templateId) external view returns (bytes32);
}
