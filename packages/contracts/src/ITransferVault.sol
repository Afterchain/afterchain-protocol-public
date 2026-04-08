// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

/// @title ITransferVault
/// @notice Lifecycle state machine for a single inheritance intent.
/// @dev State transitions: ACTIVE → ATTESTED → CLAIMABLE → EXECUTED
///
///      Asset transfer model (Sprint 8 — pull-based):
///        execute() credits asset amounts to beneficiaryDest instead of pushing them.
///        The beneficiary calls withdrawETH() / withdrawToken(token) to receive funds.
///        This eliminates the DoS vector where a beneficiary contract rejecting ETH
///        would permanently lock the vault in CLAIMABLE state.
///
///        Non-custodial invariant: only beneficiaryDest (the cryptographically
///        verified destination) can withdraw their credited assets. No operator,
///        admin, or protocol function can redirect, suppress, or recover credits.
///
///      Post-ATTESTED: all owner-side mutations revert.
///      EXECUTED is terminal: any further execute() call reverts.
interface ITransferVault {
    // ── Enums ────────────────────────────────────────────────────────────────

    enum VaultState {
        ACTIVE,
        ATTESTED,
        CLAIMABLE,
        EXECUTED
    }

    // ── Events ───────────────────────────────────────────────────────────────

    event BeneficiaryRootSet(bytes32 indexed root);

    event AssetAdded(address indexed token);

    event AttestationAccepted(
        bytes32 indexed attestationId,
        uint256 challengeWindowEnd
    );

    event ProofOfLifeReceived(address indexed owner, uint256 at);

    /// @notice Emitted when markClaimable() successfully transitions the vault to CLAIMABLE.
    event ChallengeWindowExpired(uint256 at);

    /// @notice Emitted when execute() records ETH withdrawal credit for beneficiary.
    event ETHCredited(address indexed beneficiary, uint256 amount);

    /// @notice Emitted when execute() records token withdrawal credit for beneficiary.
    event TokenCredited(address indexed token, address indexed beneficiary, uint256 amount);

    /// @notice Emitted when beneficiary calls withdrawETH() and receives ETH.
    event ETHWithdrawn(address indexed beneficiary, uint256 amount);

    /// @notice Emitted when beneficiary calls withdrawToken() and receives tokens.
    event TokenWithdrawn(address indexed token, address indexed beneficiary, uint256 amount);

    event ClaimExecuted(
        address indexed beneficiaryDest,
        bytes32 indexed nullifier,
        uint256 at
    );

    /// @notice Emitted when attestMultiSig() successfully reaches the required threshold.
    /// @dev Sprint 15 multi-signer attestation path. payloadHash is the signed digest.
    event MultiSigAttestationAccepted(
        bytes32 indexed payloadHash,
        uint256 signersCount,
        uint256 threshold,
        uint256 challengeWindowEnd
    );

    // ── Owner-only (ACTIVE state) ─────────────────────────────────────────────

    /// @notice Set or replace the Merkle root of beneficiary commitments.
    /// @dev Reverts with ConfigurationLocked once vault is ATTESTED or beyond.
    function setBeneficiaryRoot(bytes32 root) external;

    /// @notice Add a governed ERC-20 asset address to the vault's asset list.
    /// @dev Owner-only. Reverts once vault is ATTESTED (ConfigurationLocked).
    ///      Prevents duplicates. Reverts with AssetAlreadyRegistered if token is already governed.
    function addAsset(address token) external;

    /// @notice Submit proof-of-life to reset vault to ACTIVE during challenge window.
    /// @dev Reverts if the challenge window has already closed.
    function challengeProofOfLife() external;

    /// @notice Explicitly transition the vault from ATTESTED to CLAIMABLE.
    /// @dev Callable by anyone once the challenge window has expired.
    ///      Reverts with ChallengeWindowStillOpen if block.timestamp <= challengeWindowEnd.
    ///      Reverts with WrongState if vault is not in ATTESTED state.
    ///      Emits ChallengeWindowExpired. This is the canonical audit-trail point for
    ///      the CLAIMABLE transition — getState() returns only the stored _state value.
    function markClaimable() external;

    // ── Protocol flow ────────────────────────────────────────────────────────

    /// @notice Accept a signed oracle attestation. Transitions ACTIVE → ATTESTED.
    /// @param signedAttestation ABI-encoded + ECDSA-signed attestation payload.
    function attest(bytes calldata signedAttestation) external;

    /// @notice Execute the vault: verify proof, spend nullifier, credit assets to beneficiary.
    /// @dev Requires CLAIMABLE state. Transitions to EXECUTED (terminal).
    ///      Assets are credited for pull-based withdrawal — they remain in the vault
    ///      until beneficiaryDest calls withdrawETH() / withdrawToken(token).
    ///      Replay prevention: nullifier is spent atomically. Single-use state machine.
    /// @param proof         Groth16 proof (a, b, c components packed)
    /// @param publicInputs  [merkleRoot, nullifierHash, vaultAddress, beneficiaryDest]
    /// @param nullifier     Raw nullifier (spent atomically in NullifierRegistry)
    /// @param beneficiaryDest Destination address credited with vault assets
    function execute(
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes32 nullifier,
        address beneficiaryDest
    ) external;

    /// @notice Withdraw ETH credited to msg.sender by a prior execute() call.
    /// @dev Pull-based: beneficiary must call this to receive ETH after execute().
    ///      Only msg.sender can withdraw their own credits. No operator path.
    ///      Reverts with NoPendingWithdrawal if no ETH is credited.
    function withdrawETH() external;

    /// @notice Withdraw an ERC-20 token credited to msg.sender by a prior execute() call.
    /// @param token The ERC-20 token contract address.
    /// @dev Pull-based: beneficiary must call this to receive tokens after execute().
    ///      Only msg.sender can withdraw their own credits. No operator path.
    ///      Reverts with NoPendingWithdrawal if no token balance is credited.
    function withdrawToken(address token) external;

    // ── Views ────────────────────────────────────────────────────────────────

    function getState() external view returns (VaultState);

    function owner() external view returns (address);

    function beneficiaryRoot() external view returns (bytes32);

    function templateId() external view returns (bytes32);

    /// @notice Unix timestamp when the challenge window closes (0 if not ATTESTED)
    function challengeWindowEnd() external view returns (uint256);

    /// @notice ETH credited to beneficiary after execute() (available to withdraw).
    function pendingEthWithdrawals(address beneficiary) external view returns (uint256);

    /// @notice Token amount credited to beneficiary after execute() (available to withdraw).
    function pendingTokenWithdrawals(address token, address beneficiary) external view returns (uint256);
}
