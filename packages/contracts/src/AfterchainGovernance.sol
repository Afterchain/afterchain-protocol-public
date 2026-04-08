// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

/// @title AfterchainGovernance — unified multisig + timelock (Sprint SEC-8).
/// @notice Single on-chain authority for every critical signer roster change
///         in the Afterchain protocol. Replaces the legacy owner() pattern on
///         FeeTermsVerifier + AttestationVerifier. No individual key can
///         unilaterally mutate any signer set, fee policy, or verifier wiring.
///
/// @dev Action lifecycle:
///        submit   → ActionQueued, 1 approval credited to submitter
///        approve  → (n additional approvals) ActionApproved
///        execute  → (after timelock AND threshold met) ActionExecuted
///        cancel   → (any signer, any time before execute) ActionCancelled
///
///      Replay protection: actionId = keccak256(target || data || nonce)
///      where nonce is a monotonic counter. Executed actions are permanently
///      marked so a re-submit of identical bytes gets a fresh id.
///
///      Security invariants enforced here:
///        1. threshold >= 1 and threshold <= signerCount
///        2. signerCount >= threshold at ALL times (signer removal that would
///           break quorum reverts)
///        3. timelockDelay applied from QUEUE time, not from last approval
///        4. only signers can submit / approve / cancel
///        5. approvals tracked per (actionId, signer) — no double-voting
///        6. a signer removed mid-flight loses their vote on in-flight actions
contract AfterchainGovernance {
    // ── State ────────────────────────────────────────────────────────────────

    mapping(address => bool) public isSigner;
    address[] private _signerList;
    uint256 public threshold;
    uint256 public timelockDelay;

    /// @dev Monotonic counter to guarantee actionId uniqueness even for
    ///      byte-identical (target, data) submissions.
    uint256 public actionNonce;

    enum ActionState { None, Queued, Executed, Cancelled }

    struct Action {
        address target;
        bytes   data;
        uint256 queuedAt;
        uint256 approvals;
        ActionState state;
    }

    mapping(bytes32 => Action) private _actions;
    /// @dev (actionId, signer) → has-approved. Double-vote protection.
    mapping(bytes32 => mapping(address => bool)) private _approvedBy;

    // ── Events (Task 7) ──────────────────────────────────────────────────────

    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ThresholdChanged(uint256 oldThreshold, uint256 newThreshold);
    event TimelockDelayChanged(uint256 oldDelay, uint256 newDelay);
    event ActionQueued(bytes32 indexed actionId, address indexed target, address indexed submitter, uint256 queuedAt);
    event ActionApproved(bytes32 indexed actionId, address indexed signer, uint256 approvals);
    event ActionExecuted(bytes32 indexed actionId, address indexed target, bytes result);
    event ActionCancelled(bytes32 indexed actionId, address indexed canceller);

    // ── Errors ───────────────────────────────────────────────────────────────

    error NotSigner(address caller);
    error ZeroAddress();
    error AlreadySigner(address signer);
    error NotASigner(address signer);
    error InvalidThreshold(uint256 proposed, uint256 signerCount);
    error ActionNotFound(bytes32 actionId);
    error ActionWrongState(bytes32 actionId);
    error AlreadyApproved(bytes32 actionId, address signer);
    error ThresholdNotMet(uint256 approvals, uint256 threshold);
    error TimelockNotElapsed(uint256 unlockAt, uint256 currentTime);
    error RemovingSignerBreaksQuorum(uint256 remaining, uint256 threshold);
    error ExecutionFailed(bytes returnData);

    // ── Modifiers ────────────────────────────────────────────────────────────

    modifier onlySigner() {
        if (!isSigner[msg.sender]) revert NotSigner(msg.sender);
        _;
    }

    modifier onlySelf() {
        // Every mutation to the governance state itself must flow through
        // the multisig+timelock pipeline. An external caller can never call
        // these directly — they queue an action targeting address(this).
        if (msg.sender != address(this)) revert NotSigner(msg.sender);
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────────

    constructor(
        address[] memory initialSigners,
        uint256 initialThreshold,
        uint256 initialTimelockDelay
    ) {
        if (initialSigners.length == 0) revert InvalidThreshold(initialThreshold, 0);
        if (initialThreshold == 0 || initialThreshold > initialSigners.length) {
            revert InvalidThreshold(initialThreshold, initialSigners.length);
        }
        for (uint256 i = 0; i < initialSigners.length; i++) {
            address s = initialSigners[i];
            if (s == address(0)) revert ZeroAddress();
            if (isSigner[s]) revert AlreadySigner(s);
            isSigner[s] = true;
            _signerList.push(s);
            emit SignerAdded(s);
        }
        threshold = initialThreshold;
        timelockDelay = initialTimelockDelay;
        emit ThresholdChanged(0, initialThreshold);
        emit TimelockDelayChanged(0, initialTimelockDelay);
    }

    // ── Read helpers ────────────────────────────────────────────────────────

    function signerCount() external view returns (uint256) {
        return _signerList.length;
    }

    function signerAt(uint256 i) external view returns (address) {
        return _signerList[i];
    }

    function getAction(bytes32 actionId)
        external view
        returns (address target, bytes memory data, uint256 queuedAt, uint256 approvals, uint8 state)
    {
        Action storage a = _actions[actionId];
        return (a.target, a.data, a.queuedAt, a.approvals, uint8(a.state));
    }

    function hasApproved(bytes32 actionId, address signer) external view returns (bool) {
        return _approvedBy[actionId][signer];
    }

    // ── Action lifecycle ────────────────────────────────────────────────────

    /// @notice Submit a new action. The submitter's approval is credited
    ///         automatically so the common path is "submit + (threshold-1)
    ///         other approvals + execute".
    function submitAction(address target, bytes calldata data)
        external onlySigner returns (bytes32 actionId)
    {
        actionNonce += 1;
        actionId = keccak256(abi.encode(target, data, actionNonce));
        Action storage a = _actions[actionId];
        a.target    = target;
        a.data      = data;
        a.queuedAt  = block.timestamp;
        a.state     = ActionState.Queued;
        a.approvals = 1;
        _approvedBy[actionId][msg.sender] = true;
        emit ActionQueued(actionId, target, msg.sender, block.timestamp);
        emit ActionApproved(actionId, msg.sender, 1);
    }

    function approveAction(bytes32 actionId) external onlySigner {
        Action storage a = _actions[actionId];
        if (a.state != ActionState.Queued) revert ActionWrongState(actionId);
        if (_approvedBy[actionId][msg.sender]) revert AlreadyApproved(actionId, msg.sender);
        _approvedBy[actionId][msg.sender] = true;
        a.approvals += 1;
        emit ActionApproved(actionId, msg.sender, a.approvals);
    }

    /// @notice Execute a queued action. Requires:
    ///           - action is Queued
    ///           - block.timestamp >= queuedAt + timelockDelay
    ///           - effective approvals >= threshold (approvals from signers
    ///             who have since been removed do NOT count)
    function executeAction(bytes32 actionId) external onlySigner {
        Action storage a = _actions[actionId];
        if (a.state != ActionState.Queued) revert ActionWrongState(actionId);
        uint256 unlockAt = a.queuedAt + timelockDelay;
        if (block.timestamp < unlockAt) revert TimelockNotElapsed(unlockAt, block.timestamp);

        // Re-count approvals against the CURRENT signer set so that a
        // signer removed between queue and execute loses their vote.
        uint256 effective = 0;
        for (uint256 i = 0; i < _signerList.length; i++) {
            address s = _signerList[i];
            if (_approvedBy[actionId][s]) effective += 1;
        }
        if (effective < threshold) revert ThresholdNotMet(effective, threshold);

        a.state = ActionState.Executed;

        (bool ok, bytes memory ret) = a.target.call(a.data);
        if (!ok) revert ExecutionFailed(ret);

        emit ActionExecuted(actionId, a.target, ret);
    }

    function cancelAction(bytes32 actionId) external onlySigner {
        Action storage a = _actions[actionId];
        if (a.state != ActionState.Queued) revert ActionWrongState(actionId);
        a.state = ActionState.Cancelled;
        emit ActionCancelled(actionId, msg.sender);
    }

    // ── Self-call targets (only reachable through executeAction) ────────────

    function addSigner(address signer) external onlySelf {
        if (signer == address(0)) revert ZeroAddress();
        if (isSigner[signer]) revert AlreadySigner(signer);
        isSigner[signer] = true;
        _signerList.push(signer);
        emit SignerAdded(signer);
    }

    function removeSigner(address signer) external onlySelf {
        if (!isSigner[signer]) revert NotASigner(signer);
        uint256 remaining = _signerList.length - 1;
        if (remaining < threshold) revert RemovingSignerBreaksQuorum(remaining, threshold);
        isSigner[signer] = false;
        // Swap-pop from _signerList
        for (uint256 i = 0; i < _signerList.length; i++) {
            if (_signerList[i] == signer) {
                _signerList[i] = _signerList[_signerList.length - 1];
                _signerList.pop();
                break;
            }
        }
        emit SignerRemoved(signer);
    }

    function setThreshold(uint256 newThreshold) external onlySelf {
        if (newThreshold == 0 || newThreshold > _signerList.length) {
            revert InvalidThreshold(newThreshold, _signerList.length);
        }
        uint256 old = threshold;
        threshold = newThreshold;
        emit ThresholdChanged(old, newThreshold);
    }

    function setTimelockDelay(uint256 newDelay) external onlySelf {
        uint256 old = timelockDelay;
        timelockDelay = newDelay;
        emit TimelockDelayChanged(old, newDelay);
    }
}
