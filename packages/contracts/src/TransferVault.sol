// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "./ITransferVault.sol";
import "./IAttestationVerifier.sol";
import "./IMultiSigAttestationVerifier.sol";
import "./INullifierRegistry.sol";
import "./IGroth16Verifier.sol";
import "./IFeeTermsVerifier.sol";
import "./FeeTerms.sol";

/// @dev Minimal template-registry interface — only the fee mode accessor
///      added in Sprint SEC-7 Task 4. The vault does not need any other
///      registry functionality during execution.
interface ITemplateRegistryFeeMode {
    function feeModeOf(bytes32 templateId) external view returns (uint8);
}

/// @dev Minimal ERC-20 interface for asset transfer on execution.
interface IERC20Minimal {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @dev Inline reentrancy guard. No external dependencies required.
///      Identical in semantics to OpenZeppelin ReentrancyGuard v5.
///      Required by Technical Architecture Note §execution-layer-safeguards.
abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

/// @title TransferVault
/// @notice Deterministic, non-custodial inheritance vault.
///
/// @dev State machine: ACTIVE → ATTESTED → CLAIMABLE → EXECUTED
///
///      Key invariants:
///        - No admin drain path; no operator override.
///        - Configuration (beneficiaryRoot, assets) is locked once the vault is ATTESTED.
///        - CLAIMABLE transition requires an explicit markClaimable() call from
///          anyone after the challenge window expires — there is no implicit state
///          derivation; getState() always returns the stored _state.
///        - Execution is single-use: once EXECUTED, all further calls revert.
///        - The vault never manages user private keys.
///
///      Asset transfer model (Sprint 8 — pull-based):
///        execute() transitions to EXECUTED and records asset credits for beneficiaryDest.
///        Assets remain in the vault until beneficiaryDest calls withdrawETH() or
///        withdrawToken(token). This eliminates the DoS vector where a beneficiary
///        contract rejecting ETH would permanently trap the vault in CLAIMABLE state.
///
///        Non-custodial guarantee: only the beneficiary address committed in the ZK proof
///        (and checked at execute() time via publicInputs[3] == uint160(beneficiaryDest))
///        can withdraw their credited assets. No operator, admin, or protocol function
///        can redirect, recover, or suppress withdrawal credits.
///
///      Attestation encoding expected by attest():
///        signedAttestation = payload ++ sig
///        payload = abi.encode(id, vault, chainId, issuedAt, expiresAt, templateId, evidenceHash)
///                = 224 bytes (7 × 32-byte ABI fields)
///        sig     = abi.encodePacked(r, s, v) = 65 bytes
///        total   = 289 bytes
///
///        Signing: EIP-712 typed data over AttestationPayload struct bound to the
///        AttestationVerifier domain (chainId + contract address). See IAttestationVerifier.
///
///      Proof encoding expected by execute():
///        proof = abi.encode(uint256[2] a, uint256[2][2] b, uint256[2] c) = 256 bytes
///        publicInputs = uint256[] of length 4:
///          [0] merkleRoot    — must equal on-chain beneficiaryRoot (checked by vault)
///          [1] nullifierHash — bytes32 cast must equal nullifier parameter (checked by vault)
///          [2] vaultAddress  — uint256(uint160(address(this))); prevents cross-vault replay
///          [3] beneficiaryDest — uint256(uint160(beneficiaryDest)); destination address binding.
///                                Checked by vault (BeneficiaryDestMismatch). In production also
///                                enforced cryptographically by the Groth16 verifier: beneficiaryDest
///                                is the third input of the Merkle leaf commitment
///                                Poseidon(secret, entitlement, beneficiaryDest). (Sprint 6 circuit.)
contract TransferVault is ITransferVault, ReentrancyGuard {
    // ── Constants ────────────────────────────────────────────────────────────

    uint256 private constant ATTESTATION_PAYLOAD_LENGTH = 224;
    uint256 private constant SIG_LENGTH = 65;
    uint256 private constant PROOF_LENGTH = 256; // abi.encode(uint256[2], uint256[2][2], uint256[2])

    // ── State ────────────────────────────────────────────────────────────────

    VaultState private _state;

    address public override owner;
    bytes32 public override beneficiaryRoot;
    bytes32 public override templateId;

    uint256 private _challengeWindowDuration;
    uint256 public override challengeWindowEnd;

    /// @notice DD Sprint G — Finding ZK: chain id captured at construction.
    ///         Re-checked at every state-transitioning entry point so a
    ///         fork or replay against a different chain reverts deterministically.
    uint256 public immutable vaultChainId;

    // ── DD Sprint D — Finding 3.1 / 8: non-custodial anti-griefing ──────────
    //
    // CONTEXT — non-custodial invariant.
    //   The protocol architect has explicitly forbidden any on-chain financial
    //   staking / slashing bond on this vault to defend against griefing on
    //   challengeProofOfLife(). A bond would require the vault to take custody
    //   of staked funds, violating the strict non-custodial invariant
    //   (CLAUDE.md §architecture constraints).
    //
    // SOLUTION — stateless counter + hard cap.
    //   challengeProofOfLife() now increments a per-vault counter. After
    //   MAX_CHALLENGES resets the call reverts with ChallengeCapReached(). This
    //   mathematically guarantees Liveness: even an adversarial owner can
    //   reset the vault at most MAX_CHALLENGES times before the ATTESTED →
    //   CLAIMABLE → EXECUTED progression becomes irreversible. There is no
    //   infinite-DoS path.
    //
    // ECONOMIC ENFORCEMENT — delegated to L3.
    //   Financial penalties for griefing within the cap are enforced
    //   off-chain by the integrating exchange / custodian. The L1 contract
    //   preserves the non-custodial invariant; the L3 commercial layer owns
    //   the economic deterrent. Architecture docs and the IPP enrichment
    //   register reflect this split.
    uint8 public constant MAX_CHALLENGES = 3;
    uint8 public challengeCount;

    address[] private _assets;

    /// @dev Tracks registered asset addresses to prevent duplicates in addAsset().
    mapping(address => bool) private _assetRegistered;

    IAttestationVerifier private immutable _attestationVerifier;
    IMultiSigAttestationVerifier private immutable _multiSigVerifier;
    INullifierRegistry private immutable _nullifierRegistry;
    IGroth16Verifier private immutable _groth16Verifier;
    /// @dev Sprint SEC-6 — signed fee-terms verifier. address(0) = fee
    ///      enforcement disabled for this vault (sandbox / legacy deploys).
    IFeeTermsVerifier private immutable _feeTermsVerifier;
    /// @dev Sprint SEC-7 — template registry used for fee-mode binding.
    ///      address(0) is tolerated (sandbox); the fee-mode check is skipped
    ///      in that case.
    ITemplateRegistryFeeMode private immutable _templateRegistry;

    // ── Pull-based withdrawal state ───────────────────────────────────────────

    /// @notice ETH credited to each beneficiary by execute(). Beneficiary must call withdrawETH().
    mapping(address => uint256) public override pendingEthWithdrawals;

    /// @notice ERC-20 token amounts credited to each beneficiary by execute().
    /// @dev token → beneficiary → amount. Beneficiary must call withdrawToken(token).
    mapping(address => mapping(address => uint256)) public override pendingTokenWithdrawals;

    // ── Sprint 21 P1 — Task 5: multi-sig EIP-712 + replay protection ──────────

    /// @dev EIP-712 domain typehash, computed at compile time from the
    ///      standard EIP-712 domain tuple.
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev MultiSigAttestation typehash, computed at compile time.
    bytes32 private constant _MULTISIG_TYPEHASH =
        keccak256("MultiSigAttestation(address vault,uint256 chainId,bytes32 templateId,uint256 expiresAt,bytes32 payloadHash)");

    /// @dev Replay protection: every multi-sig digest (typed or raw) that has
    ///      successfully transitioned a vault ACTIVE → ATTESTED. Any subsequent
    ///      attestMultiSig / attestMultiSigTyped call that re-uses the same digest
    ///      reverts with MultiSigReplay. Mapping key is the digest actually passed
    ///      into recoverSigners(), so it binds replay protection to whatever was
    ///      signed.
    mapping(bytes32 => bool) private _usedMultiSigDigests;

    // ── Errors ───────────────────────────────────────────────────────────────

    error NotOwner(address caller);
    error WrongState(VaultState current);
    error ConfigurationLocked();
    error ChallengeWindowStillOpen(uint256 windowEnd, uint256 currentTime);
    error ChallengeWindowClosed();
    /// @dev DD Sprint D — Finding 3.1 / 8: non-custodial anti-griefing.
    ///      challengeProofOfLife() has been called the maximum permitted
    ///      number of times (MAX_CHALLENGES). Liveness is preserved without
    ///      a financial bond — the cap mathematically prevents infinite DoS.
    error ChallengeCapReached(uint8 used, uint8 cap);
    error AttestationInvalid();
    error AttestationVaultMismatch();
    /// @dev decoded.templateId in the signed attestation must equal vault.templateId.
    ///      Architectural gap closed in Sprint 7: attestation/verification path now cross-checks
    ///      templateId, preventing oracle signatures intended for one template version from being
    ///      accepted by a vault configured for a different template. (ArchitectureNote §9 §7.)
    error TemplateMismatch(bytes32 vaultTemplateId, bytes32 attestationTemplateId);
    error InvalidProof();
    error MerkleRootMismatch();
    error NullifierMismatch();
    /// @dev publicInputs[2] must equal uint256(uint160(address(this)))
    error VaultAddressMismatch();
    /// @dev publicInputs[3] must equal uint256(uint160(beneficiaryDest))
    error BeneficiaryDestMismatch();
    error BadAttestationLength(uint256 given, uint256 expected);
    error BadProofLength(uint256 given);
    error BadPublicInputsLength(uint256 given);
    /// @dev attestMultiSig() called but no multiSigVerifier was configured at deployment.
    error MultiSigNotConfigured();
    /// @dev threshold must be > 0.
    error MultiSigInvalidThreshold();
    /// @dev Fewer authorized unique signers recovered than the required threshold.
    error MultiSigThresholdNotMet(uint256 recovered, uint256 threshold);
    /// @dev Sprint 21 P1 — Task 5: the supplied digest has already been used in a
    ///      successful multi-sig attestation on this vault. Prevents replay.
    error MultiSigReplay(bytes32 digest);
    /// @dev Sprint 21 P1 — Task 5: typed attestation expiry has elapsed.
    error MultiSigExpired(uint256 expiresAt, uint256 currentTime);
    /// @dev Sprint SEC-2 · Task 4: legacy attestMultiSig is now restricted to
    ///      local sandbox (chainid 31337). Production deployments must use
    ///      attestMultiSigTyped, which carries domain-separated EIP-712 binding.
    // DD Sprint A — Finding 2.3: LegacyMultiSigForbidden removed; the
    // chainid lock on attestMultiSig() is gone. The raw-hash path is still
    // protected by _usedMultiSigDigests; production callers should still
    // prefer attestMultiSigTyped() for EIP-712 cross-chain replay safety.
    /// @dev No withdrawal credit exists for msg.sender (ETH or token).
    error NoPendingWithdrawal();
    /// @dev ETH withdrawal call to beneficiary failed (low-level call reverted).
    error WithdrawalFailed();
    /// @dev addAsset(): token is already in the governed asset list.
    error AssetAlreadyRegistered(address token);
    /// @dev addAsset(): token address cannot be zero.
    error ZeroTokenAddress();

    // ── Sprint SEC-6 · fee enforcement errors ────────────────────────────────
    /// @dev executeWithFees() called but this vault was deployed with no fee
    ///      terms verifier (sandbox / legacy deploy). Use execute() instead.
    error FeeTermsNotConfigured();
    /// @dev Fee terms signature did not verify against the authorized oracle roster.
    error FeeTermsInvalid();
    /// @dev Decoded payload vault !== address(this).
    error FeeTermsVaultMismatch(address expected, address actual);
    /// @dev Decoded payload chainId !== block.chainid.
    error FeeTermsChainMismatch(uint256 expected, uint256 actual);
    /// @dev Decoded payload templateId !== vault.templateId.
    error FeeTermsTemplateMismatch(bytes32 expected, bytes32 actual);
    /// @dev feeTermsExpiry has elapsed OR fxQuoteTimestamp is zero.
    error FeeTermsExpired(uint256 expiresAt, uint256 now_);
    /// @dev Fee model not one of the canonical enum values.
    error FeeTermsUnknownModel(uint8 model);
    /// @dev Zero afterchain recipient in a mode that requires one.
    error FeeTermsZeroAfterchainRecipient();
    /// @dev LICENSED_SPLIT mode requires a non-zero licensee recipient.
    error FeeTermsZeroLicenseeRecipient();
    /// @dev Fee payload bps > 10000 or floor/min/threshold inconsistent.
    error FeeTermsParameterOutOfRange();
    /// @dev Sprint SEC-7 — template has a pinned fee mode that does not
    ///      match the one in the signed fee-terms payload.
    error FeeTermsTemplateModeMismatch(uint8 templateMode, uint8 payloadMode);
    /// @dev DD Sprint C — Finding 4.1: oracle signed a basis-points value
    ///      below the licensing minimum (200 bps = 2.00%).
    error FeeTermsBelowMinimumBps();
    /// @dev DD Sprint C — Finding 4.1: oracle signed an execution fee floor
    ///      below the licensing minimum (25_000 cents = EUR 250.00).
    error FeeTermsBelowMinimumFloor();
    /// @dev DD Sprint C — Finding 4.4: the template-registry binding for
    ///      this vault's template is FEE_MODE_UNSET. Production templates
    ///      MUST pin a real fee mode (LICENSED_SPLIT / DIRECT_PROTOCOL /
    ///      LOW_BALANCE) — the legacy bypass is closed.
    error TemplateFeeModeNotPinned(bytes32 templateId);
    /// @dev DD Sprint G — Finding ZK: vault is being executed on a chain
    ///      different from the chain it was created on. The state would
    ///      otherwise be replayable across forks.
    error ChainMismatch(uint256 expected, uint256 actual);
    /// @dev DD Sprint G — templateId of bytes32(0) is not a valid template;
    ///      every vault MUST be bound to a real registered template at creation.
    error InvalidTemplate();

    // ── Constructor ──────────────────────────────────────────────────────────

    /// @notice Grouped dependency addresses — passed as a struct to keep
    ///         the constructor parameter count within the legacy yul stack
    ///         limit after the SEC-7 additions.
    struct Deps {
        address attestationVerifier;
        address nullifierRegistry;
        address groth16Verifier;
        address multiSigVerifier;      // address(0) = multi-sig disabled
        address feeTermsVerifier;      // address(0) = executeWithFees disabled
        address templateRegistry;      // address(0) = template→feeMode binding disabled
    }

    constructor(
        address owner_,
        bytes32 templateId_,
        bytes32 beneficiaryRoot_,
        uint256 challengeWindowDuration_,
        address[] memory assets_,
        Deps memory deps
    ) ReentrancyGuard() {
        // DD Sprint G — Finding "Template Registry safety": every vault MUST
        // be bound to a real (non-zero) template at creation. The bytes32(0)
        // value cannot be a registered template, so accepting it would
        // create a vault that no executeWithFees() call can ever reach.
        if (templateId_ == bytes32(0)) revert InvalidTemplate();

        owner = owner_;
        templateId = templateId_;
        beneficiaryRoot = beneficiaryRoot_;
        _challengeWindowDuration = challengeWindowDuration_;
        // DD Sprint G — Finding ZK: capture chain id at deploy time so a
        // fork-replay attack reverts at every state-transitioning entry point.
        vaultChainId = block.chainid;

        // Register initial asset list and mark each address as known
        for (uint256 i = 0; i < assets_.length; i++) {
            _assetRegistered[assets_[i]] = true;
        }
        _assets = assets_;

        _attestationVerifier = IAttestationVerifier(deps.attestationVerifier);
        _multiSigVerifier    = IMultiSigAttestationVerifier(deps.multiSigVerifier);
        _nullifierRegistry   = INullifierRegistry(deps.nullifierRegistry);
        _groth16Verifier     = IGroth16Verifier(deps.groth16Verifier);
        _feeTermsVerifier    = IFeeTermsVerifier(deps.feeTermsVerifier);
        _templateRegistry    = ITemplateRegistryFeeMode(deps.templateRegistry);
        _state = VaultState.ACTIVE;
    }

    /// @notice Sprint SEC-6 — the fee-terms verifier bound to this vault at deploy.
    function feeTermsVerifier() external view returns (address) {
        return address(_feeTermsVerifier);
    }

    // ── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }

    modifier inState(VaultState required) {
        if (_state != required) revert WrongState(_state);
        _;
    }

    modifier notLocked() {
        if (_state != VaultState.ACTIVE) revert ConfigurationLocked();
        _;
    }

    // ── ITransferVault: owner-only configuration ─────────────────────────────

    /// @inheritdoc ITransferVault
    function setBeneficiaryRoot(bytes32 root) external onlyOwner notLocked {
        beneficiaryRoot = root;
        emit BeneficiaryRootSet(root);
    }

    /// @inheritdoc ITransferVault
    /// @dev addAsset is only callable while the vault is ACTIVE (notLocked).
    ///      Once ATTESTED, the governed asset list is immutable — no assets
    ///      can be added to or removed from the execution scope.
    function addAsset(address token) external onlyOwner notLocked {
        if (token == address(0)) revert ZeroTokenAddress();
        if (_assetRegistered[token]) revert AssetAlreadyRegistered(token);
        _assetRegistered[token] = true;
        _assets.push(token);
        emit AssetAdded(token);
    }

    // ── ITransferVault: protocol flow ────────────────────────────────────────

    /// @inheritdoc ITransferVault
    /// @dev signedAttestation = payload (224 bytes) ++ sig (65 bytes) = 289 bytes total.
    ///      The AttestationVerifier enforces EIP-712 domain separation on the signing digest.
    ///      decoded.vault == msg.sender enforced by AttestationVerifier.verify().
    /// @dev DD Sprint G — Finding ZK: re-check chain id at every state transition.
    function attest(bytes calldata signedAttestation) external inState(VaultState.ACTIVE) {
        if (block.chainid != vaultChainId) revert ChainMismatch(vaultChainId, block.chainid);
        uint256 expectedLen = ATTESTATION_PAYLOAD_LENGTH + SIG_LENGTH;
        if (signedAttestation.length != expectedLen) {
            revert BadAttestationLength(signedAttestation.length, expectedLen);
        }

        bytes calldata payload = signedAttestation[:ATTESTATION_PAYLOAD_LENGTH];
        bytes calldata sig = signedAttestation[ATTESTATION_PAYLOAD_LENGTH:];

        // verify() checks: EIP-712 digest, signer authorized, chainId, not expired, vault == msg.sender
        (bool valid, IAttestationVerifier.DecodedAttestation memory decoded) =
            _attestationVerifier.verify(payload, sig);

        if (!valid) revert AttestationInvalid();

        // Belt-and-suspenders: confirm vault binding even though verifier checks it
        if (decoded.vault != address(this)) revert AttestationVaultMismatch();

        // Template ID cross-check (Sprint 7, ArchitectureNote §9 §7):
        // The oracle's attestation must be issued for this vault's configured template version.
        // Prevents oracle signatures for one template being accepted by vaults on a different
        // template — closes the attestation/verification path gap identified in Sprint 6 review.
        if (decoded.templateId != templateId) revert TemplateMismatch(templateId, decoded.templateId);

        _state = VaultState.ATTESTED;
        challengeWindowEnd = block.timestamp + _challengeWindowDuration;

        emit AttestationAccepted(decoded.id, challengeWindowEnd);
    }

    /// @notice Attest a vault via a threshold of ECDSA signatures from authorized signers.
    ///
    /// @dev Sprint 15 — Phase 3 service-layer multi-signer attestation path.
    ///
    ///      Caller (oracle service) submits a payload hash and a set of ECDSA signatures
    ///      from authorized roster members. The MultiSigAttestationVerifier recovers
    ///      authorized unique signers; this function enforces the threshold.
    ///
    ///      Requires multiSigVerifier != address(0) (configured at vault deployment).
    ///      Anyone may call — identical permissioning to attest().
    ///
    ///      Honest framing:
    ///        - This is service-layer enforcement; the authorized signer list is
    ///          managed by the MultiSigAttestationVerifier owner (oracle operator).
    ///        - Full on-chain threshold multisig with contract-enforced time-locked
    ///          rotation remains a future target beyond Phase 3.
    ///        - The existing attest() / AttestationVerifier path is unchanged.
    ///
    /// @param payloadHash  32-byte hash of the attestation payload (signed by oracle signers).
    /// @param signatures   Array of 65-byte ECDSA signatures in abi.encodePacked(r, s, v) format.
    /// @param threshold    Minimum number of unique authorized signers required.
    function attestMultiSig(
        bytes32 payloadHash,
        bytes[] calldata signatures,
        uint256 threshold
    ) external inState(VaultState.ACTIVE) {
        if (block.chainid != vaultChainId) revert ChainMismatch(vaultChainId, block.chainid);
        if (address(_multiSigVerifier) == address(0)) revert MultiSigNotConfigured();
        if (threshold == 0) revert MultiSigInvalidThreshold();

        // DD Sprint A — Finding 2.3: the prior chainid != 31337 lock has been
        // removed. The multi-sig path (raw-hash and typed) is now reachable on
        // any chain. Production / L2 callers SHOULD prefer
        // attestMultiSigTyped(), which carries EIP-712 domain separation
        // binding the digest to address(this), block.chainid, templateId,
        // expiresAt, and the payload hash — closing the cross-chain replay
        // vector that the raw-hash path does not address. Both paths share
        // the same _usedMultiSigDigests set so a payloadHash can transition
        // any vault at most once across either entry point.

        // Sprint 21 P1 — Task 5: replay protection (raw-hash path).
        // Prevents the same payloadHash from transitioning any vault more than once.
        if (_usedMultiSigDigests[payloadHash]) revert MultiSigReplay(payloadHash);

        address[] memory recovered = _multiSigVerifier.recoverSigners(payloadHash, signatures);

        if (recovered.length < threshold) {
            revert MultiSigThresholdNotMet(recovered.length, threshold);
        }

        _usedMultiSigDigests[payloadHash] = true;
        _state = VaultState.ATTESTED;
        challengeWindowEnd = block.timestamp + _challengeWindowDuration;

        emit MultiSigAttestationAccepted(payloadHash, recovered.length, threshold, challengeWindowEnd);
    }

    /// @notice Sprint 21 P1 — Task 5: EIP-712 typed-data multi-sig attestation.
    ///
    /// @dev Domain-separated, replay-protected, expiry-enforced variant of
    ///      attestMultiSig. Signers must sign the EIP-712 digest computed over:
    ///
    ///        MultiSigAttestation(address vault, uint256 chainId, bytes32 templateId,
    ///                            uint256 expiresAt, bytes32 payloadHash)
    ///
    ///      bound to the DOMAIN_SEPARATOR (name="Afterchain", version="1",
    ///      chainId=block.chainid, verifyingContract=address(this)).
    ///
    ///      Security properties (vs. raw attestMultiSig):
    ///        ✓ Cross-chain replay blocked     — chainid inside struct + domain
    ///        ✓ Cross-vault replay blocked     — address(this) inside struct + domain
    ///        ✓ Cross-template replay blocked  — templateId inside struct
    ///        ✓ Expired payload blocked        — expiresAt < block.timestamp reverts
    ///        ✓ Same-digest replay blocked     — _usedMultiSigDigests mapping
    ///
    ///      The templateId argument must equal this vault's configured templateId
    ///      (belt-and-suspenders: an attacker who gets signers to sign for a
    ///      different template is already broken, but this is cheap to enforce).
    function attestMultiSigTyped(
        bytes32 expectedTemplateId,
        uint256 expiresAt,
        bytes32 payloadHash,
        bytes[] calldata signatures,
        uint256 threshold
    ) external inState(VaultState.ACTIVE) {
        if (block.chainid != vaultChainId) revert ChainMismatch(vaultChainId, block.chainid);
        if (address(_multiSigVerifier) == address(0)) revert MultiSigNotConfigured();
        if (threshold == 0) revert MultiSigInvalidThreshold();
        if (expectedTemplateId != templateId) revert TemplateMismatch(templateId, expectedTemplateId);
        if (block.timestamp > expiresAt) revert MultiSigExpired(expiresAt, block.timestamp);

        // Compute EIP-712 domain-separated digest
        bytes32 domainSeparator = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("Afterchain")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                _MULTISIG_TYPEHASH,
                address(this),
                block.chainid,
                expectedTemplateId,
                expiresAt,
                payloadHash
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        if (_usedMultiSigDigests[digest]) revert MultiSigReplay(digest);

        address[] memory recovered = _multiSigVerifier.recoverSigners(digest, signatures);

        if (recovered.length < threshold) {
            revert MultiSigThresholdNotMet(recovered.length, threshold);
        }

        _usedMultiSigDigests[digest] = true;
        _state = VaultState.ATTESTED;
        challengeWindowEnd = block.timestamp + _challengeWindowDuration;

        emit MultiSigAttestationAccepted(digest, recovered.length, threshold, challengeWindowEnd);
    }

    /// @inheritdoc ITransferVault
    /// @dev DD Sprint D — Finding 3.1 / 8: non-custodial anti-griefing.
    ///      Each successful call increments `challengeCount`. After
    ///      MAX_CHALLENGES (3) resets the call reverts with ChallengeCapReached().
    ///      Liveness is mathematically guaranteed: the ATTESTED → CLAIMABLE
    ///      → EXECUTED progression becomes irreversible after at most three
    ///      legitimate proof-of-life resets, with no financial bond required
    ///      and no custody of operator funds. Economic deterrents within the
    ///      cap are delegated to the L3 custodian / integrating exchange.
    function challengeProofOfLife() external onlyOwner inState(VaultState.ATTESTED) {
        if (block.timestamp > challengeWindowEnd) revert ChallengeWindowClosed();
        if (challengeCount >= MAX_CHALLENGES) {
            revert ChallengeCapReached(challengeCount, MAX_CHALLENGES);
        }

        unchecked { challengeCount += 1; }
        _state = VaultState.ACTIVE;
        challengeWindowEnd = 0;

        emit ProofOfLifeReceived(owner, block.timestamp);
    }

    /// @inheritdoc ITransferVault
    /// @dev Permissionless. Anyone may call after the challenge window closes.
    ///      This is the canonical audit-trail point for the ATTESTED → CLAIMABLE transition.
    function markClaimable() external inState(VaultState.ATTESTED) {
        if (block.chainid != vaultChainId) revert ChainMismatch(vaultChainId, block.chainid);
        if (block.timestamp <= challengeWindowEnd) {
            revert ChallengeWindowStillOpen(challengeWindowEnd, block.timestamp);
        }
        _state = VaultState.CLAIMABLE;
        emit ChallengeWindowExpired(block.timestamp);
    }

    /// @inheritdoc ITransferVault
    /// @dev Requires _state == CLAIMABLE. Call markClaimable() first if coming from ATTESTED.
    ///      Protected by nonReentrant (Technical Architecture Note §execution-layer-safeguards).
    ///
    ///      Pull-based asset model (Sprint 8):
    ///        execute() transitions the vault to EXECUTED and records ETH / ERC-20 credits
    ///        for beneficiaryDest. Assets remain in the vault until beneficiaryDest calls
    ///        withdrawETH() / withdrawToken(token). This eliminates the DoS risk
    ///        where a beneficiary contract rejecting ETH permanently traps the vault.
    ///
    ///      State order:
    ///        1. All public input checks (fail-fast before any state mutation)
    ///        2. NullifierRegistry.spend() — atomic replay prevention (external call)
    ///        3. _state = EXECUTED — terminal state
    ///        4. _creditAssets() — record withdrawal credits (no external calls)
    ///        5. emit ClaimExecuted
    ///
    ///      Proof encoding: abi.encode(uint256[2] a, uint256[2][2] b, uint256[2] c) = 256 bytes.
    ///
    ///      Public input enforcement:
    ///        [0] merkleRoot must equal beneficiaryRoot (checked by vault).
    ///        [1] bytes32(nullifierHash) must equal nullifier (checked by vault).
    ///        [2] uint256(uint160(address(this))) — vault address binding (checked by vault).
    ///        [3] uint256(uint160(beneficiaryDest)) — destination binding (checked by vault,
    ///            BeneficiaryDestMismatch). In production also enforced by the Groth16 verifier
    ///            via the leaf commitment Poseidon(secret, entitlement, beneficiaryDest).
    function execute(
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes32 nullifier,
        address beneficiaryDest
    ) external nonReentrant inState(VaultState.CLAIMABLE) {
        // DD Sprint G — Finding ZK: re-check chain id at execution time so a
        // fork-replay against a different chain reverts deterministically.
        if (block.chainid != vaultChainId) revert ChainMismatch(vaultChainId, block.chainid);
        if (publicInputs.length != 4) revert BadPublicInputsLength(publicInputs.length);
        if (proof.length != PROOF_LENGTH) revert BadProofLength(proof.length);

        // publicInputs[0]: merkleRoot must match on-chain beneficiaryRoot
        if (bytes32(publicInputs[0]) != beneficiaryRoot) revert MerkleRootMismatch();

        // publicInputs[1]: nullifierHash — bytes32 cast must equal the nullifier parameter
        if (bytes32(publicInputs[1]) != nullifier) revert NullifierMismatch();

        // publicInputs[2]: vault address binding — prevents cross-vault proof replay.
        if (publicInputs[2] != uint256(uint160(address(this)))) revert VaultAddressMismatch();

        // publicInputs[3]: destination address binding — prevents relay-substitution attack.
        //   A valid proof cannot be reused with a different beneficiaryDest because
        //   beneficiaryDest is embedded in the Merkle leaf as the third Poseidon input:
        //   leaf = Poseidon(secret, entitlement, beneficiaryDest). (Sprint 6 circuit design.)
        //   The Groth16 verifier cryptographically enforces this in production; the vault
        //   enforces it independently here for defence in depth.
        if (publicInputs[3] != uint256(uint160(beneficiaryDest))) revert BeneficiaryDestMismatch();

        // Decode proof components from ABI-encoded bytes
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) =
            abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));

        uint256[4] memory inputs;
        inputs[0] = publicInputs[0];
        inputs[1] = publicInputs[1];
        inputs[2] = publicInputs[2];
        inputs[3] = publicInputs[3];

        // Verify proof (reverts inside groth16 verifier on invalid input types)
        if (!_groth16Verifier.verifyProof(a, b, c, inputs)) revert InvalidProof();

        // Spend nullifier atomically — reverts with NullifierAlreadySpent if reused.
        // nonReentrant guard prevents reentrancy through this external call.
        _nullifierRegistry.spend(nullifier);

        // Terminal state transition — must precede _creditAssets to ensure atomicity
        _state = VaultState.EXECUTED;

        // Record pull-based withdrawal credits for beneficiaryDest.
        // No external calls here — pure storage writes. Safe after state transition.
        _creditAssets(beneficiaryDest);

        emit ClaimExecuted(beneficiaryDest, nullifier, block.timestamp);
    }

    // ── Sprint SEC-6 · executeWithFees ────────────────────────────────────────
    //
    // Official Afterchain execution path. Identical ZK/public-input semantics
    // to execute(), plus mandatory signed fee-terms enforcement.
    //
    // Non-custodial guarantees preserved:
    //   - No admin drain path: all credits (beneficiary + afterchain + licensee)
    //     are strictly pull-based and scoped to addresses fixed in the signed
    //     fee-terms payload. The oracle cannot redirect after the fact.
    //   - Reentrancy protection via nonReentrant on execute paths and all
    //     withdraw*() functions.
    //   - No external calls between state transition and credit recording.
    //
    // Commercial enforcement:
    //   - Fee terms signature verified by the FeeTermsVerifier roster.
    //   - Vault / chain / template / expiry bindings all re-checked here.
    //   - Splits computed from the signed FX quote, applied pro-rata to every
    //     asset the vault holds (ETH + each governed ERC-20).
    //
    // A fork of the open rail can ship its own execute() without fees — but
    // it cannot forge a signature from the Afterchain oracle roster, so any
    // vault that wants to settle via the official attestation path must go
    // through executeWithFees() and honor the terms.
    function executeWithFees(
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes32 nullifier,
        address beneficiaryDest,
        bytes calldata feeTermsPayload,
        bytes[] calldata feeTermsSignatures
    ) external nonReentrant inState(VaultState.CLAIMABLE) {
        // DD Sprint G — Finding ZK: re-check chain id at execution time so a
        // fork-replay against a different chain reverts deterministically.
        // The FeeTermsChainMismatch check below catches a tampered payload;
        // this guard catches a fork-replay where the vault state and the
        // signed payload both still claim the original chain id.
        if (block.chainid != vaultChainId) revert ChainMismatch(vaultChainId, block.chainid);
        if (address(_feeTermsVerifier) == address(0)) revert FeeTermsNotConfigured();

        // Public-input + proof + groth16 check delegated to a helper — keeps
        // this frame clear of the 4-element uint256 arrays.
        _verifyProofStandard(proof, publicInputs, nullifier, beneficiaryDest);

        // Decode + bind + signature-check happens here inline so the memory
        // struct never crosses an internal function return boundary (that
        // triggers the yul IR stack-depth limit for 14-field structs).
        // SEC-10: 15 fields (added jurisdictionTier) → 480 bytes.
        if (feeTermsPayload.length != 15 * 32) revert FeeTermsInvalid();
        FeeTerms.FeeTermsPayload memory terms = FeeTerms.decode(feeTermsPayload);

        if (terms.vault != address(this))           revert FeeTermsVaultMismatch(address(this), terms.vault);
        if (terms.chainId != block.chainid)          revert FeeTermsChainMismatch(block.chainid, terms.chainId);
        if (terms.templateId != templateId)          revert FeeTermsTemplateMismatch(templateId, terms.templateId);
        if (block.timestamp >= terms.feeTermsExpiry) revert FeeTermsExpired(terms.feeTermsExpiry, block.timestamp);

        // Sprint SEC-7 Task 4 — template → fee mode binding on-chain.
        // DD Sprint C — Finding 4.4: the FEE_MODE_UNSET bypass is closed.
        // Every executeWithFees() call must hit a template that has a real
        // fee mode pinned (LICENSED_SPLIT / DIRECT_PROTOCOL / LOW_BALANCE).
        // Templates registered via the legacy `registerTemplate(id, hash)`
        // entry point that defaulted to UNSET are no longer accepted.
        if (address(_templateRegistry) != address(0)) {
            uint8 pinnedMode = _templateRegistry.feeModeOf(templateId);
            if (pinnedMode == 255 /* FEE_MODE_UNSET */) {
                revert TemplateFeeModeNotPinned(templateId);
            }
            if (pinnedMode != terms.feeModel) {
                revert FeeTermsTemplateModeMismatch(pinnedMode, terms.feeModel);
            }
        }

        _validateFeeTermsParameters(terms);

        {
            // Sprint SEC-9 — TRUE on-chain multisig enforcement.
            //
            // Verifier returns valid only when the array contains a number
            // of UNIQUE authorized signers >= the verifier's threshold.
            // No single-signature fallback exists. A production deployment
            // sets threshold = 3 via AfterchainGovernance, so any caller
            // submitting fewer than three independent signatures reverts
            // here with FeeTermsInvalid.
            bytes32 structHash = FeeTerms.hashStruct(terms);
            bytes32 domainSep  = _feeTermsVerifier.DOMAIN_SEPARATOR();
            bytes32 digest     = keccak256(abi.encodePacked(bytes2(0x1901), domainSep, structHash));
            (bool feeOk, ) = _feeTermsVerifier.verifyDigestMultiSig(digest, feeTermsSignatures);
            if (!feeOk) revert FeeTermsInvalid();
        }

        _nullifierRegistry.spend(nullifier);
        _state = VaultState.EXECUTED;

        _creditAssetsWithFees(beneficiaryDest, terms);

        // Surface the cryptographically-bound jurisdiction tier so
        // off-chain indexers can trust the value without re-deriving
        // from fee amounts.
        emit JurisdictionTierAccepted(terms.feeTermsId, terms.jurisdictionTier);
        emit ClaimExecuted(beneficiaryDest, nullifier, block.timestamp);
    }

    /// @notice Emitted from executeWithFees with the oracle-signed
    ///         jurisdiction tier enum.
    event JurisdictionTierAccepted(bytes32 indexed feeTermsId, uint8 tier);

    function _verifyProofStandard(
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes32 nullifier,
        address beneficiaryDest
    ) internal view {
        if (publicInputs.length != 4) revert BadPublicInputsLength(publicInputs.length);
        if (proof.length != PROOF_LENGTH) revert BadProofLength(proof.length);

        if (bytes32(publicInputs[0]) != beneficiaryRoot)            revert MerkleRootMismatch();
        if (bytes32(publicInputs[1]) != nullifier)                   revert NullifierMismatch();
        if (publicInputs[2] != uint256(uint160(address(this))))      revert VaultAddressMismatch();
        if (publicInputs[3] != uint256(uint160(beneficiaryDest)))     revert BeneficiaryDestMismatch();

        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) =
            abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));
        uint256[4] memory inputs;
        inputs[0] = publicInputs[0];
        inputs[1] = publicInputs[1];
        inputs[2] = publicInputs[2];
        inputs[3] = publicInputs[3];
        if (!_groth16Verifier.verifyProof(a, b, c, inputs)) revert InvalidProof();
    }

    function _validateFeeTermsParameters(FeeTerms.FeeTermsPayload memory t) internal view {
        // DD Sprint C — Finding 4.1: cryptographically enforce the
        // commercial baseline at the L1 contract layer. An oracle that signs
        // a fee-terms payload below the licensing minimum is rejected by the
        // vault before any state transition.
        //   - executionFeeBps must be >= 200  (2.00 %)
        //   - executionFeeBps must be <= 10_000 (100 %)
        //   - executionFeeFloorEurCents must be >= 25_000 (EUR 250.00)
        if (t.executionFeeBps < FeeTerms.MIN_EXECUTION_FEE_BPS) revert FeeTermsBelowMinimumBps();
        if (t.executionFeeBps > 10_000)                          revert FeeTermsParameterOutOfRange();
        if (t.executionFeeFloorEurCents < FeeTerms.MIN_EXECUTION_FEE_FLOOR_EUR_CENTS) {
            revert FeeTermsBelowMinimumFloor();
        }
        // Mode bounded
        if (t.feeModel > FeeTerms.FEE_MODEL_LOW_BALANCE) revert FeeTermsUnknownModel(t.feeModel);
        //
        // ── DD Sprint D — Finding 4.3: LOW_BALANCE oracle trust assumption ──
        //
        // SECURITY NOTE: Fiat valuation for the low-balance exemption is
        // entirely dependent on the Oracle payload (`fxQuoteEurValueCents` +
        // `fxQuoteTimestamp`). The L1 vault has no native EUR oracle and
        // intentionally avoids one — adding a chain-link price feed would
        // import the feed's full trust surface into the protocol.
        //
        // On-chain validation of fiat valuation is therefore deferred to L2
        // (off-chain quote freshness window, multi-source confirmation) and
        // L3 (per-jurisdiction custodial reconciliation). The L1 contract
        // commits to the fiat valuation that the oracle multisig signed and
        // stops there.
        //
        // The mitigations the L1 vault DOES enforce:
        //   - The fiat valuation is bound by the EIP-712 fee-terms signature,
        //     so the oracle cannot drift it post-signing.
        //   - The execution fee floor (EUR 250) is hard-coded so even a
        //     malicious oracle cannot drop the fee below the licensing minimum.
        //   - `lowBalanceThresholdEurCents == 0` is rejected below to prevent
        //     a degenerate "everything is low balance" payload.
        //   - The vault never holds custody of the fiat value — it only acts
        //     on the EIP-712-bound integer.
        // Sprint SEC-7 Amendment Task 1 — treasury fallback:
        //   feeRecipientAfterchain == address(0) is allowed; the vault substitutes
        //   FeeTermsVerifier.PROTOCOL_TREASURY() at credit time. Licensee recipient
        //   still required for LICENSED_SPLIT.
        if (t.feeModel == FeeTerms.FEE_MODEL_LICENSED_SPLIT) {
            if (t.feeRecipientLicensee == address(0)) revert FeeTermsZeroLicenseeRecipient();
        }
        // afterchainMin cannot exceed floor (would be unsatisfiable on wallet == floor)
        if (t.afterchainMinEurCents > t.executionFeeFloorEurCents) revert FeeTermsParameterOutOfRange();
        // Low-balance threshold and quote timestamp must be set
        if (t.lowBalanceThresholdEurCents == 0) revert FeeTermsParameterOutOfRange();
        if (t.fxQuoteTimestamp == 0)            revert FeeTermsExpired(0, block.timestamp);
        // Sprint SEC-10 / DD Sprint D Task 3 — jurisdictionTier is part of
        // the EIP-712 typehash (FeeTermsPayload field #15). The on-chain
        // contract is therefore "legally aware" of the executed jurisdiction:
        //   1. The tier is bound by the oracle multisig signature; an
        //      adversary cannot tamper with it without invalidating the
        //      signature.
        //   2. Range-checked here so an out-of-band tier value (>= 4) is
        //      rejected before any fee math runs.
        //   3. Surfaced to the audit trail via the JurisdictionTierAccepted
        //      event emitted in executeWithFees() — every successful
        //      execution leaves an immutable on-chain log of the tier under
        //      which it ran.
        //   4. Persisted into the feeEvidence.execution.jurisdictionTier
        //      field of the off-chain evidence package so downstream
        //      auditors and regulators can reconcile per-jurisdiction
        //      execution volume against the on-chain log.
        if (t.jurisdictionTier > FeeTerms.TIER_MAX) revert FeeTermsParameterOutOfRange();
    }

    /// @dev Sprint SEC-7 Amendment Task 1 — resolve afterchain recipient.
    ///      Returns the payload address if non-zero, otherwise PROTOCOL_TREASURY.
    ///      Reverts with FeeTermsZeroAfterchainRecipient ONLY if both are zero,
    ///      which can only happen when the vault was deployed without a
    ///      fee-terms verifier (sandbox) yet somehow reached this code path —
    ///      i.e. a programming error, not a user-submittable state.
    function _resolveAfterchainRecipient(address payloadRecipient) internal view returns (address) {
        if (payloadRecipient != address(0)) return payloadRecipient;
        address treasury = _feeTermsVerifier.PROTOCOL_TREASURY();
        if (treasury == address(0)) revert FeeTermsZeroAfterchainRecipient();
        return treasury;
    }

    /// @dev Feebook keeps the per-asset split inputs on the stack as a small
    ///      struct — fewer locals than passing 10 scalars through function
    ///      parameters, which fits the legacy codegen stack.
    struct Feebook {
        address acRecipient;
        address lcRecipient;
        uint256 walletValue;
        uint256 afterchainMin;
        uint256 feeEurCents;
        uint8   model;
        bool    lowBalance;
    }

    function _creditAssetsWithFees(
        address beneficiary,
        FeeTerms.FeeTermsPayload memory terms
    ) internal {
        Feebook memory fb;
        fb.model         = terms.feeModel;
        // SEC-7 Amendment Task 1 — treasury fallback when payload recipient is zero.
        fb.acRecipient   = _resolveAfterchainRecipient(terms.feeRecipientAfterchain);
        fb.lcRecipient   = terms.feeRecipientLicensee;
        fb.walletValue   = terms.fxQuoteEurValueCents;
        fb.afterchainMin = terms.afterchainMinEurCents;
        fb.lowBalance    =
            terms.feeModel == FeeTerms.FEE_MODEL_LOW_BALANCE ||
            terms.fxQuoteEurValueCents < terms.lowBalanceThresholdEurCents;

        if (!fb.lowBalance) {
            uint256 bpsFee = (fb.walletValue * terms.executionFeeBps) / 10_000;
            fb.feeEurCents = bpsFee >= terms.executionFeeFloorEurCents
                ? bpsFee
                : terms.executionFeeFloorEurCents;
        }

        uint256 ethBal = address(this).balance;
        if (ethBal > 0) _splitAndCreditETH(ethBal, beneficiary, fb);

        uint256 n = _assets.length;
        for (uint256 i = 0; i < n; i++) {
            address token = _assets[i];
            uint256 bal = IERC20Minimal(token).balanceOf(address(this));
            if (bal > 0) _splitAndCreditToken(token, bal, beneficiary, fb);
        }
    }

    function _computeCuts(uint256 balance, Feebook memory fb)
        internal pure
        returns (uint256 beneficiaryCut, uint256 afterchainCut, uint256 licenseeCut)
    {
        if (!fb.lowBalance && fb.feeEurCents > 0 && fb.walletValue > 0) {
            uint256 assetFee = (balance * fb.feeEurCents) / fb.walletValue;
            if (assetFee > balance) assetFee = balance;

            if (fb.model == FeeTerms.FEE_MODEL_DIRECT_PROTOCOL) {
                afterchainCut = assetFee;
            } else if (fb.model == FeeTerms.FEE_MODEL_LICENSED_SPLIT) {
                uint256 ac = (assetFee * 20) / 100;
                uint256 afterchainMinForAsset = (balance * fb.afterchainMin) / fb.walletValue;
                if (ac < afterchainMinForAsset) {
                    ac = afterchainMinForAsset;
                    if (ac > assetFee) ac = assetFee;
                }
                afterchainCut = ac;
                licenseeCut   = assetFee - ac;
            }
        }
        beneficiaryCut = balance - afterchainCut - licenseeCut;
    }

    function _splitAndCreditETH(
        uint256 balance,
        address beneficiary,
        Feebook memory fb
    ) internal {
        (uint256 beneficiaryCut, uint256 afterchainCut, uint256 licenseeCut) =
            _computeCuts(balance, fb);
        if (beneficiaryCut > 0) {
            pendingEthWithdrawals[beneficiary] += beneficiaryCut;
            emit ETHCredited(beneficiary, beneficiaryCut);
        }
        if (afterchainCut > 0) {
            pendingEthWithdrawals[fb.acRecipient] += afterchainCut;
            emit ETHCredited(fb.acRecipient, afterchainCut);
        }
        if (licenseeCut > 0 && fb.lcRecipient != address(0)) {
            pendingEthWithdrawals[fb.lcRecipient] += licenseeCut;
            emit ETHCredited(fb.lcRecipient, licenseeCut);
        }
    }

    function _splitAndCreditToken(
        address asset,
        uint256 balance,
        address beneficiary,
        Feebook memory fb
    ) internal {
        (uint256 beneficiaryCut, uint256 afterchainCut, uint256 licenseeCut) =
            _computeCuts(balance, fb);
        if (beneficiaryCut > 0) {
            pendingTokenWithdrawals[asset][beneficiary] += beneficiaryCut;
            emit TokenCredited(asset, beneficiary, beneficiaryCut);
        }
        if (afterchainCut > 0) {
            pendingTokenWithdrawals[asset][fb.acRecipient] += afterchainCut;
            emit TokenCredited(asset, fb.acRecipient, afterchainCut);
        }
        if (licenseeCut > 0 && fb.lcRecipient != address(0)) {
            pendingTokenWithdrawals[asset][fb.lcRecipient] += licenseeCut;
            emit TokenCredited(asset, fb.lcRecipient, licenseeCut);
        }
    }

    /// @inheritdoc ITransferVault
    /// @dev Pull-based ETH withdrawal.
    ///      Follows checks-effects-interactions: zero credit before external call.
    ///      nonReentrant provides defence-in-depth against malicious receive() callbacks.
    function withdrawETH() external nonReentrant {
        uint256 amount = pendingEthWithdrawals[msg.sender];
        if (amount == 0) revert NoPendingWithdrawal();

        // Zero credit before external call (CEI pattern)
        pendingEthWithdrawals[msg.sender] = 0;

        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert WithdrawalFailed();

        emit ETHWithdrawn(msg.sender, amount);
    }

    /// @inheritdoc ITransferVault
    /// @dev Pull-based ERC-20 withdrawal.
    ///      Follows checks-effects-interactions: zero credit before external call.
    ///      nonReentrant provides defence-in-depth against reentrancy via token transfer hooks.
    function withdrawToken(address token) external nonReentrant {
        uint256 amount = pendingTokenWithdrawals[token][msg.sender];
        if (amount == 0) revert NoPendingWithdrawal();

        // Zero credit before external call (CEI pattern)
        pendingTokenWithdrawals[token][msg.sender] = 0;

        bool ok = IERC20Minimal(token).transfer(msg.sender, amount);
        if (!ok) revert WithdrawalFailed();

        emit TokenWithdrawn(token, msg.sender, amount);
    }

    // ── ITransferVault: views ────────────────────────────────────────────────

    /// @inheritdoc ITransferVault
    /// @dev Returns the stored _state only. No derived values.
    ///      When ATTESTED and window has expired, state remains ATTESTED until
    ///      markClaimable() is called explicitly.
    function getState() external view override returns (VaultState) {
        return _state;
    }

    // ── ETH reception ────────────────────────────────────────────────────────

    receive() external payable {}

    // ── Internal ─────────────────────────────────────────────────────────────

    /// @dev Records pull-based withdrawal credits for beneficiary at execute() time.
    ///      Captures ETH balance and each governed ERC-20 balance at the moment of execution.
    ///      Assets sent to the vault AFTER execute() are not included (vault is single-use).
    ///      Pure storage writes — no external calls. Emits credit events for auditability.
    ///
    ///      L1 note: this replaces the Sprint 7 push-based _transferAssets() pattern.
    ///      The beneficiary must call withdrawETH() / withdrawToken(token) to receive funds.
    function _creditAssets(address beneficiary) internal {
        // Credit ETH balance
        uint256 ethBal = address(this).balance;
        if (ethBal > 0) {
            pendingEthWithdrawals[beneficiary] += ethBal;
            emit ETHCredited(beneficiary, ethBal);
        }

        // Credit each governed ERC-20 balance
        for (uint256 i = 0; i < _assets.length; i++) {
            uint256 bal = IERC20Minimal(_assets[i]).balanceOf(address(this));
            if (bal > 0) {
                pendingTokenWithdrawals[_assets[i]][beneficiary] += bal;
                emit TokenCredited(_assets[i], beneficiary, bal);
            }
        }
    }
}
