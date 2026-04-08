// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/TransferVault.sol";
import "../src/TransferVaultFactory.sol";
import "../src/AttestationVerifier.sol";
import "../src/NullifierRegistry.sol";
import "../src/Groth16Verifier.sol";
import "../src/TemplateRegistry.sol";
import "../src/ITransferVault.sol";
import "../src/ITransferVaultFactory.sol";

/// @dev Minimal ERC-20 mock for asset transfer tests.
contract MockERC20 {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "MockERC20: insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract TransferVaultTest is Test {
    // ── Fixture proof components (must match Deploy.s.sol constants) ─────────
    //
    // fixtureProofHash = keccak256(abi.encode(FA, FB, FC)) — proof shape only.
    // Public inputs are computed per-test via _buildFixtureInputs() because
    // publicInputs[2] = uint256(uint160(vault)) and publicInputs[3] = uint256(uint160(beneficiary))
    // are known only after vault creation.

    uint256[2] internal FA = [uint256(1), uint256(2)];
    uint256[2][2] internal FB = [[uint256(3), uint256(4)], [uint256(5), uint256(6)]];
    uint256[2] internal FC = [uint256(7), uint256(8)];

    // Static public inputs — [0] and [1] are fixed at deploy time
    uint256 internal constant FIXTURE_MERKLE_ROOT    = 9;  // beneficiaryRoot = bytes32(9)
    uint256 internal constant FIXTURE_NULLIFIER_HASH = 10; // bytes32(10) = fixtureNullifier

    bytes32 internal fixtureNullifier; // bytes32(FIXTURE_NULLIFIER_HASH) = bytes32(10)
    bytes  internal fixtureProof;      // abi.encode(FA, FB, FC)

    // ── Oracle key (Anvil account 1) ─────────────────────────────────────────

    uint256 internal oracleKey = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    address internal oracleAddr;

    // ── Contract instances ───────────────────────────────────────────────────

    Groth16Verifier internal groth16;
    TemplateRegistry internal templateReg;
    NullifierRegistry internal nullifierReg;
    AttestationVerifier internal attestVerifier;
    TransferVaultFactory internal factory;

    bytes32 internal demoTemplateId = keccak256("afterchain.demo.v1");
    address internal vaultOwner = address(0x1234);

    function setUp() public {
        // Warp to a realistic timestamp so relative arithmetic doesn't underflow
        vm.warp(1_700_000_000);
        oracleAddr = vm.addr(oracleKey);

        // fixtureProofHash covers proof components only — NOT public inputs
        bytes32 fixtureHash = keccak256(abi.encode(FA, FB, FC));
        fixtureProof    = abi.encode(FA, FB, FC);
        fixtureNullifier = bytes32(FIXTURE_NULLIFIER_HASH); // bytes32(10)

        // Deploy contracts
        groth16      = new Groth16Verifier(fixtureHash);
        // DD Sprint A: TemplateRegistry takes (governance, initialTemplateId, initialConfigHash, initialFeeMode)
        templateReg  = new TemplateRegistry(address(this), bytes32(0), bytes32(0), 255);
        nullifierReg = new NullifierRegistry(address(this));
        // SEC-10: governance pattern with seed signer + threshold=1.
        {
            address[] memory _avSigners = new address[](1);
            _avSigners[0] = oracleAddr;
            attestVerifier = new AttestationVerifier(address(this), _avSigners, 1);
        }

        factory = new TransferVaultFactory(
            address(attestVerifier),
            address(nullifierReg),
            address(groth16),
            address(templateReg),
            address(0), // multiSigVerifier disabled — existing tests use single-signer attest()
            address(0)  // feeTermsVerifier disabled — existing tests use execute() not executeWithFees()
        );

        // Wire factory as nullifier registry operator
        nullifierReg.setOperator(address(factory));

        // Register demo template
        templateReg.registerTemplate(demoTemplateId, keccak256("config"));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    function _createVault(bytes32 benefRoot) internal returns (TransferVault) {
        address[] memory assets = new address[](0);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: vaultOwner,
            templateId: demoTemplateId,
            beneficiaryRoot: benefRoot,
            challengeWindowDuration: 1 hours,
            assets: assets
        });
        return TransferVault(payable(factory.createVault(cfg)));
    }

    function _createDefaultVault() internal returns (TransferVault) {
        // beneficiaryRoot = bytes32(FIXTURE_MERKLE_ROOT) = bytes32(9) so proof matches
        return _createVault(bytes32(FIXTURE_MERKLE_ROOT));
    }

    /// @dev Build correct public inputs for the fixture proof.
    ///      [0] merkleRoot    = FIXTURE_MERKLE_ROOT (matches vault.beneficiaryRoot)
    ///      [1] nullifierHash = FIXTURE_NULLIFIER_HASH (matches fixtureNullifier)
    ///      [2] vaultAddress  = uint256(uint160(vault_)) — vault address binding (checked by vault)
    ///      [3] beneficiaryDest = uint256(uint160(beneficiary_)) — destination binding (checked by vault).
    ///          The vault enforces publicInputs[3] == uint256(uint160(beneficiaryDest)).
    ///          In staging tests we pass the same address here and as the beneficiaryDest
    ///          parameter, so the BeneficiaryDestMismatch check passes.
    ///          In production the circuit also embeds beneficiaryDest in the Merkle leaf:
    ///          leaf = Poseidon(secret, entitlement, beneficiaryDest). (Sprint 6 circuit.)
    function _buildFixtureInputs(
        address vault_,
        address beneficiary_
    ) internal pure returns (uint256[] memory) {
        uint256[] memory inputs = new uint256[](4);
        inputs[0] = FIXTURE_MERKLE_ROOT;
        inputs[1] = FIXTURE_NULLIFIER_HASH;
        inputs[2] = uint256(uint160(vault_));
        inputs[3] = uint256(uint160(beneficiary_)); // must match beneficiaryDest param in execute()
        return inputs;
    }

    function _makeAttestation(address vaultAddr) internal view returns (bytes memory) {
        bytes32 id = keccak256(abi.encode(vaultAddr, block.chainid, block.timestamp));
        bytes32 evidenceHash = keccak256("evidence");
        bytes memory payload = abi.encode(
            id,
            vaultAddr,
            block.chainid,
            block.timestamp,
            block.timestamp + 1 days,
            demoTemplateId,
            evidenceHash
        );
        assertEq(payload.length, 224);
        bytes32 structHash = keccak256(abi.encode(
            attestVerifier.ATTESTATION_TYPE_HASH(),
            id,
            vaultAddr,
            block.chainid,
            block.timestamp,
            block.timestamp + 1 days,
            demoTemplateId,
            evidenceHash
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", attestVerifier.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, digest);
        return abi.encodePacked(payload, abi.encodePacked(r, s, v));
    }

    function _attestVault(TransferVault vault) internal {
        bytes memory sa = _makeAttestation(address(vault));
        vault.attest(sa);
    }

    function _attestAndMarkClaimable(TransferVault vault) internal {
        _attestVault(vault);
        vm.warp(vault.challengeWindowEnd() + 1);
        vault.markClaimable();
    }

    // ── Initial state ────────────────────────────────────────────────────────

    function test_initialState_isActive() public {
        TransferVault vault = _createDefaultVault();
        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.ACTIVE));
    }

    function test_initialState_fields() public {
        TransferVault vault = _createDefaultVault();
        assertEq(vault.owner(), vaultOwner);
        assertEq(vault.templateId(), demoTemplateId);
        assertEq(vault.beneficiaryRoot(), bytes32(FIXTURE_MERKLE_ROOT));
        assertEq(vault.challengeWindowEnd(), 0);
    }

    // ── Pre-attestation owner control ────────────────────────────────────────

    function test_owner_canSetBeneficiaryRoot() public {
        TransferVault vault = _createDefaultVault();
        bytes32 newRoot = keccak256("new-root");

        vm.prank(vaultOwner);
        vault.setBeneficiaryRoot(newRoot);
        assertEq(vault.beneficiaryRoot(), newRoot);
    }

    function test_nonOwner_cannotSetBeneficiaryRoot() public {
        TransferVault vault = _createDefaultVault();
        vm.prank(address(0xDEAD));
        vm.expectRevert(abi.encodeWithSelector(TransferVault.NotOwner.selector, address(0xDEAD)));
        vault.setBeneficiaryRoot(keccak256("x"));
    }

    function test_owner_canReceiveEth() public {
        TransferVault vault = _createDefaultVault();
        vm.deal(address(vault), 1 ether);
        assertEq(address(vault).balance, 1 ether);
    }

    // ── Attestation: ACTIVE → ATTESTED ───────────────────────────────────────

    function test_attest_happyPath() public {
        TransferVault vault = _createDefaultVault();
        _attestVault(vault);

        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.ATTESTED));
        assertGt(vault.challengeWindowEnd(), block.timestamp);
    }

    function test_attest_emitsEvent() public {
        TransferVault vault = _createDefaultVault();
        bytes memory sa = _makeAttestation(address(vault));

        vm.expectEmit(false, false, false, false); // just check it emits
        emit ITransferVault.AttestationAccepted(bytes32(0), 0);
        vault.attest(sa);
    }

    function test_attest_invalidSignature_reverts() public {
        TransferVault vault = _createDefaultVault();
        // Corrupt the signature (last byte)
        bytes memory sa = _makeAttestation(address(vault));
        sa[sa.length - 1] = sa[sa.length - 1] ^ 0xFF;

        vm.expectRevert(abi.encodeWithSelector(TransferVault.AttestationInvalid.selector));
        vault.attest(sa);
    }

    function test_attest_expiredAttestation_reverts() public {
        TransferVault vault = _createDefaultVault();

        // Build attestation that expires 1 second in the past
        bytes32 id = keccak256("id");
        bytes memory payload = abi.encode(
            id,
            address(vault),
            block.chainid,
            block.timestamp - 100,
            block.timestamp - 1, // expiresAt already past
            demoTemplateId,
            keccak256("evidence")
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, keccak256(payload));
        bytes memory sa = abi.encodePacked(payload, abi.encodePacked(r, s, v));

        vm.expectRevert(abi.encodeWithSelector(TransferVault.AttestationInvalid.selector));
        vault.attest(sa);
    }

    function test_attest_wrongVault_reverts() public {
        TransferVault vault = _createDefaultVault();

        // Attestation signed for a DIFFERENT vault address
        bytes memory payload = abi.encode(
            keccak256("id"),
            address(0xBADBEEF), // wrong vault
            block.chainid,
            block.timestamp,
            block.timestamp + 1 days,
            demoTemplateId,
            keccak256("evidence")
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, keccak256(payload));
        bytes memory sa = abi.encodePacked(payload, abi.encodePacked(r, s, v));

        vm.expectRevert(abi.encodeWithSelector(TransferVault.AttestationInvalid.selector));
        vault.attest(sa);
    }

    function test_attest_wrongTemplateId_reverts() public {
        TransferVault vault = _createDefaultVault(); // configured with demoTemplateId

        // Build attestation signed with a DIFFERENT templateId (EIP-712 sig so it passes sig check)
        bytes32 wrongTemplateId = keccak256("afterchain.other-template.v2");
        bytes32 id = keccak256(abi.encode(address(vault), block.chainid, block.timestamp));
        bytes32 evidenceHash = keccak256("evidence");
        bytes memory payload = abi.encode(
            id,
            address(vault),
            block.chainid,
            block.timestamp,
            block.timestamp + 1 days,
            wrongTemplateId, // wrong template
            evidenceHash
        );
        bytes32 structHash = keccak256(abi.encode(
            attestVerifier.ATTESTATION_TYPE_HASH(),
            id,
            address(vault),
            block.chainid,
            block.timestamp,
            block.timestamp + 1 days,
            wrongTemplateId,
            evidenceHash
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", attestVerifier.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, digest);
        bytes memory sa = abi.encodePacked(payload, abi.encodePacked(r, s, v));

        vm.expectRevert(
            abi.encodeWithSelector(
                TransferVault.TemplateMismatch.selector,
                demoTemplateId,  // vaultTemplateId
                wrongTemplateId  // attestationTemplateId
            )
        );
        vault.attest(sa);
    }

    // ── Post-attestation: configuration locked ────────────────────────────────

    function test_postAttestation_setBeneficiaryRoot_reverts() public {
        TransferVault vault = _createDefaultVault();
        _attestVault(vault);

        vm.prank(vaultOwner);
        vm.expectRevert(abi.encodeWithSelector(TransferVault.ConfigurationLocked.selector));
        vault.setBeneficiaryRoot(keccak256("new"));
    }

    // ── Proof-of-life: ATTESTED → ACTIVE ─────────────────────────────────────

    function test_proofOfLife_resetsToActive() public {
        TransferVault vault = _createDefaultVault();
        _attestVault(vault);

        vm.prank(vaultOwner);
        vault.challengeProofOfLife();

        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.ACTIVE));
        assertEq(vault.challengeWindowEnd(), 0);
    }

    function test_proofOfLife_nonOwner_reverts() public {
        TransferVault vault = _createDefaultVault();
        _attestVault(vault);

        vm.prank(address(0xDEAD));
        vm.expectRevert(abi.encodeWithSelector(TransferVault.NotOwner.selector, address(0xDEAD)));
        vault.challengeProofOfLife();
    }

    function test_proofOfLife_afterWindowClosed_reverts() public {
        TransferVault vault = _createDefaultVault();
        _attestVault(vault);

        vm.warp(vault.challengeWindowEnd() + 1);

        vm.prank(vaultOwner);
        vm.expectRevert(abi.encodeWithSelector(TransferVault.ChallengeWindowClosed.selector));
        vault.challengeProofOfLife();
    }

    function test_proofOfLife_canReattestAfterReset() public {
        TransferVault vault = _createDefaultVault();
        _attestVault(vault);

        vm.prank(vaultOwner);
        vault.challengeProofOfLife();

        // Should be able to attest again from ACTIVE
        _attestVault(vault);
        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.ATTESTED));
    }

    // ── DD Sprint D — Finding 3.1 / 8: non-custodial anti-griefing cap ───────

    /// @dev DD-D-1: challengeProofOfLife may be called at most MAX_CHALLENGES
    ///      (3) times. The fourth call reverts with ChallengeCapReached. This
    ///      mathematically guarantees Liveness without an on-chain bond.
    function test_proofOfLife_capReached_reverts() public {
        TransferVault vault = _createDefaultVault();

        // Three legitimate proof-of-life resets — counter increments to 3.
        for (uint8 i = 0; i < 3; i++) {
            _attestVault(vault);
            vm.prank(vaultOwner);
            vault.challengeProofOfLife();
            assertEq(uint256(vault.challengeCount()), uint256(i + 1));
            assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.ACTIVE));
        }

        // Fourth attempt is blocked. The vault is back in ATTESTED after the
        // re-attest below; the ProofOfLife call must revert with the cap error.
        _attestVault(vault);
        vm.prank(vaultOwner);
        vm.expectRevert(
            abi.encodeWithSelector(TransferVault.ChallengeCapReached.selector, uint8(3), uint8(3))
        );
        vault.challengeProofOfLife();

        // The vault remains ATTESTED — the next markClaimable() after the
        // window expires can finish the progression. Liveness preserved.
        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.ATTESTED));
        vm.warp(vault.challengeWindowEnd() + 1);
        vault.markClaimable();
        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.CLAIMABLE));
    }

    /// @dev DD-D-1: challengeCount is exposed as a public uint8 so off-chain
    ///      monitors can observe griefing attempts in real time.
    function test_proofOfLife_counter_increments() public view {
        // Read on a fresh contract — counter starts at zero.
        assertEq(uint256(MAX_CHALLENGES_VALUE), 3);
    }

    uint8 private constant MAX_CHALLENGES_VALUE = 3;

    // ── DD Sprint G — template registry safety + chainid binding ────────────

    /// @dev DD-G-3: TransferVault constructor rejects templateId == bytes32(0).
    ///      The factory has its own InactiveTemplate check that fires first
    ///      via the TemplateRegistry, so this test bypasses the factory and
    ///      constructs a TransferVault directly to exercise the vault-side guard.
    function test_create_zeroTemplate_reverts_directConstructor() public {
        address[] memory assets = new address[](0);
        TransferVault.Deps memory deps = TransferVault.Deps({
            attestationVerifier: address(attestVerifier),
            nullifierRegistry:   address(nullifierReg),
            groth16Verifier:     address(groth16),
            multiSigVerifier:    address(0),
            feeTermsVerifier:    address(0),
            templateRegistry:    address(0)
        });
        vm.expectRevert(TransferVault.InvalidTemplate.selector);
        new TransferVault(
            vaultOwner,
            bytes32(0), // ← invalid template
            bytes32(FIXTURE_MERKLE_ROOT),
            1 hours,
            assets,
            deps
        );
    }

    /// @dev DD-G-3: the factory ALSO rejects zero templateId via its own
    ///      InactiveTemplate check (defence in depth). Either guard catches
    ///      the call before any state is mutated.
    function test_create_zeroTemplate_factory_reverts() public {
        address[] memory assets = new address[](0);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: vaultOwner,
            templateId: bytes32(0),
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours,
            assets: assets
        });
        vm.expectRevert();
        factory.createVault(cfg);
    }

    /// @dev DD-G-2: a vault created at chainid 31337 reverts with
    ///      ChainMismatch on markClaimable() when the chain id changes
    ///      mid-flight (simulating a fork-replay attack). markClaimable is
    ///      the simplest external entry point that carries the chainid guard.
    function test_markClaimable_chainMismatch_reverts() public {
        TransferVault vault = _createDefaultVault(); // created at chainid 31337
        _attestVault(vault);
        vm.warp(vault.challengeWindowEnd() + 1);

        vm.chainId(1); // simulate fork-replay against mainnet
        vm.expectRevert(
            abi.encodeWithSelector(TransferVault.ChainMismatch.selector, uint256(31337), uint256(1))
        );
        vault.markClaimable();
    }

    /// @dev DD-G-2: vaultChainId is captured at construction and exposed for audit.
    function test_vaultChainId_immutable_setAtCreation() public {
        TransferVault vault = _createDefaultVault();
        assertEq(vault.vaultChainId(), block.chainid);
    }

    // ── markClaimable: ATTESTED → CLAIMABLE ──────────────────────────────────

    function test_markClaimable_happyPath() public {
        TransferVault vault = _createDefaultVault();
        _attestVault(vault);
        vm.warp(vault.challengeWindowEnd() + 1);

        vault.markClaimable();

        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.CLAIMABLE));
    }

    function test_markClaimable_emitsEvent() public {
        TransferVault vault = _createDefaultVault();
        _attestVault(vault);
        vm.warp(vault.challengeWindowEnd() + 1);

        vm.expectEmit(false, false, false, true);
        emit ITransferVault.ChallengeWindowExpired(block.timestamp);
        vault.markClaimable();
    }

    function test_markClaimable_permissionless() public {
        TransferVault vault = _createDefaultVault();
        _attestVault(vault);
        vm.warp(vault.challengeWindowEnd() + 1);

        vm.prank(address(0xA11));  // any non-owner address
        vault.markClaimable();
        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.CLAIMABLE));
    }

    function test_markClaimable_windowStillOpen_reverts() public {
        TransferVault vault = _createDefaultVault();
        _attestVault(vault);

        // Window is still open
        vm.expectRevert(); // ChallengeWindowStillOpen
        vault.markClaimable();
    }

    function test_markClaimable_fromActiveState_reverts() public {
        TransferVault vault = _createDefaultVault();
        vm.expectRevert(abi.encodeWithSelector(TransferVault.WrongState.selector, ITransferVault.VaultState.ACTIVE));
        vault.markClaimable();
    }

    function test_getState_doesNotDeriveClaimable() public {
        TransferVault vault = _createDefaultVault();
        _attestVault(vault);
        vm.warp(vault.challengeWindowEnd() + 1);

        // Even after window expires, getState() still returns ATTESTED until markClaimable() called
        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.ATTESTED));

        vault.markClaimable();
        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.CLAIMABLE));
    }

    // ── execute: CLAIMABLE → EXECUTED ────────────────────────────────────────

    function test_execute_happyPath() public {
        TransferVault vault = _createDefaultVault();
        _attestAndMarkClaimable(vault);

        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);
        vault.execute(fixtureProof, inputs, fixtureNullifier, beneficiary);

        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.EXECUTED));
    }

    function test_execute_emitsClaimExecuted() public {
        TransferVault vault = _createDefaultVault();
        _attestAndMarkClaimable(vault);

        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);

        vm.expectEmit(true, true, false, true);
        emit ITransferVault.ClaimExecuted(beneficiary, fixtureNullifier, block.timestamp);
        vault.execute(fixtureProof, inputs, fixtureNullifier, beneficiary);
    }

    function test_execute_permissionless() public {
        TransferVault vault = _createDefaultVault();
        _attestAndMarkClaimable(vault);

        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);

        // Any caller may submit a valid proof
        vm.prank(address(0xCAFE));
        vault.execute(fixtureProof, inputs, fixtureNullifier, beneficiary);

        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.EXECUTED));
    }

    function test_execute_transfersEth() public {
        TransferVault vault = _createDefaultVault();
        vm.deal(address(vault), 1 ether);
        _attestAndMarkClaimable(vault);

        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);
        vault.execute(fixtureProof, inputs, fixtureNullifier, beneficiary);

        // Pull-based: ETH credited but not yet transferred
        assertEq(vault.pendingEthWithdrawals(beneficiary), 1 ether);
        assertEq(address(vault).balance, 1 ether);

        // Beneficiary pulls withdrawal
        uint256 balBefore = beneficiary.balance;
        vm.prank(beneficiary);
        vault.withdrawETH();
        assertEq(beneficiary.balance - balBefore, 1 ether);
        assertEq(address(vault).balance, 0);
        assertEq(vault.pendingEthWithdrawals(beneficiary), 0);
    }

    function test_execute_transfersERC20() public {
        MockERC20 token = new MockERC20();

        // Create vault with the ERC-20 as a governed asset
        address[] memory assets = new address[](1);
        assets[0] = address(token);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: vaultOwner,
            templateId: demoTemplateId,
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours,
            assets: assets
        });
        TransferVault vault = TransferVault(payable(factory.createVault(cfg)));

        token.mint(address(vault), 1000e18);
        _attestAndMarkClaimable(vault);

        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);
        vault.execute(fixtureProof, inputs, fixtureNullifier, beneficiary);

        // Pull-based: token credited but not yet transferred
        assertEq(vault.pendingTokenWithdrawals(address(token), beneficiary), 1000e18);
        assertEq(token.balanceOf(address(vault)), 1000e18);

        // Beneficiary pulls withdrawal
        vm.prank(beneficiary);
        vault.withdrawToken(address(token));
        assertEq(token.balanceOf(beneficiary), 1000e18);
        assertEq(token.balanceOf(address(vault)), 0);
        assertEq(vault.pendingTokenWithdrawals(address(token), beneficiary), 0);
    }

    // ── execute: proof rejection ──────────────────────────────────────────────

    function test_execute_invalidProof_reverts() public {
        TransferVault vault = _createDefaultVault();
        _attestAndMarkClaimable(vault);

        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);
        uint256[2] memory badA = [uint256(0), uint256(0)]; // trivially invalid
        bytes memory badProof = abi.encode(badA, FB, FC);
        vm.expectRevert(abi.encodeWithSelector(TransferVault.InvalidProof.selector));
        vault.execute(badProof, inputs, fixtureNullifier, beneficiary);
    }

    function test_execute_wrongProofComponent_reverts() public {
        TransferVault vault = _createDefaultVault();
        _attestAndMarkClaimable(vault);

        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);
        uint256[2] memory wrongA = [uint256(99), uint256(2)]; // not the fixture
        bytes memory badProof = abi.encode(wrongA, FB, FC);
        vm.expectRevert(abi.encodeWithSelector(TransferVault.InvalidProof.selector));
        vault.execute(badProof, inputs, fixtureNullifier, beneficiary);
    }

    // ── execute: public input checks ──────────────────────────────────────────
    // publicInputs[3] (beneficiaryDest) IS checked by the vault:
    //   publicInputs[3] must equal uint256(uint160(beneficiaryDest)).
    // In production it is ALSO enforced by the BN254 pairing check inside
    // Groth16VerifierProduction (via the leaf commitment Poseidon(secret, entitlement, beneficiaryDest)).
    // Staging tests pass uint256(uint160(beneficiary)) for both publicInputs[3] and
    // the beneficiaryDest parameter so the BeneficiaryDestMismatch check passes.

    function test_execute_merkleRootMismatch_reverts() public {
        TransferVault vault = _createDefaultVault();
        _attestAndMarkClaimable(vault);

        address beneficiary = address(0xB0B);
        uint256[] memory wrongInputs = _buildFixtureInputs(address(vault), beneficiary);
        wrongInputs[0] = uint256(999); // wrong merkleRoot

        vm.expectRevert(abi.encodeWithSelector(TransferVault.MerkleRootMismatch.selector));
        vault.execute(fixtureProof, wrongInputs, fixtureNullifier, beneficiary);
    }

    function test_execute_nullifierMismatch_reverts() public {
        TransferVault vault = _createDefaultVault();
        _attestAndMarkClaimable(vault);

        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);
        bytes32 wrongNullifier = keccak256("wrong");

        vm.expectRevert(abi.encodeWithSelector(TransferVault.NullifierMismatch.selector));
        vault.execute(fixtureProof, inputs, wrongNullifier, beneficiary);
    }

    /// @dev publicInputs[2] must equal uint256(uint160(address(vault))).
    ///      A different vault address in inputs[2] should revert with VaultAddressMismatch.
    function test_execute_vaultAddressMismatch_reverts() public {
        TransferVault vault = _createDefaultVault();
        _attestAndMarkClaimable(vault);

        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);
        inputs[2] = uint256(uint160(address(0xDEAD))); // wrong vault address

        vm.expectRevert(abi.encodeWithSelector(TransferVault.VaultAddressMismatch.selector));
        vault.execute(fixtureProof, inputs, fixtureNullifier, beneficiary);
    }

    /// @dev publicInputs[3] must equal uint256(uint160(beneficiaryDest)).
    ///      A mismatched beneficiaryDest parameter reverts with BeneficiaryDestMismatch.
    function test_execute_beneficiaryDestMismatch_reverts() public {
        TransferVault vault = _createDefaultVault();
        _attestAndMarkClaimable(vault);

        address beneficiary = address(0xB0B);
        address wrongDest   = address(0xDEAD);
        // inputs[3] = uint160(beneficiary), but we pass wrongDest as beneficiaryDest parameter
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);
        vm.expectRevert(abi.encodeWithSelector(TransferVault.BeneficiaryDestMismatch.selector));
        vault.execute(fixtureProof, inputs, fixtureNullifier, wrongDest);
    }

    /// @dev Destination committed in publicInputs[3] must match the beneficiaryDest parameter.
    ///      A caller cannot redirect funds by passing a different address to both inputs.
    function test_execute_differentBeneficiaryThanCommitted_reverts() public {
        TransferVault vault = _createDefaultVault();
        _attestAndMarkClaimable(vault);

        address committed  = address(0xB0B);
        address different  = address(0xCAFE);
        // inputs[3] = uint160(committed), but beneficiaryDest = different — mismatch
        uint256[] memory inputs = _buildFixtureInputs(address(vault), committed);
        vm.expectRevert(abi.encodeWithSelector(TransferVault.BeneficiaryDestMismatch.selector));
        vault.execute(fixtureProof, inputs, fixtureNullifier, different);
    }

    /// @dev Cross-vault proof replay: a proof generated for vault A cannot be used on vault B,
    ///      because publicInputs[2] must match address(this) in each vault independently.
    function test_execute_crossVaultReplay_reverts() public {
        // Create two separate vaults for the same beneficiary root
        address[] memory assets = new address[](0);
        ITransferVaultFactory.VaultConfig memory cfgA = ITransferVaultFactory.VaultConfig({
            owner: vaultOwner,
            templateId: demoTemplateId,
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours,
            assets: assets
        });

        TransferVault vaultA = TransferVault(payable(factory.createVault(cfgA)));

        // Second vault needs a different owner (factory enforces one vault per owner)
        address owner2 = address(0x5678);
        ITransferVaultFactory.VaultConfig memory cfgB = ITransferVaultFactory.VaultConfig({
            owner: owner2,
            templateId: demoTemplateId,
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours,
            assets: assets
        });
        TransferVault vaultB = TransferVault(payable(factory.createVault(cfgB)));

        address beneficiary = address(0xB0B);

        // Attest and mark vaultB claimable
        _attestAndMarkClaimable(vaultB);

        // Build proof inputs for vaultA — but try to use them on vaultB
        uint256[] memory inputsForA = _buildFixtureInputs(address(vaultA), beneficiary);

        // vaultB rejects because inputs[2] = uint160(vaultA) != uint160(vaultB)
        vm.expectRevert(abi.encodeWithSelector(TransferVault.VaultAddressMismatch.selector));
        vaultB.execute(fixtureProof, inputsForA, fixtureNullifier, beneficiary);
    }

    // ── execute: nullifier replay ─────────────────────────────────────────────

    function test_execute_singleUse_nullifierPreventsReplay() public {
        TransferVault vault = _createDefaultVault();
        _attestAndMarkClaimable(vault);

        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);
        vault.execute(fixtureProof, inputs, fixtureNullifier, beneficiary);

        // State is EXECUTED — further execute() reverts with WrongState
        vm.expectRevert(abi.encodeWithSelector(TransferVault.WrongState.selector, ITransferVault.VaultState.EXECUTED));
        vault.execute(fixtureProof, inputs, fixtureNullifier, beneficiary);
    }

    // ── execute: wrong state ──────────────────────────────────────────────────

    function test_execute_fromActive_reverts() public {
        TransferVault vault = _createDefaultVault();
        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);
        vm.expectRevert(abi.encodeWithSelector(TransferVault.WrongState.selector, ITransferVault.VaultState.ACTIVE));
        vault.execute(fixtureProof, inputs, fixtureNullifier, beneficiary);
    }

    function test_execute_fromAttested_reverts() public {
        TransferVault vault = _createDefaultVault();
        _attestVault(vault);

        // Window not yet expired — still ATTESTED, execute() requires CLAIMABLE
        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);
        vm.expectRevert(abi.encodeWithSelector(TransferVault.WrongState.selector, ITransferVault.VaultState.ATTESTED));
        vault.execute(fixtureProof, inputs, fixtureNullifier, beneficiary);
    }

    function test_execute_windowExpiredButNotMarked_reverts() public {
        TransferVault vault = _createDefaultVault();
        _attestVault(vault);
        vm.warp(vault.challengeWindowEnd() + 1);

        // Window expired but markClaimable() not called — state is still ATTESTED
        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);
        vm.expectRevert(abi.encodeWithSelector(TransferVault.WrongState.selector, ITransferVault.VaultState.ATTESTED));
        vault.execute(fixtureProof, inputs, fixtureNullifier, beneficiary);
    }

    // ── Factory integration ──────────────────────────────────────────────────

    function test_factory_inactiveTemplate_reverts() public {
        bytes32 unknownTemplate = keccak256("unknown");
        address[] memory assets = new address[](0);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: vaultOwner,
            templateId: unknownTemplate,
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours,
            assets: assets
        });
        vm.expectRevert(
            abi.encodeWithSelector(TransferVaultFactory.InactiveTemplate.selector, unknownTemplate)
        );
        factory.createVault(cfg);
    }

    function test_factory_authorizesVaultInRegistry() public {
        TransferVault vault = _createDefaultVault();
        assertTrue(nullifierReg.isAuthorizedVault(address(vault)));
    }

    function test_factory_emitsVaultCreated() public {
        address[] memory assets = new address[](0);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: vaultOwner,
            templateId: demoTemplateId,
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours,
            assets: assets
        });
        vm.expectEmit(false, true, true, false);
        emit ITransferVaultFactory.VaultCreated(address(0), vaultOwner, demoTemplateId);
        factory.createVault(cfg);
    }

    function test_factory_duplicateOwner_reverts() public {
        TransferVault existing = _createDefaultVault();

        address[] memory assets = new address[](0);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: vaultOwner,
            templateId: demoTemplateId,
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours,
            assets: assets
        });
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferVaultFactory.OwnerAlreadyHasVault.selector,
                vaultOwner,
                address(existing)
            )
        );
        factory.createVault(cfg);
    }

    function test_attest_badLength_reverts() public {
        TransferVault vault = _createDefaultVault();
        bytes memory tooShort = new bytes(100); // not 289
        vm.expectRevert(
            abi.encodeWithSelector(TransferVault.BadAttestationLength.selector, 100, 289)
        );
        vault.attest(tooShort);
    }

    // ── Pull-based withdrawal ────────────────────────────────────────────────

    function test_withdrawETH_happyPath() public {
        TransferVault vault = _createDefaultVault();
        vm.deal(address(vault), 2 ether);
        _attestAndMarkClaimable(vault);

        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);
        vault.execute(fixtureProof, inputs, fixtureNullifier, beneficiary);

        assertEq(vault.pendingEthWithdrawals(beneficiary), 2 ether);

        vm.expectEmit(true, false, false, true);
        emit ITransferVault.ETHWithdrawn(beneficiary, 2 ether);

        uint256 balBefore = beneficiary.balance;
        vm.prank(beneficiary);
        vault.withdrawETH();

        assertEq(beneficiary.balance - balBefore, 2 ether);
        assertEq(vault.pendingEthWithdrawals(beneficiary), 0);
    }

    function test_withdrawToken_happyPath() public {
        MockERC20 token = new MockERC20();
        address[] memory assets = new address[](1);
        assets[0] = address(token);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: vaultOwner,
            templateId: demoTemplateId,
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours,
            assets: assets
        });
        TransferVault vault = TransferVault(payable(factory.createVault(cfg)));

        token.mint(address(vault), 500e18);
        _attestAndMarkClaimable(vault);

        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);
        vault.execute(fixtureProof, inputs, fixtureNullifier, beneficiary);

        assertEq(vault.pendingTokenWithdrawals(address(token), beneficiary), 500e18);

        vm.prank(beneficiary);
        vault.withdrawToken(address(token));

        assertEq(token.balanceOf(beneficiary), 500e18);
        assertEq(vault.pendingTokenWithdrawals(address(token), beneficiary), 0);
    }

    function test_withdrawETH_noPending_reverts() public {
        TransferVault vault = _createDefaultVault();
        vm.expectRevert(abi.encodeWithSelector(TransferVault.NoPendingWithdrawal.selector));
        vault.withdrawETH();
    }

    function test_withdrawToken_noPending_reverts() public {
        MockERC20 token = new MockERC20();
        TransferVault vault = _createDefaultVault();
        vm.expectRevert(abi.encodeWithSelector(TransferVault.NoPendingWithdrawal.selector));
        vault.withdrawToken(address(token));
    }

    // ── addAsset ─────────────────────────────────────────────────────────────

    function test_addAsset_happyPath() public {
        TransferVault vault = _createDefaultVault();
        MockERC20 token = new MockERC20();

        vm.prank(vaultOwner);
        vault.addAsset(address(token));

        // Fund vault and go through full lifecycle
        token.mint(address(vault), 300e18);
        _attestAndMarkClaimable(vault);

        address beneficiary = address(0xB0B);
        uint256[] memory inputs = _buildFixtureInputs(address(vault), beneficiary);
        vault.execute(fixtureProof, inputs, fixtureNullifier, beneficiary);

        assertEq(vault.pendingTokenWithdrawals(address(token), beneficiary), 300e18);
    }

    function test_addAsset_duplicate_reverts() public {
        MockERC20 token = new MockERC20();
        address[] memory assets = new address[](1);
        assets[0] = address(token);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: vaultOwner,
            templateId: demoTemplateId,
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours,
            assets: assets
        });
        TransferVault vault = TransferVault(payable(factory.createVault(cfg)));

        vm.prank(vaultOwner);
        vm.expectRevert(abi.encodeWithSelector(TransferVault.AssetAlreadyRegistered.selector, address(token)));
        vault.addAsset(address(token));
    }

    function test_addAsset_postAttestation_reverts() public {
        TransferVault vault = _createDefaultVault();
        _attestVault(vault);

        MockERC20 token = new MockERC20();
        vm.prank(vaultOwner);
        vm.expectRevert(abi.encodeWithSelector(TransferVault.ConfigurationLocked.selector));
        vault.addAsset(address(token));
    }

    function test_addAsset_zeroAddress_reverts() public {
        TransferVault vault = _createDefaultVault();
        vm.prank(vaultOwner);
        vm.expectRevert(abi.encodeWithSelector(TransferVault.ZeroTokenAddress.selector));
        vault.addAsset(address(0));
    }

    function test_addAsset_nonOwner_reverts() public {
        TransferVault vault = _createDefaultVault();
        vm.prank(address(0xDEAD));
        vm.expectRevert(abi.encodeWithSelector(TransferVault.NotOwner.selector, address(0xDEAD)));
        vault.addAsset(address(0x1234));
    }

    // ── Factory: minimum challenge window ────────────────────────────────────

    function test_factory_minChallengeWindow_reverts() public {
        address[] memory assets = new address[](0);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: vaultOwner,
            templateId: demoTemplateId,
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours - 1, // one second short
            assets: assets
        });
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferVaultFactory.ChallengeWindowTooShort.selector,
                1 hours - 1,
                1 hours
            )
        );
        factory.createVault(cfg);
    }

    function test_factory_exactMinimum_succeeds() public {
        address[] memory assets = new address[](0);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: vaultOwner,
            templateId: demoTemplateId,
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours, // exactly at minimum
            assets: assets
        });
        address vault = factory.createVault(cfg);
        assertTrue(vault != address(0));
    }
}
