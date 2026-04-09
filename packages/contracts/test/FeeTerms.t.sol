// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/TransferVault.sol";
import "../src/TransferVaultFactory.sol";
import "../src/AttestationVerifier.sol";
import "../src/NullifierRegistry.sol";
import "../src/Groth16Verifier.sol";
import "../src/TemplateRegistry.sol";
import "../src/FeeTermsVerifier.sol";
import "../src/FeeTerms.sol";
import "../src/ITransferVaultFactory.sol";

/// @title FeeTermsTest — SEC-6 contract-level fee enforcement tests.
/// @notice Exercises the oracle-signed fee-terms path end-to-end through a
///         fresh factory configured with a real FeeTermsVerifier. Uses the
///         staging Groth16Verifier fixture proof shape for the ZK part so
///         the test is standalone from the real circuit.
contract FeeTermsTest is Test {
    // Fixture proof components (identical to TransferVault.t.sol)
    uint256[2]    FA = [uint256(1), uint256(2)];
    uint256[2][2] FB = [[uint256(3), uint256(4)], [uint256(5), uint256(6)]];
    uint256[2]    FC = [uint256(7), uint256(8)];
    uint256 internal constant FIXTURE_MERKLE_ROOT    = 9;
    uint256 internal constant FIXTURE_NULLIFIER_HASH = 10;

    bytes32 internal fixtureNullifier = bytes32(FIXTURE_NULLIFIER_HASH);
    bytes   internal fixtureProof;

    // Oracle key (Anvil account 1) — signs both attestations and fee terms
    uint256 internal oracleKey = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    address internal oracleAddr;

    // Recipients
    address internal afterchainRecipient = address(0xA11CE);
    address internal licenseeRecipient   = address(0xB0B);
    address internal beneficiary         = address(0x5EC6);

    // Contracts
    Groth16Verifier      internal groth16;
    TemplateRegistry     internal templateReg;
    NullifierRegistry    internal nullifierReg;
    AttestationVerifier  internal attestVerifier;
    FeeTermsVerifier     internal feeTermsVerifier;
    TransferVaultFactory internal factory;

    // DD Sprint C — Finding 4.4: the FEE_MODE_UNSET bypass is closed, so
    // every template used by executeWithFees must be pinned to a real fee
    // mode. Tests that exercise multiple modes register one template per mode.
    bytes32 internal tplLicensedSplit  = keccak256("afterchain.demo.licensed-split.v1");
    bytes32 internal tplDirectProtocol = keccak256("afterchain.demo.direct-protocol.v1");
    address internal vaultOwner = address(0x1234);

    // Common EUR constants (cents)
    uint256 internal constant EUR_250   = 25_000;  // EUR 250.00
    uint256 internal constant EUR_50    = 5_000;   // EUR 50.00
    uint256 internal constant FEE_BPS   = 200;     // 2.00%
    uint256 internal constant LOW_THRES = 25_000;  // EUR 250.00

    function setUp() public {
        vm.warp(1_700_000_000);
        oracleAddr = vm.addr(oracleKey);

        bytes32 fixtureHash = keccak256(abi.encode(FA, FB, FC));
        fixtureProof = abi.encode(FA, FB, FC);

        groth16      = new Groth16Verifier(fixtureHash);
        // DD Sprint A: TemplateRegistry takes (governance, initialTemplateId, initialConfigHash, initialFeeMode)
        templateReg  = new TemplateRegistry(address(this), bytes32(0), bytes32(0), 255);
        nullifierReg = new NullifierRegistry(address(this));
        // SEC-10: governance-controlled AttestationVerifier. Test contract
        // is the governance; threshold=1 for legacy single-sig path.
        {
            address[] memory _avSigners = new address[](1);
            _avSigners[0] = oracleAddr;
            attestVerifier = new AttestationVerifier(address(this), _avSigners, 1);
        }

        // Sprint SEC-8: governance-controlled verifier. In this unit-test
        // suite the test contract itself plays the role of "governance",
        // so it can seed the oracle key straight through the constructor.
        // Threshold = 1 keeps the legacy single-signer happy path compatible
        // with the pre-SEC-8 fee-terms scenarios in this file.
        address[] memory fvSigners = new address[](1);
        fvSigners[0] = oracleAddr;
        feeTermsVerifier = new FeeTermsVerifier(
            address(this),  // governance
            address(this),  // treasury
            fvSigners,      // initial signers
            1               // threshold (sandbox)
        );
        // SEC-8: oracle already seeded in the constructor. This line is kept
        // as a no-op sanity check that governance (= the test contract) can
        // re-add the same signer after removal — not needed for setUp.
        // (The actual seeding happens via `fvSigners` above.)

        factory = new TransferVaultFactory(
            address(attestVerifier),
            address(nullifierReg),
            address(groth16),
            address(templateReg),
            address(0xDEAD1),               // multiSigVerifier placeholder
            address(feeTermsVerifier)       // SEC-6 fee terms enforcement enabled
        );
        nullifierReg.setOperator(address(factory));
        // DD Sprint C — register both demo templates with explicit fee modes.
        templateReg.registerTemplateWithFeeMode(
            tplLicensedSplit, keccak256("config-ls"), FeeTerms.FEE_MODEL_LICENSED_SPLIT
        );
        templateReg.registerTemplateWithFeeMode(
            tplDirectProtocol, keccak256("config-dp"), FeeTerms.FEE_MODEL_DIRECT_PROTOCOL
        );
    }

    /// @dev Pick the demo template that matches the given fee mode. The
    ///      LOW_BALANCE flow is exercised through the LICENSED_SPLIT template
    ///      because the contract evaluates LOW_BALANCE based on wallet value,
    ///      not on the payload's feeModel byte.
    function _templateForMode(uint8 mode) internal view returns (bytes32) {
        if (mode == FeeTerms.FEE_MODEL_DIRECT_PROTOCOL) return tplDirectProtocol;
        return tplLicensedSplit;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// @dev DD Sprint C — vault creation is parameterized by the fee mode so
    ///      the vault's templateId matches the pinned mode in the registry.
    function _createVault() internal returns (TransferVault v) {
        return _createVaultForMode(FeeTerms.FEE_MODEL_LICENSED_SPLIT);
    }

    function _createVaultForMode(uint8 mode) internal returns (TransferVault v) {
        address[] memory assets = new address[](0);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: vaultOwner,
            templateId: _templateForMode(mode),
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours,
            assets: assets
        });
        v = TransferVault(payable(factory.createVault(cfg)));
    }

    function _makeAttestation(address vaultAddr) internal view returns (bytes memory) {
        // DD Sprint C: read the vault's pinned templateId so the attestation
        // matches whichever (LS / DP) template the vault was created against.
        bytes32 vaultTplId   = TransferVault(payable(vaultAddr)).templateId();
        bytes32 id           = keccak256(abi.encode(vaultAddr, block.chainid, block.timestamp));
        bytes32 evidenceHash = keccak256("evidence");
        bytes memory payload = abi.encode(
            id, vaultAddr, block.chainid, block.timestamp, block.timestamp + 1 days,
            vaultTplId, evidenceHash
        );
        bytes32 structHash = keccak256(abi.encode(
            attestVerifier.ATTESTATION_TYPE_HASH(),
            id, vaultAddr, block.chainid, block.timestamp, block.timestamp + 1 days,
            vaultTplId, evidenceHash
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", attestVerifier.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, digest);
        return abi.encodePacked(payload, abi.encodePacked(r, s, v));
    }

    function _claimable(TransferVault v) internal {
        v.attest(_makeAttestation(address(v)));
        vm.warp(v.challengeWindowEnd() + 1);
        v.markClaimable();
    }

    function _buildInputs(address vaultAddr) internal view returns (uint256[] memory inputs) {
        inputs = new uint256[](4);
        inputs[0] = FIXTURE_MERKLE_ROOT;
        inputs[1] = FIXTURE_NULLIFIER_HASH;
        inputs[2] = uint256(uint160(vaultAddr));
        inputs[3] = uint256(uint160(beneficiary));
    }

    function _makeTerms(
        address vaultAddr,
        uint8   model,
        uint256 walletValueEurCents
    ) internal view returns (FeeTerms.FeeTermsPayload memory t) {
        t.feeTermsId                   = keccak256(abi.encode(vaultAddr, "fee-terms-v1"));
        t.vault                        = vaultAddr;
        t.chainId                      = block.chainid;
        // DD Sprint C: read the vault's actual templateId so the payload's
        // templateId binding matches the on-chain vault state.
        t.templateId                   = TransferVault(payable(vaultAddr)).templateId();
        t.feeModel                     = model;
        t.feeRecipientAfterchain       = afterchainRecipient;
        t.feeRecipientLicensee         = model == FeeTerms.FEE_MODEL_LICENSED_SPLIT ? licenseeRecipient : address(0);
        t.executionFeeBps              = FEE_BPS;
        t.executionFeeFloorEurCents    = EUR_250;
        t.afterchainMinEurCents        = EUR_50;
        t.lowBalanceThresholdEurCents  = LOW_THRES;
        t.fxQuoteEurValueCents         = walletValueEurCents;
        t.fxQuoteTimestamp             = block.timestamp;
        t.feeTermsExpiry               = block.timestamp + 1 hours;
        t.jurisdictionTier             = FeeTerms.TIER_GREEN; // SEC-10
    }

    /// @dev Off-chain encoder that matches FeeTerms.decode() layout byte-for-byte.
    ///      Split into two halves to stay within the legacy solc stack limit.
    function _encodeTerms(FeeTerms.FeeTermsPayload memory t) internal pure returns (bytes memory) {
        bytes memory head = abi.encode(
            t.feeTermsId, t.vault, t.chainId, t.templateId,
            uint256(t.feeModel),  // pad uint8 to 32 bytes
            t.feeRecipientAfterchain, t.feeRecipientLicensee
        );
        bytes memory tail = abi.encode(
            t.executionFeeBps, t.executionFeeFloorEurCents,
            t.afterchainMinEurCents, t.lowBalanceThresholdEurCents,
            t.fxQuoteEurValueCents, t.fxQuoteTimestamp, t.feeTermsExpiry,
            uint256(t.jurisdictionTier) // SEC-10: pad uint8 to 32 bytes
        );
        return bytes.concat(head, tail);
    }

    /// SEC-9: TransferVault.executeWithFees now takes bytes[] signatures.
    /// FeeTermsVerifier.threshold is 1 in this sandbox suite, so a single
    /// signature wrapped in a 1-element array satisfies verifyDigestMultiSig.
    function _wrap(bytes memory sig) internal pure returns (bytes[] memory arr) {
        arr = new bytes[](1);
        arr[0] = sig;
    }

    function _signTerms(FeeTerms.FeeTermsPayload memory t)
        internal view
        returns (bytes memory encoded, bytes memory signature)
    {
        encoded = _encodeTerms(t);
        bytes32 structHash = FeeTerms.hashStruct(t);
        bytes32 domainSep  = feeTermsVerifier.DOMAIN_SEPARATOR();
        bytes32 digest     = keccak256(abi.encodePacked(bytes2(0x1901), domainSep, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    /// @dev T1: LICENSED_SPLIT with wallet >= EUR 250 — 80/20 split.
    function test_feeTerms_licensedSplit_above_threshold() public {
        TransferVault v = _createVault();
        vm.deal(address(v), 10 ether);
        _claimable(v);

        // Wallet value = EUR 10,000 → fee = max(2% × 10000, 250) = EUR 200 vs floor 250 → EUR 250.
        FeeTerms.FeeTermsPayload memory t = _makeTerms(
            address(v), FeeTerms.FEE_MODEL_LICENSED_SPLIT, 1_000_000 // EUR 10_000.00
        );
        (bytes memory enc, bytes memory sig) = _signTerms(t);

        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig));

        // feeEurCents = 25000. feeFraction = 25000 / 1000000 = 0.025 → 0.25 ETH total fee.
        // LICENSED_SPLIT default: ac = 20% × 0.25 = 0.05 ETH ; lc = 0.20 ETH.
        // afterchainMin in ETH = 10e18 × 5000/1000000 = 0.05 ETH (equal to ac, no bump).
        uint256 totalFee    = (10 ether * 25_000) / 1_000_000;        // 0.25 ether
        uint256 expectedAc  = (totalFee * 20) / 100;                   // 0.05 ether
        uint256 expectedLc  = totalFee - expectedAc;                   // 0.20 ether
        uint256 expectedBen = 10 ether - totalFee;                      // 9.75 ether

        assertEq(v.pendingEthWithdrawals(beneficiary),          expectedBen, "beneficiary cut");
        assertEq(v.pendingEthWithdrawals(afterchainRecipient),  expectedAc,  "afterchain cut");
        assertEq(v.pendingEthWithdrawals(licenseeRecipient),    expectedLc,  "licensee cut");
    }

    /// @dev T1b: LICENSED_SPLIT minimum-bump — afterchain min kicks in when
    ///      wallet is just above threshold and 20% of fee is below EUR 50.
    function test_feeTerms_licensedSplit_minimumBump() public {
        TransferVault v = _createVault();
        vm.deal(address(v), 1 ether);
        _claimable(v);

        // Wallet = EUR 250 exactly → fee floor = EUR 250 (whole wallet).
        // 20% of that = EUR 50 → equals afterchainMin → NO extra bump needed.
        //
        // To force a bump we use wallet EUR 251 (slightly above threshold):
        // total fee = max(2% × 251, 250) = 250 (floor).
        // 20% of 250 = 50 → equals afterchainMin → still no bump.
        //
        // A clearer case: wallet EUR 10 000, but with feeBps = 10 → fee = max(10, 250) = 250.
        // 20% × 250 = 50 = min. Still tight.
        //
        // A true bump scenario: afterchainMin > 20% of fee. Use
        // afterchainMin = 100, fee = 250 → 20% = 50 < 100 → bump to 100.
        FeeTerms.FeeTermsPayload memory t = _makeTerms(
            address(v), FeeTerms.FEE_MODEL_LICENSED_SPLIT, 1_000_000 // EUR 10_000
        );
        t.afterchainMinEurCents = 10_000; // EUR 100 — raises the bar above 20%
        (bytes memory enc, bytes memory sig) = _signTerms(t);

        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig));

        // total fee ETH = 1e18 × 25000/1_000_000 = 0.025 ether
        // 20% = 0.005 ether ; afterchainMinForAsset = 1e18 × 10000/1_000_000 = 0.01 ether
        // → afterchain bumped to 0.01 ether ; licensee = 0.015 ether.
        uint256 totalFee = (1 ether * 25_000) / 1_000_000;  // 0.025
        uint256 expectedAc = (1 ether * 10_000) / 1_000_000; // 0.01
        uint256 expectedLc = totalFee - expectedAc;          // 0.015
        uint256 expectedBen = 1 ether - totalFee;            // 0.975

        assertEq(v.pendingEthWithdrawals(beneficiary),         expectedBen);
        assertEq(v.pendingEthWithdrawals(afterchainRecipient), expectedAc);
        assertEq(v.pendingEthWithdrawals(licenseeRecipient),   expectedLc);
    }

    /// @dev T2: DIRECT_PROTOCOL — 100% of fee to afterchain.
    function test_feeTerms_directProtocol() public {
        TransferVault v = _createVaultForMode(FeeTerms.FEE_MODEL_DIRECT_PROTOCOL);
        vm.deal(address(v), 4 ether);
        _claimable(v);

        FeeTerms.FeeTermsPayload memory t = _makeTerms(
            address(v), FeeTerms.FEE_MODEL_DIRECT_PROTOCOL, 400_000 // EUR 4000
        );
        (bytes memory enc, bytes memory sig) = _signTerms(t);

        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig));

        // fee = max(2% × 4000, 250) = max(80, 250) = 250 EUR → 0.25 ETH.
        uint256 totalFee = (4 ether * 25_000) / 400_000; // 0.25 ether
        assertEq(v.pendingEthWithdrawals(beneficiary),         4 ether - totalFee);
        assertEq(v.pendingEthWithdrawals(afterchainRecipient), totalFee);
        assertEq(v.pendingEthWithdrawals(licenseeRecipient),   0);
    }

    /// @dev T3: Wallet < EUR 250 — no fee at all (LOW_BALANCE exemption).
    function test_feeTerms_lowBalance_exemption() public {
        TransferVault v = _createVault();
        vm.deal(address(v), 1 ether);
        _claimable(v);

        // Wallet value EUR 100 — below threshold (EUR 250).
        FeeTerms.FeeTermsPayload memory t = _makeTerms(
            address(v), FeeTerms.FEE_MODEL_LICENSED_SPLIT, 10_000 // EUR 100
        );
        (bytes memory enc, bytes memory sig) = _signTerms(t);

        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig));

        assertEq(v.pendingEthWithdrawals(beneficiary),         1 ether, "full balance to beneficiary");
        assertEq(v.pendingEthWithdrawals(afterchainRecipient), 0,       "no afterchain cut");
        assertEq(v.pendingEthWithdrawals(licenseeRecipient),   0,       "no licensee cut");
    }

    /// @dev T4: expired fee quote → revert.
    function test_feeTerms_expired_reverts() public {
        TransferVault v = _createVaultForMode(FeeTerms.FEE_MODEL_DIRECT_PROTOCOL);
        vm.deal(address(v), 1 ether);
        _claimable(v);

        FeeTerms.FeeTermsPayload memory t = _makeTerms(
            address(v), FeeTerms.FEE_MODEL_DIRECT_PROTOCOL, 1_000_000
        );
        t.feeTermsExpiry = block.timestamp; // already at expiry
        (bytes memory enc, bytes memory sig) = _signTerms(t);

        vm.expectRevert();
        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig));
    }

    /// @dev T5: tampered fee recipient after signing → revert
    ///      (digest no longer matches the signature).
    function test_feeTerms_tamperedRecipient_reverts() public {
        TransferVault v = _createVaultForMode(FeeTerms.FEE_MODEL_DIRECT_PROTOCOL);
        vm.deal(address(v), 1 ether);
        _claimable(v);

        FeeTerms.FeeTermsPayload memory t = _makeTerms(
            address(v), FeeTerms.FEE_MODEL_DIRECT_PROTOCOL, 1_000_000
        );
        (bytes memory enc, bytes memory sig) = _signTerms(t);

        // Rebuild the encoded payload with a different recipient — signature mismatch.
        t.feeRecipientAfterchain = address(0xDEAD);
        bytes memory badEnc = _encodeTerms(t);

        vm.expectRevert(TransferVault.FeeTermsInvalid.selector);
        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, badEnc, _wrap(sig));
    }

    /// @dev T6: tampered feeModel / bps after signing → revert.
    /// DD Sprint C: with the FEE_MODE_UNSET bypass closed, the templateRegistry
    /// binding check fires BEFORE the signature check — the tamper now reverts
    /// with FeeTermsTemplateModeMismatch (a stronger early revert).
    function test_feeTerms_tamperedModel_reverts() public {
        TransferVault v = _createVaultForMode(FeeTerms.FEE_MODEL_DIRECT_PROTOCOL);
        vm.deal(address(v), 1 ether);
        _claimable(v);

        FeeTerms.FeeTermsPayload memory t = _makeTerms(
            address(v), FeeTerms.FEE_MODEL_DIRECT_PROTOCOL, 1_000_000
        );
        (, bytes memory sig) = _signTerms(t);

        // Flip the mode + bps on the wire without re-signing.
        t.feeModel        = FeeTerms.FEE_MODEL_LICENSED_SPLIT;
        t.executionFeeBps = 900;
        t.feeRecipientLicensee = licenseeRecipient;
        bytes memory badEnc = _encodeTerms(t);

        vm.expectRevert(
            abi.encodeWithSelector(
                TransferVault.FeeTermsTemplateModeMismatch.selector,
                FeeTerms.FEE_MODEL_DIRECT_PROTOCOL,
                FeeTerms.FEE_MODEL_LICENSED_SPLIT
            )
        );
        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, badEnc, _wrap(sig));
    }

    /// @dev T7: fee terms for a different vault → FeeTermsVaultMismatch.
    function test_feeTerms_wrongVault_reverts() public {
        TransferVault v = _createVaultForMode(FeeTerms.FEE_MODEL_DIRECT_PROTOCOL);
        vm.deal(address(v), 1 ether);
        _claimable(v);

        FeeTerms.FeeTermsPayload memory t = _makeTerms(
            address(v), FeeTerms.FEE_MODEL_DIRECT_PROTOCOL, 1_000_000
        );
        t.vault = address(0xBAD); // vault binding fails
        (bytes memory enc, bytes memory sig) = _signTerms(t);

        vm.expectRevert(
            abi.encodeWithSelector(TransferVault.FeeTermsVaultMismatch.selector, address(v), address(0xBAD))
        );
        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig));
    }

    // ── DD Sprint C — Finding 4.1: commercial fee-floor enforcement ─────────

    /// @dev DD-C-1: an oracle that signs executionFeeBps < 200 (below the
    ///      licensing 2% minimum) is rejected by the vault. The contract is
    ///      now the absolute floor — no L2 trust required.
    function test_feeTerms_belowMinimumBps_reverts() public {
        TransferVault v = _createVaultForMode(FeeTerms.FEE_MODEL_LICENSED_SPLIT);
        vm.deal(address(v), 1 ether);
        _claimable(v);

        FeeTerms.FeeTermsPayload memory t = _makeTerms(
            address(v), FeeTerms.FEE_MODEL_LICENSED_SPLIT, 1_000_000
        );
        t.executionFeeBps = 199; // 1.99 % — one bp below the licensing minimum
        (bytes memory enc, bytes memory sig) = _signTerms(t);

        vm.expectRevert(TransferVault.FeeTermsBelowMinimumBps.selector);
        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig));
    }

    /// @dev DD-C-1: an oracle that signs executionFeeFloorEurCents < 25_000
    ///      (below EUR 250) is rejected by the vault.
    function test_feeTerms_belowMinimumFloor_reverts() public {
        TransferVault v = _createVaultForMode(FeeTerms.FEE_MODEL_LICENSED_SPLIT);
        vm.deal(address(v), 1 ether);
        _claimable(v);

        FeeTerms.FeeTermsPayload memory t = _makeTerms(
            address(v), FeeTerms.FEE_MODEL_LICENSED_SPLIT, 1_000_000
        );
        t.executionFeeFloorEurCents   = 24_999; // EUR 249.99
        // afterchainMin must stay <= floor or it would hit the older sanity
        // check first; lower it accordingly so the floor check is reached.
        t.afterchainMinEurCents       = 4_999;
        t.lowBalanceThresholdEurCents = 24_999;
        (bytes memory enc, bytes memory sig) = _signTerms(t);

        vm.expectRevert(TransferVault.FeeTermsBelowMinimumFloor.selector);
        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig));
    }

    // ── DD Sprint C — Finding 4.4: FEE_MODE_UNSET bypass closure ─────────────

    /// @dev DD-C-4: a vault whose template is registered without an explicit
    ///      fee mode (FEE_MODE_UNSET = 255) cannot reach executeWithFees(). The
    ///      legacy bypass is closed: every production template must pin a real
    ///      mode at registration time.
    function test_feeTerms_unsetTemplateMode_reverts() public {
        // Register a fresh template via the legacy entry point (which sets UNSET).
        bytes32 unsetTplId = keccak256("dd-sprint-c.unset.v1");
        templateReg.registerTemplate(unsetTplId, keccak256("config-unset"));

        // Build a vault bound to that template.
        address[] memory assets = new address[](0);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: vaultOwner,
            templateId: unsetTplId,
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours,
            assets: assets
        });
        TransferVault v = TransferVault(payable(factory.createVault(cfg)));
        vm.deal(address(v), 1 ether);
        _claimable(v);

        FeeTerms.FeeTermsPayload memory t = _makeTerms(
            address(v), FeeTerms.FEE_MODEL_LICENSED_SPLIT, 1_000_000
        );
        (bytes memory enc, bytes memory sig) = _signTerms(t);

        vm.expectRevert(
            abi.encodeWithSelector(TransferVault.TemplateFeeModeNotPinned.selector, unsetTplId)
        );
        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig));
    }

    /// @dev T8: fee terms for a different chainId → FeeTermsChainMismatch.
    function test_feeTerms_wrongChainId_reverts() public {
        TransferVault v = _createVaultForMode(FeeTerms.FEE_MODEL_DIRECT_PROTOCOL);
        vm.deal(address(v), 1 ether);
        _claimable(v);

        FeeTerms.FeeTermsPayload memory t = _makeTerms(
            address(v), FeeTerms.FEE_MODEL_DIRECT_PROTOCOL, 1_000_000
        );
        t.chainId = 0xC0FFEE;
        (bytes memory enc, bytes memory sig) = _signTerms(t);

        vm.expectRevert(
            abi.encodeWithSelector(TransferVault.FeeTermsChainMismatch.selector, block.chainid, uint256(0xC0FFEE))
        );
        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig));
    }
}
