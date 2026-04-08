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

/// @title FeeTermsSec7Test — Sprint SEC-7 Task 10 security tests.
/// @notice Covers the additional enforcement paths added in SEC-7:
///          - template → fee mode binding (LICENSED ↛ DIRECT downgrade)
///          - executeWithFees / execute() nullifier replay interaction
///          - expired fee terms (stale FX quote) revert path
///          - fee-terms binding checks (already in FeeTerms.t.sol, mirrored here
///            for a template-pinned factory)
contract FeeTermsSec7Test is Test {
    uint256[2]    FA = [uint256(1), uint256(2)];
    uint256[2][2] FB = [[uint256(3), uint256(4)], [uint256(5), uint256(6)]];
    uint256[2]    FC = [uint256(7), uint256(8)];
    uint256 internal constant FIXTURE_MERKLE_ROOT    = 9;
    uint256 internal constant FIXTURE_NULLIFIER_HASH = 10;

    bytes32 internal fixtureNullifier = bytes32(FIXTURE_NULLIFIER_HASH);
    bytes   internal fixtureProof;

    uint256 internal oracleKey = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    address internal oracleAddr;

    address internal afterchainRecipient = address(0xA11CE);
    address internal licenseeRecipient   = address(0xB0B);
    address internal beneficiary         = address(0x5EC6);

    Groth16Verifier      internal groth16;
    TemplateRegistry     internal templateReg;
    NullifierRegistry    internal nullifierReg;
    AttestationVerifier  internal attestVerifier;
    FeeTermsVerifier     internal feeTermsVerifier;
    TransferVaultFactory internal factory;

    // Two templates: one pinned to LICENSED_SPLIT, one pinned to DIRECT_PROTOCOL.
    bytes32 internal tplLicensed = keccak256("sec7.licensed.v1");
    bytes32 internal tplDirect   = keccak256("sec7.direct.v1");
    address internal vaultOwner  = address(0x1234);

    uint256 internal constant EUR_250 = 25_000;
    uint256 internal constant EUR_50  =  5_000;

    function setUp() public {
        vm.warp(1_700_000_000);
        oracleAddr = vm.addr(oracleKey);

        bytes32 fixtureHash = keccak256(abi.encode(FA, FB, FC));
        fixtureProof = abi.encode(FA, FB, FC);

        groth16      = new Groth16Verifier(fixtureHash);
        // DD Sprint A: TemplateRegistry takes (governance, initialTemplateId, initialConfigHash, initialFeeMode)
        templateReg  = new TemplateRegistry(address(this), bytes32(0), bytes32(0), 255);
        nullifierReg = new NullifierRegistry(address(this));
        {
            // SEC-10 governance pattern.
            address[] memory _avSigners = new address[](1);
            _avSigners[0] = oracleAddr;
            attestVerifier = new AttestationVerifier(address(this), _avSigners, 1);
        }

        {
            address[] memory fvSigners = new address[](1);
            fvSigners[0] = oracleAddr;
            feeTermsVerifier = new FeeTermsVerifier(
                address(this), // governance = this test contract
                address(this), // treasury
                fvSigners,
                1              // threshold (sandbox)
            );
        }

        factory = new TransferVaultFactory(
            address(attestVerifier),
            address(nullifierReg),
            address(groth16),
            address(templateReg),
            address(0),
            address(feeTermsVerifier)
        );
        nullifierReg.setOperator(address(factory));

        // SEC-7: templates are pinned to a single fee mode at registration.
        templateReg.registerTemplateWithFeeMode(
            tplLicensed, keccak256("cfg-l"), FeeTerms.FEE_MODEL_LICENSED_SPLIT
        );
        templateReg.registerTemplateWithFeeMode(
            tplDirect,   keccak256("cfg-d"), FeeTerms.FEE_MODEL_DIRECT_PROTOCOL
        );
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    function _createVault(bytes32 templateId) internal returns (TransferVault v) {
        address[] memory assets = new address[](0);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: vaultOwner,
            templateId: templateId,
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours,
            assets: assets
        });
        v = TransferVault(payable(factory.createVault(cfg)));
    }

    function _makeAttestation(address vaultAddr, bytes32 templateId) internal view returns (bytes memory) {
        bytes32 id = keccak256(abi.encode(vaultAddr, block.chainid, block.timestamp));
        bytes32 evidenceHash = keccak256("evidence");
        bytes memory payload = abi.encode(
            id, vaultAddr, block.chainid, block.timestamp, block.timestamp + 1 days,
            templateId, evidenceHash
        );
        bytes32 structHash = keccak256(abi.encode(
            attestVerifier.ATTESTATION_TYPE_HASH(),
            id, vaultAddr, block.chainid, block.timestamp, block.timestamp + 1 days,
            templateId, evidenceHash
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", attestVerifier.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, digest);
        return abi.encodePacked(payload, abi.encodePacked(r, s, v));
    }

    function _claimable(TransferVault v, bytes32 tpl) internal {
        v.attest(_makeAttestation(address(v), tpl));
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

    function _encodeTerms(FeeTerms.FeeTermsPayload memory t) internal pure returns (bytes memory) {
        bytes memory head = abi.encode(
            t.feeTermsId, t.vault, t.chainId, t.templateId,
            uint256(t.feeModel),
            t.feeRecipientAfterchain, t.feeRecipientLicensee
        );
        bytes memory tail = abi.encode(
            t.executionFeeBps, t.executionFeeFloorEurCents,
            t.afterchainMinEurCents, t.lowBalanceThresholdEurCents,
            t.fxQuoteEurValueCents, t.fxQuoteTimestamp, t.feeTermsExpiry,
            uint256(t.jurisdictionTier) // SEC-10
        );
        return bytes.concat(head, tail);
    }

    function _makeTerms(
        address vaultAddr,
        bytes32 templateId,
        uint8   model,
        uint256 walletValueEurCents
    ) internal view returns (FeeTerms.FeeTermsPayload memory t) {
        t.feeTermsId                   = keccak256(abi.encode(vaultAddr, templateId, block.timestamp));
        t.vault                        = vaultAddr;
        t.chainId                      = block.chainid;
        t.templateId                   = templateId;
        t.feeModel                     = model;
        t.feeRecipientAfterchain       = afterchainRecipient;
        t.feeRecipientLicensee         = model == FeeTerms.FEE_MODEL_LICENSED_SPLIT ? licenseeRecipient : address(0);
        t.executionFeeBps              = 200;
        t.executionFeeFloorEurCents    = EUR_250;
        t.afterchainMinEurCents        = EUR_50;
        t.lowBalanceThresholdEurCents  = EUR_250;
        t.fxQuoteEurValueCents         = walletValueEurCents;
        t.fxQuoteTimestamp             = block.timestamp;
        t.feeTermsExpiry               = block.timestamp + 1 hours;
        t.jurisdictionTier             = FeeTerms.TIER_GREEN; // SEC-10
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

    /// SEC-9: wrap a single signature in the bytes[] array shape that
    /// TransferVault.executeWithFees now requires.
    function _wrap(bytes memory sig) internal pure returns (bytes[] memory arr) {
        arr = new bytes[](1);
        arr[0] = sig;
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    /// @dev SEC-7 T4 — LICENSED_SPLIT template cannot be executed as DIRECT_PROTOCOL
    ///      even with a validly-signed DIRECT payload.
    function test_sec7_template_mode_downgrade_reverts() public {
        TransferVault v = _createVault(tplLicensed);
        vm.deal(address(v), 1 ether);
        _claimable(v, tplLicensed);

        // Oracle signs a DIRECT_PROTOCOL payload for a LICENSED_SPLIT template.
        FeeTerms.FeeTermsPayload memory t =
            _makeTerms(address(v), tplLicensed, FeeTerms.FEE_MODEL_DIRECT_PROTOCOL, 1_000_000);
        (bytes memory enc, bytes memory sig) = _signTerms(t);

        vm.expectRevert(
            abi.encodeWithSelector(
                TransferVault.FeeTermsTemplateModeMismatch.selector,
                FeeTerms.FEE_MODEL_LICENSED_SPLIT, // pinned
                FeeTerms.FEE_MODEL_DIRECT_PROTOCOL  // submitted
            )
        );
        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig));
    }

    /// @dev SEC-7 T4 — DIRECT_PROTOCOL template accepts DIRECT_PROTOCOL payload.
    function test_sec7_template_mode_matched_direct_passes() public {
        TransferVault v = _createVault(tplDirect);
        vm.deal(address(v), 1 ether);
        _claimable(v, tplDirect);

        FeeTerms.FeeTermsPayload memory t =
            _makeTerms(address(v), tplDirect, FeeTerms.FEE_MODEL_DIRECT_PROTOCOL, 1_000_000);
        (bytes memory enc, bytes memory sig) = _signTerms(t);
        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig));
        // Fee = max(2%×10000, 250) = 250 EUR → 0.025 ether
        uint256 expectedFee = (1 ether * 25_000) / 1_000_000;
        assertEq(v.pendingEthWithdrawals(afterchainRecipient), expectedFee, "afterchain 100% fee");
        assertEq(v.pendingEthWithdrawals(beneficiary),         1 ether - expectedFee);
    }

    /// @dev SEC-7 T10 — replay: executeWithFees, then calling execute() or
    ///      executeWithFees() again must fail (nullifier already spent / state).
    function test_sec7_replay_after_executeWithFees_reverts() public {
        TransferVault v = _createVault(tplDirect);
        vm.deal(address(v), 1 ether);
        _claimable(v, tplDirect);

        FeeTerms.FeeTermsPayload memory t =
            _makeTerms(address(v), tplDirect, FeeTerms.FEE_MODEL_DIRECT_PROTOCOL, 1_000_000);
        (bytes memory enc, bytes memory sig) = _signTerms(t);
        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig));

        // Attempt #1: call execute() with the same nullifier — vault state is
        // now EXECUTED so inState(CLAIMABLE) reverts before nullifier check.
        vm.expectRevert();
        v.execute(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary);

        // Attempt #2: call executeWithFees() again — same wrong-state revert.
        vm.expectRevert();
        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig));
    }

    /// @dev SEC-7 T10 — stale FX quote: a fee-terms payload whose expiry is
    ///      already in the past reverts with FeeTermsExpired.
    function test_sec7_stale_quote_reverts() public {
        TransferVault v = _createVault(tplDirect);
        vm.deal(address(v), 1 ether);
        _claimable(v, tplDirect);

        FeeTerms.FeeTermsPayload memory t =
            _makeTerms(address(v), tplDirect, FeeTerms.FEE_MODEL_DIRECT_PROTOCOL, 1_000_000);
        t.feeTermsExpiry = block.timestamp; // expired at the exact moment
        (bytes memory enc, bytes memory sig) = _signTerms(t);

        vm.expectRevert();
        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig));
    }

    /// @dev SEC-7 Amendment Task 1 — treasury fallback: when the signed
    ///      payload supplies address(0) for feeRecipientAfterchain, the vault
    ///      MUST substitute FeeTermsVerifier.PROTOCOL_TREASURY() automatically.
    function test_sec7_treasury_fallback_when_recipient_zero() public {
        _runTreasuryFallback(address(0xBEEF));
    }

    function _runTreasuryFallback(address treasury) internal {
        address[] memory sig1 = new address[](1);
        sig1[0] = oracleAddr;
        FeeTermsVerifier dedicated = new FeeTermsVerifier(
            address(this), treasury, sig1, 1
        );

        NullifierRegistry freshNull = new NullifierRegistry(address(this));
        TransferVaultFactory fresh = new TransferVaultFactory(
            address(attestVerifier),
            address(freshNull),
            address(groth16),
            address(templateReg),
            address(0),
            address(dedicated)
        );
        freshNull.setOperator(address(fresh));

        address[] memory assets = new address[](0);
        TransferVault v = TransferVault(payable(fresh.createVault(
            ITransferVaultFactory.VaultConfig({
                owner: address(0xCAFE),
                templateId: tplDirect,
                beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
                challengeWindowDuration: 1 hours,
                assets: assets
            })
        )));

        vm.deal(address(v), 1 ether);
        _claimable(v, tplDirect);

        (bytes memory enc, bytes memory sig) = _makeAndSignZeroRecipientTerms(
            address(v), dedicated.DOMAIN_SEPARATOR()
        );
        v.executeWithFees(
            fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, enc, _wrap(sig)
        );

        uint256 expectedFee = (1 ether * 25_000) / 1_000_000; // 0.025 ether
        assertEq(v.pendingEthWithdrawals(treasury),   expectedFee);
        assertEq(v.pendingEthWithdrawals(beneficiary), 1 ether - expectedFee);
    }

    function _makeAndSignZeroRecipientTerms(address vaultAddr, bytes32 domainSep)
        internal view returns (bytes memory, bytes memory)
    {
        FeeTerms.FeeTermsPayload memory t;
        t.feeTermsId                   = keccak256("tr-fallback");
        t.vault                        = vaultAddr;
        t.chainId                      = block.chainid;
        t.templateId                   = tplDirect;
        t.feeModel                     = FeeTerms.FEE_MODEL_DIRECT_PROTOCOL;
        t.feeRecipientAfterchain       = address(0);
        t.feeRecipientLicensee         = address(0);
        t.executionFeeBps              = 200;
        t.executionFeeFloorEurCents    = EUR_250;
        t.afterchainMinEurCents        = EUR_50;
        t.lowBalanceThresholdEurCents  = EUR_250;
        t.fxQuoteEurValueCents         = 1_000_000;
        t.fxQuoteTimestamp             = block.timestamp;
        t.feeTermsExpiry               = block.timestamp + 1 hours;
        t.jurisdictionTier             = FeeTerms.TIER_GREEN; // SEC-10

        bytes memory encoded = _encodeTerms(t);
        bytes32 digest = keccak256(abi.encodePacked(
            bytes2(0x1901), domainSep, FeeTerms.hashStruct(t)
        ));
        (uint8 vv, bytes32 rr, bytes32 ss) = vm.sign(oracleKey, digest);
        return (encoded, abi.encodePacked(rr, ss, vv));
    }

    /// @dev SEC-7 T10 — tampering with any bound field after signing must
    ///      fail the signature check (regression alongside the SEC-6 suite).
    function test_sec7_tampered_walletValue_reverts() public {
        TransferVault v = _createVault(tplDirect);
        vm.deal(address(v), 1 ether);
        _claimable(v, tplDirect);

        FeeTerms.FeeTermsPayload memory t =
            _makeTerms(address(v), tplDirect, FeeTerms.FEE_MODEL_DIRECT_PROTOCOL, 1_000_000);
        (, bytes memory sig) = _signTerms(t);

        // Halve the wallet value on the wire without re-signing.
        t.fxQuoteEurValueCents = 500_000;
        bytes memory badEnc = _encodeTerms(t);

        vm.expectRevert(TransferVault.FeeTermsInvalid.selector);
        v.executeWithFees(fixtureProof, _buildInputs(address(v)), fixtureNullifier, beneficiary, badEnc, _wrap(sig));
    }
}
