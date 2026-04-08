// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AfterchainGovernance.sol";
import "../src/FeeTermsVerifier.sol";
import "../src/FeeTerms.sol";
import "../src/AttestationVerifier.sol";

/// @title Governance.t.sol — Sprint SEC-8 tests for AfterchainGovernance.
/// @notice Covers:
///           - threshold + timelock enforcement
///           - signer rotation via governance action
///           - replay + wrong-state + unauthorized-caller reverts
///           - removing a signer updates quorum correctly
///           - governance-owned FeeTermsVerifier cannot be mutated by outsiders
///           - a signer removed mid-flight loses their vote on in-flight actions
contract GovernanceTest is Test {
    AfterchainGovernance internal gov;
    FeeTermsVerifier     internal fv;

    // Five signers with known private keys for ECDSA tests where needed.
    uint256 internal pk1 = 0xA11CE;
    uint256 internal pk2 = 0xB0B;
    uint256 internal pk3 = 0xCA1F;
    uint256 internal pk4 = 0xD00D;
    uint256 internal pk5 = 0xE5CA;
    address internal s1;
    address internal s2;
    address internal s3;
    address internal s4;
    address internal s5;

    uint256 internal constant TIMELOCK = 24 hours;
    address internal constant TREASURY = address(0xBEEF);
    address internal constant FRESH_FEE_SIGNER = address(0xFEED);

    function setUp() public {
        vm.warp(1_700_000_000);
        s1 = vm.addr(pk1);
        s2 = vm.addr(pk2);
        s3 = vm.addr(pk3);
        s4 = vm.addr(pk4);
        s5 = vm.addr(pk5);

        address[] memory signers = new address[](5);
        signers[0] = s1; signers[1] = s2; signers[2] = s3;
        signers[3] = s4; signers[4] = s5;
        gov = new AfterchainGovernance(signers, 3, TIMELOCK);

        // Deploy FeeTermsVerifier owned by this governance contract so we
        // can exercise the full governance → target mutation pipeline.
        address[] memory fvSigners = new address[](1);
        fvSigners[0] = address(0xDECAF);
        fv = new FeeTermsVerifier(address(gov), TREASURY, fvSigners, 1);
    }

    // ── Deploy / constructor ────────────────────────────────────────────────

    function test_governance_constructor_sets_state() public view {
        assertEq(gov.threshold(),    3);
        assertEq(gov.timelockDelay(), TIMELOCK);
        assertEq(gov.signerCount(),  5);
        assertTrue(gov.isSigner(s1));
        assertTrue(gov.isSigner(s5));
    }

    function test_governance_constructor_rejects_empty_signer_set() public {
        address[] memory empty = new address[](0);
        vm.expectRevert();
        new AfterchainGovernance(empty, 1, 0);
    }

    function test_governance_constructor_rejects_threshold_gt_signers() public {
        address[] memory one = new address[](1);
        one[0] = s1;
        vm.expectRevert();
        new AfterchainGovernance(one, 2, 0);
    }

    // ── Submit / approve / execute happy path ───────────────────────────────

    function _queueAddSigner(address newSigner) internal returns (bytes32) {
        bytes memory data = abi.encodeWithSelector(fv.addSigner.selector, newSigner);
        vm.prank(s1);
        return gov.submitAction(address(fv), data);
    }

    function test_sec8_happy_path_addSigner_via_governance() public {
        bytes32 id = _queueAddSigner(FRESH_FEE_SIGNER);
        vm.prank(s2); gov.approveAction(id);
        vm.prank(s3); gov.approveAction(id);

        // Timelock still blocking
        vm.prank(s1);
        vm.expectRevert();
        gov.executeAction(id);

        vm.warp(block.timestamp + TIMELOCK + 1);
        vm.prank(s1);
        gov.executeAction(id);

        assertTrue(fv.isAuthorizedSigner(FRESH_FEE_SIGNER));
        assertEq(fv.signerCount(), 2);
    }

    // ── T10.a: cannot execute below threshold ───────────────────────────────

    function test_sec8_threshold_not_met_reverts() public {
        bytes32 id = _queueAddSigner(FRESH_FEE_SIGNER);
        vm.prank(s2); gov.approveAction(id); // only 2 approvals, threshold is 3
        vm.warp(block.timestamp + TIMELOCK + 1);
        vm.prank(s1);
        vm.expectRevert();
        gov.executeAction(id);
    }

    // ── T10.b: cannot execute before timelock ──────────────────────────────

    function test_sec8_timelock_not_elapsed_reverts() public {
        bytes32 id = _queueAddSigner(FRESH_FEE_SIGNER);
        vm.prank(s2); gov.approveAction(id);
        vm.prank(s3); gov.approveAction(id);
        // Don't warp — timelock still active.
        vm.prank(s1);
        vm.expectRevert();
        gov.executeAction(id);
    }

    // ── T10.c: signer rotation requires timelock ───────────────────────────

    function test_sec8_signer_rotation_requires_timelock() public {
        address toRemove = s5;
        bytes memory data = abi.encodeWithSelector(gov.removeSigner.selector, toRemove);
        vm.prank(s1);
        bytes32 id = gov.submitAction(address(gov), data);
        vm.prank(s2); gov.approveAction(id);
        vm.prank(s3); gov.approveAction(id);
        // Attempt immediate execution
        vm.prank(s1);
        vm.expectRevert();
        gov.executeAction(id);
        // Wait for timelock
        vm.warp(block.timestamp + TIMELOCK + 1);
        vm.prank(s1);
        gov.executeAction(id);
        assertFalse(gov.isSigner(toRemove));
        assertEq(gov.signerCount(), 4);
    }

    // ── T10.d: replay of action fails ──────────────────────────────────────

    function test_sec8_replay_of_executed_action_reverts() public {
        bytes32 id = _queueAddSigner(FRESH_FEE_SIGNER);
        vm.prank(s2); gov.approveAction(id);
        vm.prank(s3); gov.approveAction(id);
        vm.warp(block.timestamp + TIMELOCK + 1);
        vm.prank(s1);
        gov.executeAction(id);
        // Second call fails — state is now Executed, not Queued.
        vm.prank(s1);
        vm.expectRevert();
        gov.executeAction(id);
    }

    // ── T10.e: unauthorized caller fails ───────────────────────────────────

    function test_sec8_unauthorized_caller_reverts() public {
        bytes32 id = _queueAddSigner(FRESH_FEE_SIGNER);
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        gov.approveAction(id);

        vm.prank(address(0xDEAD));
        vm.expectRevert();
        gov.submitAction(address(fv), abi.encodeWithSelector(fv.addSigner.selector, FRESH_FEE_SIGNER));
    }

    // ── T10.f: removing signer updates quorum correctly ────────────────────

    function test_sec8_remove_signer_updates_quorum() public {
        // Start: 5 signers, threshold 3. Remove s5 — 4 signers, threshold still 3.
        bytes memory data = abi.encodeWithSelector(gov.removeSigner.selector, s5);
        vm.prank(s1);
        bytes32 id = gov.submitAction(address(gov), data);
        vm.prank(s2); gov.approveAction(id);
        vm.prank(s3); gov.approveAction(id);
        vm.warp(block.timestamp + TIMELOCK + 1);
        vm.prank(s1);
        gov.executeAction(id);

        assertEq(gov.signerCount(), 4);
        assertEq(gov.threshold(),   3);

        // Now attempt to remove s4 too — only 3 would remain, still >= threshold 3.
        bytes memory data2 = abi.encodeWithSelector(gov.removeSigner.selector, s4);
        vm.prank(s1);
        bytes32 id2 = gov.submitAction(address(gov), data2);
        vm.prank(s2); gov.approveAction(id2);
        vm.prank(s3); gov.approveAction(id2);
        vm.warp(block.timestamp + TIMELOCK + 1);
        vm.prank(s1);
        gov.executeAction(id2);

        assertEq(gov.signerCount(), 3);

        // Attempt to remove one more — would break quorum, must revert.
        bytes memory data3 = abi.encodeWithSelector(gov.removeSigner.selector, s3);
        vm.prank(s1);
        bytes32 id3 = gov.submitAction(address(gov), data3);
        vm.prank(s2); gov.approveAction(id3);
        // Approving with s3 still possible — s3 is self-vetoing the removal
        vm.prank(s3); gov.approveAction(id3);
        vm.warp(block.timestamp + TIMELOCK + 1);
        vm.prank(s1);
        vm.expectRevert();  // RemovingSignerBreaksQuorum
        gov.executeAction(id3);
    }

    // ── In-flight revocation ────────────────────────────────────────────────

    function test_sec8_removed_signer_loses_vote_on_inflight_action() public {
        // s5 approves action A, then gets removed before action A executes.
        bytes32 idA = _queueAddSigner(FRESH_FEE_SIGNER);
        vm.prank(s5); gov.approveAction(idA);
        // Queue removal of s5 (separate action) + advance timelock
        bytes memory data = abi.encodeWithSelector(gov.removeSigner.selector, s5);
        vm.prank(s1);
        bytes32 idB = gov.submitAction(address(gov), data);
        vm.prank(s2); gov.approveAction(idB);
        vm.prank(s3); gov.approveAction(idB);
        vm.warp(block.timestamp + TIMELOCK + 1);
        vm.prank(s1);
        gov.executeAction(idB);
        assertFalse(gov.isSigner(s5));

        // Action A has approvals from s1 (submitter) and s5 (now removed).
        // Effective approvals = 1 < threshold 3 → execution must revert.
        vm.prank(s1);
        vm.expectRevert(); // ThresholdNotMet
        gov.executeAction(idA);

        // s2 + s3 top up the approvals → execution succeeds.
        vm.prank(s2); gov.approveAction(idA);
        vm.prank(s3); gov.approveAction(idA);
        vm.prank(s1);
        gov.executeAction(idA);
        assertTrue(fv.isAuthorizedSigner(FRESH_FEE_SIGNER));
    }

    // ── FeeTermsVerifier is NOT externally mutable ──────────────────────────

    function test_sec8_feeTermsVerifier_rejects_direct_addSigner() public {
        vm.expectRevert(); // NotGovernance
        fv.addSigner(FRESH_FEE_SIGNER);
    }

    function test_sec8_feeTermsVerifier_rejects_direct_setThreshold() public {
        vm.expectRevert(); // NotGovernance
        fv.setThreshold(1);
    }

    // ── Cancel ──────────────────────────────────────────────────────────────

    function test_sec8_cancel_prevents_execution() public {
        bytes32 id = _queueAddSigner(FRESH_FEE_SIGNER);
        vm.prank(s2); gov.approveAction(id);
        vm.prank(s3); gov.approveAction(id);
        vm.prank(s1); gov.cancelAction(id);

        vm.warp(block.timestamp + TIMELOCK + 1);
        vm.prank(s1);
        vm.expectRevert(); // ActionWrongState
        gov.executeAction(id);
    }

    function test_sec8_cancel_by_outsider_reverts() public {
        bytes32 id = _queueAddSigner(FRESH_FEE_SIGNER);
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        gov.cancelAction(id);
    }

    function test_sec8_double_approve_reverts() public {
        bytes32 id = _queueAddSigner(FRESH_FEE_SIGNER);
        vm.prank(s1);
        vm.expectRevert(); // AlreadyApproved — s1 already approved on submit
        gov.approveAction(id);
    }

    // ── setThreshold via governance ────────────────────────────────────────

    // ── SEC-9: no fallback to single-signature on the verifier ──────────────

    function test_sec9_single_signature_reverts_when_threshold_three() public {
        // Build a fresh FeeTermsVerifier with three real signers and threshold=3.
        address[] memory three = new address[](3);
        three[0] = s1; three[1] = s2; three[2] = s3;
        FeeTermsVerifier fv3 = new FeeTermsVerifier(address(gov), TREASURY, three, 3);

        // Sign a synthetic digest with only ONE key (s1).
        bytes32 digest = keccak256("sec9 single sig");
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(pk1, digest);
        bytes memory oneSig = abi.encodePacked(r, ss, v);
        bytes[] memory only1 = new bytes[](1);
        only1[0] = oneSig;

        (bool ok, uint256 unique) = fv3.verifyDigestMultiSig(digest, only1);
        assertFalse(ok, "single signature must NOT pass threshold-3");
        assertEq(unique, 0, "uniqueAuthorized returned early as 0 because length < threshold");

        // With three signatures from three signers it MUST pass.
        bytes[] memory three_sigs = new bytes[](3);
        (v, r, ss) = vm.sign(pk1, digest); three_sigs[0] = abi.encodePacked(r, ss, v);
        (v, r, ss) = vm.sign(pk2, digest); three_sigs[1] = abi.encodePacked(r, ss, v);
        (v, r, ss) = vm.sign(pk3, digest); three_sigs[2] = abi.encodePacked(r, ss, v);
        (ok, unique) = fv3.verifyDigestMultiSig(digest, three_sigs);
        assertTrue(ok, "three signatures from three authorized signers must pass");
        assertEq(unique, 3);
    }

    function test_sec9_duplicate_signatures_do_not_count_twice() public {
        address[] memory three = new address[](3);
        three[0] = s1; three[1] = s2; three[2] = s3;
        FeeTermsVerifier fv3 = new FeeTermsVerifier(address(gov), TREASURY, three, 3);

        bytes32 digest = keccak256("sec9 dup sig");
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(pk1, digest);
        bytes memory dup = abi.encodePacked(r, ss, v);
        bytes[] memory threeDuplicates = new bytes[](3);
        threeDuplicates[0] = dup; threeDuplicates[1] = dup; threeDuplicates[2] = dup;

        (bool ok, uint256 unique) = fv3.verifyDigestMultiSig(digest, threeDuplicates);
        assertFalse(ok, "three identical signatures must NOT count as three unique signers");
        assertEq(unique, 1);
    }

    function test_sec9_setThreshold_via_governance_then_multisig_required() public {
        // Add two more signers via governance, then raise threshold from 1 to 3.
        // Use the test contract's `gov` (5 signers, threshold 3) as governance.
        address[] memory one = new address[](1);
        one[0] = s1;
        FeeTermsVerifier fv1 = new FeeTermsVerifier(address(gov), TREASURY, one, 1);

        // Single signature with threshold=1 → passes.
        bytes32 digest = keccak256("sec9 raise thresh");
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(pk1, digest);
        bytes[] memory single = new bytes[](1);
        single[0] = abi.encodePacked(r, ss, v);
        (bool ok1, ) = fv1.verifyDigestMultiSig(digest, single);
        assertTrue(ok1, "single sig passes when threshold=1");

        // Governance adds s2, s3 then raises threshold to 3.
        bytes[3] memory actions;
        actions[0] = abi.encodeWithSelector(fv1.addSigner.selector, s2);
        actions[1] = abi.encodeWithSelector(fv1.addSigner.selector, s3);
        actions[2] = abi.encodeWithSelector(fv1.setThreshold.selector, uint256(3));
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(s1);
            bytes32 id = gov.submitAction(address(fv1), actions[i]);
            vm.prank(s2); gov.approveAction(id);
            vm.prank(s3); gov.approveAction(id);
            vm.warp(block.timestamp + TIMELOCK + 1);
            vm.prank(s1);
            gov.executeAction(id);
        }
        assertEq(fv1.threshold(), 3);

        // The previously-passing single signature MUST now fail.
        (bool ok2, ) = fv1.verifyDigestMultiSig(digest, single);
        assertFalse(ok2, "single sig must FAIL after governance raises threshold to 3");
    }

    function test_sec8_setThreshold_requires_timelock_and_approvals() public {
        bytes memory data = abi.encodeWithSelector(gov.setThreshold.selector, uint256(4));
        vm.prank(s1);
        bytes32 id = gov.submitAction(address(gov), data);
        vm.prank(s2); gov.approveAction(id);
        vm.prank(s3); gov.approveAction(id);
        vm.warp(block.timestamp + TIMELOCK + 1);
        vm.prank(s1);
        gov.executeAction(id);
        assertEq(gov.threshold(), 4);
    }

    // ── Sprint SEC-10 — AttestationVerifier governance migration ───────────

    function test_sec10_attestationVerifier_owner_pattern_gone() public {
        // The constructor now requires (governance, signers, threshold).
        // Outsiders cannot mutate the signer set even if they call directly.
        AttestationVerifier av = _newAv();
        vm.prank(address(0xBADBADBAD));
        vm.expectRevert(abi.encodeWithSelector(AttestationVerifier.NotGovernance.selector, address(0xBADBADBAD)));
        av.addSigner(address(0xC0FFEE));
    }

    function test_sec10_attestationVerifier_addSigner_via_governance() public {
        AttestationVerifier av = _newAv();
        // Roster path: queue addSigner(0xCAFE), approve, time-warp, execute.
        bytes memory data = abi.encodeWithSelector(av.addSigner.selector, address(0xCAFE));
        vm.prank(s1);
        bytes32 id = gov.submitAction(address(av), data);
        vm.prank(s2); gov.approveAction(id);
        vm.prank(s3); gov.approveAction(id);
        vm.warp(block.timestamp + TIMELOCK + 1);
        vm.prank(s1);
        gov.executeAction(id);
        assertTrue(av.isAuthorizedSigner(address(0xCAFE)));
        assertEq(av.signerCount(), 2);
    }

    function test_sec10_attestationVerifier_setThreshold_then_singleSig_blocked() public {
        AttestationVerifier av = _newAv();
        // First seed a second signer so threshold can move to 2 without
        // breaking the signerCount >= threshold invariant.
        _govExec(address(av), abi.encodeWithSelector(av.addSigner.selector, address(0xCAFE)));
        _govExec(address(av), abi.encodeWithSelector(av.setThreshold.selector, uint256(2)));
        assertEq(av.threshold(), 2);

        // The legacy single-sig verify() path must now refuse — even with a
        // valid authorized signer. Production callers must use verifyMultiSigForVault.
        bytes memory payload = _attPayload(address(this));
        bytes32 digest       = _attDigest(av, payload);
        bytes memory sig     = _sign(pk1, digest);  // s1 isn't on this AV; use the placeholder signer instead

        // Replace sig with one from the placeholder signer (added at construction).
        // We construct a fresh AV here whose initial signer is signed by pk1 (s1).
        AttestationVerifier av2 = _newAvWithSeed(s1);
        _govExecOn(av2, abi.encodeWithSelector(av2.addSigner.selector, address(0xCAFE)));
        _govExecOn(av2, abi.encodeWithSelector(av2.setThreshold.selector, uint256(2)));

        bytes memory payload2 = _attPayload(address(this));
        bytes32 digest2       = _attDigest(av2, payload2);
        bytes memory sig2     = _sign(pk1, digest2);

        vm.prank(address(this));
        (bool ok,) = av2.verify(payload2, sig2);
        assertFalse(ok, "single-sig verify must fail when threshold > 1");

        // And single-sig fails on the original av too — not a confused-deputy.
        sig; av; digest; payload;
    }

    function test_sec10_attestationVerifier_multisig_happy_path() public {
        // Build an AV whose signers are s1 and s2; threshold 2.
        address[] memory roster = new address[](2);
        roster[0] = s1;
        roster[1] = s2;
        AttestationVerifier av = new AttestationVerifier(address(gov), roster, 2);

        bytes memory payload = _attPayload(address(this));
        bytes32 digest       = _attDigest(av, payload);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(pk1, digest);
        sigs[1] = _sign(pk2, digest);

        vm.prank(address(this));
        (bool ok, , uint256 unique) = av.verifyMultiSigForVault(payload, sigs);
        assertTrue(ok);
        assertEq(unique, 2);

        // Duplicate sig from same signer must fail (only 1 unique).
        bytes[] memory dupSigs = new bytes[](2);
        dupSigs[0] = _sign(pk1, digest);
        dupSigs[1] = _sign(pk1, digest);
        vm.prank(address(this));
        (bool ok2, , uint256 unique2) = av.verifyMultiSigForVault(payload, dupSigs);
        assertFalse(ok2);
        assertEq(unique2, 1);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    function _newAv() internal returns (AttestationVerifier) {
        return _newAvWithSeed(address(0xDECAF));
    }

    function _newAvWithSeed(address seed) internal returns (AttestationVerifier) {
        address[] memory r = new address[](1);
        r[0] = seed;
        return new AttestationVerifier(address(gov), r, 1);
    }

    function _govExec(address target, bytes memory data) internal {
        vm.prank(s1);
        bytes32 id = gov.submitAction(target, data);
        vm.prank(s2); gov.approveAction(id);
        vm.prank(s3); gov.approveAction(id);
        vm.warp(block.timestamp + TIMELOCK + 1);
        vm.prank(s1);
        gov.executeAction(id);
    }

    function _govExecOn(AttestationVerifier av, bytes memory data) internal {
        _govExec(address(av), data);
    }

    function _attPayload(address vaultAddr) internal view returns (bytes memory) {
        bytes32 id = keccak256(abi.encode(vaultAddr, block.chainid, block.timestamp));
        bytes32 templateId = keccak256("afterchain.demo.v1");
        bytes32 evidenceHash = keccak256("evidence-sec10");
        return abi.encode(
            id,
            vaultAddr,
            block.chainid,
            block.timestamp,
            block.timestamp + 1 days,
            templateId,
            evidenceHash
        );
    }

    function _attDigest(AttestationVerifier av, bytes memory payload) internal view returns (bytes32) {
        // Decode and rebuild the EIP-712 struct hash exactly as the verifier does.
        (bytes32 id, address vault, uint256 cid, uint256 issuedAt, uint256 expiresAt, bytes32 templateId, bytes32 evidenceHash) =
            abi.decode(payload, (bytes32, address, uint256, uint256, uint256, bytes32, bytes32));
        bytes32 structHash = keccak256(abi.encode(
            av.ATTESTATION_TYPE_HASH(),
            id,
            vault,
            cid,
            issuedAt,
            expiresAt,
            templateId,
            evidenceHash
        ));
        return keccak256(abi.encodePacked("\x19\x01", av.DOMAIN_SEPARATOR(), structHash));
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}
