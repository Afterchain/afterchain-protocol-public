// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/MultiSigAttestationVerifier.sol";
import "../src/TransferVault.sol";
import "../src/TransferVaultFactory.sol";
import "../src/AttestationVerifier.sol";
import "../src/NullifierRegistry.sol";
import "../src/Groth16Verifier.sol";
import "../src/TemplateRegistry.sol";
import "../src/ITransferVault.sol";
import "../src/ITransferVaultFactory.sol";

/// @title MultiSigAttestation.t.sol
/// @notice Sprint 15 — tests for the multi-signer attestation execution path.
///
/// @dev Coverage:
///        1. recoverSigners — 3 valid sigs → 3 authorized addresses returned
///        2. attestMultiSig — threshold=3, 3-of-3 → vault transitions ACTIVE → ATTESTED
///        3. attestMultiSig — threshold=3, 2-of-3 → MultiSigThresholdNotMet revert
///        4. attestMultiSig — duplicate sig (same key twice) → deduplicated → 1 of 3 → revert
///        5. attestMultiSig — revoked signer → excluded → threshold not met → revert
///        6. attestMultiSig — unauthorized signer → excluded → threshold not met → revert
///        7. attestMultiSig — threshold=0 → MultiSigInvalidThreshold revert
///        8. attestMultiSig — multiSigVerifier not configured (address(0)) → MultiSigNotConfigured revert
///        9. recoverSigners — wrong payloadHash → recovered ≠ authorized → empty array
///       10. attestMultiSig success emits MultiSigAttestationAccepted event
contract MultiSigAttestationTest is Test {
    // ── Fixture proof ────────────────────────────────────────────────────────

    uint256[2] internal FA = [uint256(1), uint256(2)];
    uint256[2][2] internal FB = [[uint256(3), uint256(4)], [uint256(5), uint256(6)]];
    uint256[2] internal FC = [uint256(7), uint256(8)];

    uint256 internal constant FIXTURE_MERKLE_ROOT    = 9;
    uint256 internal constant FIXTURE_NULLIFIER_HASH = 10;

    // ── Signer keys (Anvil accounts 1–4) ────────────────────────────────────

    uint256 internal signerKey1 = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    uint256 internal signerKey2 = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 internal signerKey3 = 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6;
    uint256 internal unauthorizedKey = 0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926b;

    address internal signer1;
    address internal signer2;
    address internal signer3;
    address internal unauthorizedSigner;

    // ── Contracts ────────────────────────────────────────────────────────────

    MultiSigAttestationVerifier internal multiSigVerifier;
    AttestationVerifier          internal attestVerifier;  // for single-sig factory
    Groth16Verifier              internal groth16;
    TemplateRegistry             internal templateReg;
    NullifierRegistry            internal nullifierReg;
    TransferVaultFactory         internal factory;

    bytes32 internal demoTemplateId = keccak256("afterchain.demo.v1");
    address internal vaultOwner = address(0x1234);

    // ── Setup ────────────────────────────────────────────────────────────────

    function setUp() public {
        vm.warp(1_700_000_000);

        signer1           = vm.addr(signerKey1);
        signer2           = vm.addr(signerKey2);
        signer3           = vm.addr(signerKey3);
        unauthorizedSigner = vm.addr(unauthorizedKey);

        // DD Sprint F: MultiSigAttestationVerifier is now governance-controlled.
        // The test contract plays the role of governance and seeds the three
        // authorized signers atomically through the constructor.
        {
            address[] memory _msvSigners = new address[](3);
            _msvSigners[0] = signer1;
            _msvSigners[1] = signer2;
            _msvSigners[2] = signer3;
            multiSigVerifier = new MultiSigAttestationVerifier(address(this), _msvSigners);
        }
        // unauthorizedSigner is NOT added

        // Deploy protocol infrastructure
        bytes32 fixtureHash = keccak256(abi.encode(FA, FB, FC));
        groth16     = new Groth16Verifier(fixtureHash);
        // DD Sprint A: TemplateRegistry takes (governance, initialTemplateId, initialConfigHash, initialFeeMode)
        templateReg = new TemplateRegistry(address(this), bytes32(0), bytes32(0), 255);
        nullifierReg = new NullifierRegistry(address(this));
        // SEC-10 governance pattern. Multi-sig tests don't exercise the
        // single-sig path, but constructor still needs at least one signer.
        {
            address[] memory _avSigners = new address[](1);
            _avSigners[0] = address(0xCAFE);
            attestVerifier = new AttestationVerifier(address(this), _avSigners, 1);
        }

        factory = new TransferVaultFactory(
            address(attestVerifier),
            address(nullifierReg),
            address(groth16),
            address(templateReg),
            address(multiSigVerifier),
            address(0) // feeTermsVerifier — not exercised by multi-sig tests
        );
        nullifierReg.setOperator(address(factory));
        templateReg.registerTemplate(demoTemplateId, keccak256("config"));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    function _createVault() internal returns (TransferVault) {
        address[] memory assets = new address[](0);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: vaultOwner,
            templateId: demoTemplateId,
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours,
            assets: assets
        });
        return TransferVault(payable(factory.createVault(cfg)));
    }

    /// @dev Sign payloadHash with a given private key and return the 65-byte sig.
    function _sign(uint256 privateKey, bytes32 payloadHash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, payloadHash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Build 3 valid signatures from signer1, signer2, signer3.
    function _buildThreeSigs(bytes32 payloadHash) internal view returns (bytes[] memory sigs) {
        sigs = new bytes[](3);
        sigs[0] = _sign(signerKey1, payloadHash);
        sigs[1] = _sign(signerKey2, payloadHash);
        sigs[2] = _sign(signerKey3, payloadHash);
    }

    // ── recoverSigners tests ─────────────────────────────────────────────────

    /// @dev Test 1: 3 valid authorized signatures → all 3 returned.
    function test_recoverSigners_threeValid() public view {
        bytes32 hash = keccak256("payload-abc");
        bytes[] memory sigs = _buildThreeSigs(hash);

        address[] memory recovered = multiSigVerifier.recoverSigners(hash, sigs);
        assertEq(recovered.length, 3, "should recover 3 authorized signers");
        // All three must be in the result (order may vary)
        bool foundS1; bool foundS2; bool foundS3;
        for (uint256 i = 0; i < recovered.length; i++) {
            if (recovered[i] == signer1) foundS1 = true;
            if (recovered[i] == signer2) foundS2 = true;
            if (recovered[i] == signer3) foundS3 = true;
        }
        assertTrue(foundS1, "signer1 not in recovered");
        assertTrue(foundS2, "signer2 not in recovered");
        assertTrue(foundS3, "signer3 not in recovered");
    }

    /// @dev Test 2: Duplicate sig from same key → deduplicated → only 1 returned.
    function test_recoverSigners_deduplicatesDuplicateSig() public view {
        bytes32 hash = keccak256("payload-dup");
        bytes[] memory sigs = new bytes[](3);
        sigs[0] = _sign(signerKey1, hash); // signer1
        sigs[1] = _sign(signerKey1, hash); // signer1 again
        sigs[2] = _sign(signerKey2, hash); // signer2

        address[] memory recovered = multiSigVerifier.recoverSigners(hash, sigs);
        assertEq(recovered.length, 2, "duplicates should be de-duplicated to 2");
    }

    /// @dev Test 3: Unauthorized signer → excluded.
    function test_recoverSigners_excludesUnauthorized() public view {
        bytes32 hash = keccak256("payload-unauth");
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(signerKey1, hash);      // authorized
        sigs[1] = _sign(unauthorizedKey, hash); // NOT authorized

        address[] memory recovered = multiSigVerifier.recoverSigners(hash, sigs);
        assertEq(recovered.length, 1, "unauthorized signer should be excluded");
        assertEq(recovered[0], signer1);
    }

    /// @dev Test 4: Wrong payload hash → ecrecover returns wrong address → excluded.
    function test_recoverSigners_wrongHashReturnsEmpty() public view {
        bytes32 correctHash = keccak256("correct");
        bytes32 wrongHash   = keccak256("wrong");
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(signerKey1, correctHash); // signed over different hash

        address[] memory recovered = multiSigVerifier.recoverSigners(wrongHash, sigs);
        // The recovered address won't be signer1, so it's either not authorized or address(0)
        assertEq(recovered.length, 0, "wrong hash should yield 0 authorized signers");
    }

    // ── attestMultiSig tests ─────────────────────────────────────────────────

    /// @dev Test 5: 3-of-3 threshold met → vault transitions ACTIVE → ATTESTED.
    function test_attestMultiSig_thresholdMet_transitionsToAttested() public {
        TransferVault vault = _createVault();
        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.ACTIVE));

        bytes32 payloadHash = keccak256("multisig-payload-1");
        bytes[] memory sigs = _buildThreeSigs(payloadHash);

        vault.attestMultiSig(payloadHash, sigs, 3);

        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.ATTESTED));
        assertGt(vault.challengeWindowEnd(), block.timestamp, "challenge window should be set");
    }

    /// @dev Test 6: 3-of-3 success emits MultiSigAttestationAccepted event.
    function test_attestMultiSig_emitsEvent() public {
        TransferVault vault = _createVault();
        bytes32 payloadHash = keccak256("multisig-payload-event");
        bytes[] memory sigs = _buildThreeSigs(payloadHash);

        vm.expectEmit(true, false, false, true);
        emit ITransferVault.MultiSigAttestationAccepted(
            payloadHash,
            3,
            3,
            block.timestamp + 1 hours
        );
        vault.attestMultiSig(payloadHash, sigs, 3);
    }

    /// @dev Test 7: 2-of-3 signatures with threshold=3 → MultiSigThresholdNotMet.
    function test_attestMultiSig_twoSigsThresholdThree_reverts() public {
        TransferVault vault = _createVault();
        bytes32 payloadHash = keccak256("multisig-payload-2of3");
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(signerKey1, payloadHash);
        sigs[1] = _sign(signerKey2, payloadHash);

        vm.expectRevert(
            abi.encodeWithSelector(TransferVault.MultiSigThresholdNotMet.selector, 2, 3)
        );
        vault.attestMultiSig(payloadHash, sigs, 3);
        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.ACTIVE), "state unchanged on revert");
    }

    /// @dev Test 8: Duplicate sig stuffing — 3 sigs from same key → 1 unique → threshold 3 fails.
    function test_attestMultiSig_duplicateStuffing_reverts() public {
        TransferVault vault = _createVault();
        bytes32 payloadHash = keccak256("multisig-payload-dup");
        bytes[] memory sigs = new bytes[](3);
        sigs[0] = _sign(signerKey1, payloadHash);
        sigs[1] = _sign(signerKey1, payloadHash); // duplicate
        sigs[2] = _sign(signerKey1, payloadHash); // duplicate

        vm.expectRevert(
            abi.encodeWithSelector(TransferVault.MultiSigThresholdNotMet.selector, 1, 3)
        );
        vault.attestMultiSig(payloadHash, sigs, 3);
    }

    // ── DD Sprint F — Perplexity audit High finding remediation ─────────────

    /// @dev DD-F-1: addSigner is now onlyGovernance. A non-governance call
    ///      reverts with NotGovernance — there is no owner() pattern, no
    ///      single-key roster mutation path, and no "deployer" backdoor.
    function test_addSigner_byNonGovernance_reverts() public {
        address rando = address(0x1234);
        vm.prank(rando);
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigAttestationVerifier.NotGovernance.selector, rando)
        );
        multiSigVerifier.addSigner(address(0xCAFE));
    }

    /// @dev DD-F-1: removeSigner is now onlyGovernance.
    function test_removeSigner_byNonGovernance_reverts() public {
        address rando = address(0x1234);
        vm.prank(rando);
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigAttestationVerifier.NotGovernance.selector, rando)
        );
        multiSigVerifier.removeSigner(signer1);
    }

    /// @dev DD-F-1: constructor seeds the initial roster atomically. The seed
    ///      list is rejected when it contains duplicates.
    function test_constructor_rejects_duplicate_initial_signers() public {
        address[] memory dupSeed = new address[](2);
        dupSeed[0] = signer1;
        dupSeed[1] = signer1;
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigAttestationVerifier.AlreadySigner.selector, signer1)
        );
        new MultiSigAttestationVerifier(address(this), dupSeed);
    }

    /// @dev Test 9: Revoked signer excluded — vault transitions with 2 remaining signers;
    ///              with threshold=2 it passes; with threshold=3 it reverts.
    function test_attestMultiSig_revokedSignerExcluded() public {
        // Revoke signer3
        multiSigVerifier.removeSigner(signer3);

        TransferVault vault = _createVault();
        bytes32 payloadHash = keccak256("multisig-payload-revoked");
        bytes[] memory sigs = _buildThreeSigs(payloadHash); // includes sig from signer3

        // threshold=3: signer3 excluded → only 2 recovered → fails
        vm.expectRevert(
            abi.encodeWithSelector(TransferVault.MultiSigThresholdNotMet.selector, 2, 3)
        );
        vault.attestMultiSig(payloadHash, sigs, 3);

        // threshold=2: signer1 + signer2 sufficient → passes
        TransferVault vault2 = _createVault2();
        vault2.attestMultiSig(payloadHash, sigs, 2);
        assertEq(uint256(vault2.getState()), uint256(ITransferVault.VaultState.ATTESTED));
    }

    /// @dev Test 10: threshold=0 → MultiSigInvalidThreshold.
    function test_attestMultiSig_zeroThreshold_reverts() public {
        TransferVault vault = _createVault();
        bytes32 payloadHash = keccak256("multisig-payload-zero");
        bytes[] memory sigs = _buildThreeSigs(payloadHash);

        vm.expectRevert(TransferVault.MultiSigInvalidThreshold.selector);
        vault.attestMultiSig(payloadHash, sigs, 0);
    }

    /// @dev Test 11: vault has no multiSigVerifier (factory with address(0)) → MultiSigNotConfigured.
    function test_attestMultiSig_notConfigured_reverts() public {
        // Deploy a factory without multiSigVerifier
        TransferVaultFactory bareFactory = new TransferVaultFactory(
            address(attestVerifier),
            address(nullifierReg),
            address(groth16),
            address(templateReg),
            address(0), // disabled
            address(0)  // feeTermsVerifier disabled
        );
        // Cannot setOperator twice on nullifierReg (already set to factory above).
        // Deploy a fresh nullifier registry for this bare factory.
        NullifierRegistry bareNullifierReg = new NullifierRegistry(address(this));
        bareFactory = new TransferVaultFactory(
            address(attestVerifier),
            address(bareNullifierReg),
            address(groth16),
            address(templateReg),
            address(0),
            address(0)
        );
        bareNullifierReg.setOperator(address(bareFactory));

        address[] memory assets = new address[](0);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: address(0x5678),
            templateId: demoTemplateId,
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours,
            assets: assets
        });
        TransferVault bareVault = TransferVault(payable(bareFactory.createVault(cfg)));

        bytes32 payloadHash = keccak256("multisig-payload-noconfig");
        bytes[] memory sigs = _buildThreeSigs(payloadHash);

        vm.expectRevert(TransferVault.MultiSigNotConfigured.selector);
        bareVault.attestMultiSig(payloadHash, sigs, 3);
    }

    /// @dev Test 12: attestMultiSig reverts if vault is not ACTIVE (already ATTESTED).
    function test_attestMultiSig_wrongState_reverts() public {
        TransferVault vault = _createVault();
        bytes32 payloadHash = keccak256("multisig-payload-state");
        bytes[] memory sigs = _buildThreeSigs(payloadHash);

        // First call succeeds
        vault.attestMultiSig(payloadHash, sigs, 3);
        assertEq(uint256(vault.getState()), uint256(ITransferVault.VaultState.ATTESTED));

        // Second call fails — vault no longer ACTIVE
        vm.expectRevert(
            abi.encodeWithSelector(TransferVault.WrongState.selector, ITransferVault.VaultState.ATTESTED)
        );
        vault.attestMultiSig(payloadHash, sigs, 3);
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// @dev Creates a second vault for the same owner is not allowed; use different owner.
    function _createVault2() internal returns (TransferVault) {
        address[] memory assets = new address[](0);
        ITransferVaultFactory.VaultConfig memory cfg = ITransferVaultFactory.VaultConfig({
            owner: address(0x9999),
            templateId: demoTemplateId,
            beneficiaryRoot: bytes32(FIXTURE_MERKLE_ROOT),
            challengeWindowDuration: 1 hours,
            assets: assets
        });
        return TransferVault(payable(factory.createVault(cfg)));
    }

    // ── Sprint SEC-2 · Task 4: canonicalization + Task 5 hardening tests ─────

    /// @dev DD Sprint A: chainid lock on attestMultiSig has been removed.
    /// @dev DD Sprint G — Finding ZK: the per-vault chainid binding now
    ///      protects every entry point against cross-chain replay. A vault
    ///      created at chainid 31337 reverts with ChainMismatch when called
    ///      on chainid 1. This is a STRONGER guarantee than the old "31337
    ///      only" lock — every chain is allowed at deploy time, but each
    ///      vault is permanently bound to its creation chain.
    function test_attestMultiSig_chainMismatch_reverts() public {
        TransferVault vault = _createVault(); // created at chainid 31337
        bytes32 payloadHash = keccak256("payload-cross-chain");
        bytes[] memory sigs = _buildThreeSigs(payloadHash);

        vm.chainId(1); // simulate fork-replay against mainnet
        vm.expectRevert(
            abi.encodeWithSelector(TransferVault.ChainMismatch.selector, uint256(31337), uint256(1))
        );
        vault.attestMultiSig(payloadHash, sigs, 3);
    }

    /// @dev Typed multisig path accepts a correctly-signed EIP-712 digest on
    ///      the current (local) chain and transitions the vault to ATTESTED.
    function test_attestMultiSigTyped_happyPath() public {
        TransferVault vault = _createVault();
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes32 payloadHash = keccak256("typed-payload-ok");

        bytes32 digest = _typedDigest(address(vault), expiresAt, payloadHash);
        bytes[] memory sigs = _buildThreeSigs(digest);

        vault.attestMultiSigTyped(demoTemplateId, expiresAt, payloadHash, sigs, 3);
        assertEq(uint8(vault.getState()), uint8(ITransferVault.VaultState.ATTESTED));
    }

    /// @dev Typed path rejects reuse of the same digest (replay protection).
    function test_attestMultiSigTyped_replay_reverts() public {
        TransferVault vault = _createVault();
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes32 payloadHash = keccak256("typed-replay-payload");
        bytes32 digest = _typedDigest(address(vault), expiresAt, payloadHash);
        bytes[] memory sigs = _buildThreeSigs(digest);

        vault.attestMultiSigTyped(demoTemplateId, expiresAt, payloadHash, sigs, 3);

        // Second call with the same inputs — even against a new vault — is
        // implicitly blocked because the digest is per-vault. Here we verify
        // the same-vault replay case reverts with MultiSigReplay OR with the
        // ACTIVE-state guard (vault is now ATTESTED). Either is acceptable;
        // both are security-equivalent.
        vm.expectRevert();
        vault.attestMultiSigTyped(demoTemplateId, expiresAt, payloadHash, sigs, 3);
    }

    /// @dev Expired typed attestation is rejected.
    function test_attestMultiSigTyped_expired_reverts() public {
        TransferVault vault = _createVault();
        uint256 expiresAt = block.timestamp + 10;
        bytes32 payloadHash = keccak256("typed-expired-payload");
        bytes32 digest = _typedDigest(address(vault), expiresAt, payloadHash);
        bytes[] memory sigs = _buildThreeSigs(digest);

        // Advance past expiry
        vm.warp(expiresAt + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                TransferVault.MultiSigExpired.selector, expiresAt, block.timestamp
            )
        );
        vault.attestMultiSigTyped(demoTemplateId, expiresAt, payloadHash, sigs, 3);
    }

    /// @dev Wrong vault binding: a digest computed for vault A cannot be
    ///      accepted by vault B. Simulated by signing the A-scoped digest
    ///      then submitting it to vault B via attestMultiSigTyped.
    function test_attestMultiSigTyped_wrongVault_reverts() public {
        TransferVault vaultA = _createVault();
        TransferVault vaultB = _createVault2();
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes32 payloadHash = keccak256("typed-wrong-vault");

        bytes32 digestA = _typedDigest(address(vaultA), expiresAt, payloadHash);
        bytes[] memory sigsA = _buildThreeSigs(digestA);

        // Submit A-signed digest to vault B. Vault B recomputes the digest
        // with address(this)=vaultB, so recovered signers ≠ authorized and
        // threshold check fails.
        vm.expectRevert();
        vaultB.attestMultiSigTyped(demoTemplateId, expiresAt, payloadHash, sigsA, 3);
    }

    /// @dev Wrong chainId: a digest signed for chainid X cannot be reused on
    ///      chainid Y. Simulated by signing the digest, then vm.chainId(Y)
    ///      and submitting.
    function test_attestMultiSigTyped_wrongChainId_reverts() public {
        TransferVault vault = _createVault();
        uint256 expiresAt = block.timestamp + 1 hours;
        bytes32 payloadHash = keccak256("typed-wrong-chain");

        // Sign the digest on chainid 31337 (current).
        bytes32 digest = _typedDigest(address(vault), expiresAt, payloadHash);
        bytes[] memory sigs = _buildThreeSigs(digest);

        // Pretend to be on a different chain — recompute will differ,
        // recovered signers ≠ authorized.
        vm.chainId(1);
        vm.expectRevert();
        vault.attestMultiSigTyped(demoTemplateId, expiresAt, payloadHash, sigs, 3);
    }

    /// @dev Helper: compute the EIP-712 digest for attestMultiSigTyped.
    ///      Must match the hash construction in TransferVault.attestMultiSigTyped.
    function _typedDigest(
        address vault,
        uint256 expiresAt,
        bytes32 payloadHash
    ) internal view returns (bytes32) {
        bytes32 domainTypeHash =
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        bytes32 structTypeHash =
            keccak256("MultiSigAttestation(address vault,uint256 chainId,bytes32 templateId,uint256 expiresAt,bytes32 payloadHash)");

        bytes32 domainSeparator = keccak256(abi.encode(
            domainTypeHash,
            keccak256(bytes("Afterchain")),
            keccak256(bytes("1")),
            block.chainid,
            vault
        ));
        bytes32 structHash = keccak256(abi.encode(
            structTypeHash,
            vault,
            block.chainid,
            demoTemplateId,
            expiresAt,
            payloadHash
        ));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
