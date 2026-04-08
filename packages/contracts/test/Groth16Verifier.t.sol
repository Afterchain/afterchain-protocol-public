// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Groth16Verifier.sol";

/// @dev Tests for the staging Groth16Verifier.
///
///      Design reminder:
///        The staging verifier checks ONLY proof components (a, b, c).
///        Public inputs are NOT part of fixtureProofHash; they are enforced
///        independently by TransferVault.execute() (merkleRoot, nullifierHash,
///        vaultAddress, beneficiaryDest). See TransferVault.t.sol for those tests.
contract Groth16VerifierTest is Test {
    // ── Fixture proof components (must match Deploy.s.sol constants) ─────────

    uint256[2] internal fixtureA = [uint256(1), uint256(2)];
    uint256[2][2] internal fixtureB = [[uint256(3), uint256(4)], [uint256(5), uint256(6)]];
    uint256[2] internal fixtureC = [uint256(7), uint256(8)];

    // Arbitrary public inputs — verifier does not check these.
    // TransferVault.execute() enforces their semantics separately.
    uint256[4] internal someInputs = [uint256(9), uint256(10), uint256(11), uint256(12)];

    Groth16Verifier internal verifier;

    function setUp() public {
        // fixtureProofHash = keccak256(abi.encode(a, b, c)) — NO public inputs
        bytes32 fh = keccak256(abi.encode(fixtureA, fixtureB, fixtureC));
        verifier = new Groth16Verifier(fh);
    }

    // ── IS_PRODUCTION_VERIFIER guard ─────────────────────────────────────────

    function test_isNotProductionVerifier() public view {
        assertFalse(verifier.IS_PRODUCTION_VERIFIER());
    }

    // ── Valid fixture proof accepts ───────────────────────────────────────────

    function test_validFixtureProof_accepts() public view {
        assertTrue(verifier.verifyProof(fixtureA, fixtureB, fixtureC, someInputs));
    }

    /// @dev Any public inputs are accepted when the proof components are correct.
    ///      Input semantics are enforced by TransferVault.execute(), not here.
    function test_validFixtureProof_anyInputsAccepted() public view {
        uint256[4] memory zeroInputs    = [uint256(0), uint256(0), uint256(0), uint256(0)];
        uint256[4] memory maxInputs     = [type(uint256).max, type(uint256).max, type(uint256).max, type(uint256).max];
        uint256[4] memory randomInputs  = [uint256(42), uint256(99999), uint256(0xDEAD), uint256(1337)];

        assertTrue(verifier.verifyProof(fixtureA, fixtureB, fixtureC, zeroInputs));
        assertTrue(verifier.verifyProof(fixtureA, fixtureB, fixtureC, maxInputs));
        assertTrue(verifier.verifyProof(fixtureA, fixtureB, fixtureC, randomInputs));
    }

    // ── Invalid proof components reject ──────────────────────────────────────

    function test_zeroProof_rejects() public view {
        uint256[2] memory zeroA = [uint256(0), uint256(0)];
        assertFalse(verifier.verifyProof(zeroA, fixtureB, fixtureC, someInputs));
    }

    function test_partiallyZeroA_rejectsViaHashCheck() public view {
        // a[0]=0 but a[1]!=0 — passes trivial-zero guard, fails hash check
        uint256[2] memory partialZeroA = [uint256(0), uint256(2)];
        assertFalse(verifier.verifyProof(partialZeroA, fixtureB, fixtureC, someInputs));
    }

    function test_wrongA_rejects() public view {
        uint256[2] memory wrongA = [uint256(99), uint256(2)];
        assertFalse(verifier.verifyProof(wrongA, fixtureB, fixtureC, someInputs));
    }

    function test_wrongB_rejects() public view {
        uint256[2][2] memory wrongB = [[uint256(999), uint256(4)], [uint256(5), uint256(6)]];
        assertFalse(verifier.verifyProof(fixtureA, wrongB, fixtureC, someInputs));
    }

    function test_wrongC_rejects() public view {
        uint256[2] memory wrongC = [uint256(7), uint256(999)];
        assertFalse(verifier.verifyProof(fixtureA, fixtureB, wrongC, someInputs));
    }

    // ── Different verifier instances are independent ──────────────────────────

    function test_differentFixtureHash_independent() public {
        uint256[2] memory altA = [uint256(100), uint256(200)];
        uint256[2][2] memory altB = [[uint256(300), uint256(400)], [uint256(500), uint256(600)]];
        uint256[2] memory altC = [uint256(700), uint256(800)];

        bytes32 altHash = keccak256(abi.encode(altA, altB, altC));
        Groth16Verifier altVerifier = new Groth16Verifier(altHash);

        // Alt verifier accepts alt fixture
        assertTrue(altVerifier.verifyProof(altA, altB, altC, someInputs));
        // Original verifier rejects alt fixture
        assertFalse(verifier.verifyProof(altA, altB, altC, someInputs));
        // Alt verifier rejects original fixture
        assertFalse(altVerifier.verifyProof(fixtureA, fixtureB, fixtureC, someInputs));
    }

    // ── fixtureProofHash field ────────────────────────────────────────────────

    function test_fixtureProofHash_matchesExpected() public view {
        bytes32 expected = keccak256(abi.encode(fixtureA, fixtureB, fixtureC));
        assertEq(verifier.fixtureProofHash(), expected);
    }
}
