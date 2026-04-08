// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Groth16VerifierProduction.sol";
import "../src/Groth16Verifier.sol";

/// @title SelfVerification — SEC-4 mandatory self-verification challenge.
/// @dev Test 1 (Crypto Gate) + Test 2 (Binding Lock at verifier level).
contract SelfVerificationTest is Test {
    Groth16VerifierProduction internal prod;

    // Same fixture proof used by the STAGING Groth16Verifier and by the demo's
    // staging flow (bytes32 values [1..8]). This proof has trivial structure
    // with (a=[1,2], b=[[3,4],[5,6]], c=[7,8]) and is ACCEPTED BY DESIGN by
    // the staging fixture verifier. A real BN254 pairing verifier must reject it.
    uint256 internal constant FX_A0  = 1;
    uint256 internal constant FX_A1  = 2;
    uint256 internal constant FX_B00 = 3;
    uint256 internal constant FX_B01 = 4;
    uint256 internal constant FX_B10 = 5;
    uint256 internal constant FX_B11 = 6;
    uint256 internal constant FX_C0  = 7;
    uint256 internal constant FX_C1  = 8;

    function setUp() public {
        prod = new Groth16VerifierProduction();
    }

    /// @dev Test 1 — Crypto Gate.
    ///
    /// The production verifier must REJECT the staging fixture proof. If it
    /// returns true, the contract has been swapped back to a fixture acceptor
    /// and SEC-4 has failed.
    function test_selfVerification_cryptoGate_rejectsStagingFixture() public view {
        uint256[2]    memory a = [FX_A0, FX_A1];
        uint256[2][2] memory b = [[FX_B00, FX_B01], [FX_B10, FX_B11]];
        uint256[2]    memory c = [FX_C0,  FX_C1 ];
        // Arbitrary well-formed public inputs (inside the scalar field).
        uint256[4]    memory input = [uint256(9), uint256(10), uint256(11), uint256(12)];

        bool ok = prod.verifyProof(a, b, c, input);

        // MUST be false. If this ever flips to true, the contract is not a
        // real pairing verifier and the cryptographic gate has failed.
        assertFalse(ok, "staging fixture was accepted by production verifier");

        // Also confirm the production verifier self-identifies correctly.
        assertEq(prod.VERIFIER_GRADE(), keccak256("PRODUCTION"));
        assertTrue(prod.IS_PRODUCTION_VERIFIER());
    }

    /// @dev Test 2 — Binding Lock at the vault layer.
    ///
    /// The production verifier must reject a proof whose public inputs have
    /// been mutated, even if the proof elements themselves are unchanged.
    /// This mirrors the BeneficiaryDestMismatch pathway at the cryptographic
    /// level: swapping the destination in publicInputs[3] breaks the pairing.
    ///
    /// The real proof + the correct public inputs (loaded from the snarkjs
    /// test vector embedded in Groth16VerifierProduction.t.sol) pass. Mutating
    /// publicInputs[3] — which is the "beneficiaryDest-equivalent" input in
    /// the SEC-4 production verifier's 4-input layout — must cause the
    /// pairing to fail.
    // Sprint SEC-5: regenerated from the real BeneficiaryEntitlement circuit via
    // packages/circuits/scripts/gen-test-vector.js after mpc-setup.sh.
    uint256 internal constant A_X = 16057720112079300361057091886386683663302150775256395504809396826218394137926;
    uint256 internal constant A_Y = 19779871859296154783900103124428920297950366712130759811188777512292122101766;
    uint256 internal constant B_X1 = 812323663297958548872328325126837989226143425019847035728642417418677187295;
    uint256 internal constant B_X0 = 8217486068500222541241721143817159374649444622201054525252487117043278393041;
    uint256 internal constant B_Y1 = 21669293286796568513935466960952122987866018374075497520584520300724354204733;
    uint256 internal constant B_Y0 = 6685279747673920216360439196720232929330962235660814903931879256571386774950;
    uint256 internal constant C_X = 9172729287204939335054017209933202082922600184446181780350119291063945465419;
    uint256 internal constant C_Y = 12134982273341535780629109343134087327371781305771463651423426908653063552761;
    // [merkleRoot, nullifierHash, vaultAddress_uint160, beneficiaryDest_uint160]
    uint256 internal constant PUB_0 = 17444204900052998062376695351910386082298755158547180308695296975527653160809;
    uint256 internal constant PUB_1 = 11185046449344603297183102735202405064970949800920656159166448941772465254933;
    uint256 internal constant PUB_2 = 103929005307927756724354605802047639613112342136;
    uint256 internal constant PUB_3 = 1158896792795502070752211396329834747757200325310;

    function test_selfVerification_bindingLock_rejectsMutatedDest() public view {
        uint256[2]    memory a = [A_X, A_Y];
        uint256[2][2] memory b = [[B_X1, B_X0], [B_Y1, B_Y0]];
        uint256[2]    memory c = [C_X,  C_Y];

        // Baseline: the real proof verifies.
        uint256[4] memory good = [PUB_0, PUB_1, PUB_2, PUB_3];
        assertTrue(prod.verifyProof(a, b, c, good), "baseline real proof must verify");

        // Mutated beneficiaryDest-equivalent input (publicInputs[3]).
        // A prover who did not know the real destination cannot produce a
        // valid proof for any other value — this is the cryptographic binding
        // that closes the relay-substitution attack.
        uint256[4] memory evil = [PUB_0, PUB_1, PUB_2, uint256(0xdeadbeef)];
        assertFalse(
            prod.verifyProof(a, b, c, evil),
            "mutated beneficiaryDest public input was accepted by production verifier"
        );
    }
}
