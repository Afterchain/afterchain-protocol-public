// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Groth16VerifierProduction.sol";

/// @title Groth16VerifierProduction.t.sol
/// @notice Sprint SEC-4 — real BN254 Groth16 pairing verification tests.
///
/// @dev The constants below are a REAL Groth16 proof + public signals
///      produced by snarkjs 0.7.6 during the SEC-4 build. The verification
///      key embedded in Groth16VerifierProduction.sol is the verification
///      key for the same trusted setup; the proof was generated from the
///      corresponding zkey. Running `snarkjs groth16 verify` against them
///      produces OK. These tests exercise the EVM ec_pairing precompile
///      (0x08) end-to-end and prove that the production verifier:
///
///        1. Accepts a cryptographically valid proof over the bound inputs.
///        2. Rejects the same proof with a mutated public input.
///        3. Rejects the same inputs with a mutated proof element.
///        4. Refuses public inputs outside the scalar field.
///
///      These tests cover the full cryptographic contract. The circuit
///      artifacts are checked in under packages/circuits/beneficiary_entitlement/build/.
contract Groth16VerifierProductionTest is Test {
    Groth16VerifierProduction internal verifier;

    // ── Real test vector (from snarkjs groth16 prove against BeneficiaryEntitlement) ──
    //
    // Sprint SEC-5: regenerated from the real Afterchain BeneficiaryEntitlement
    // circuit + MPC trusted setup (ceremony grade 'mpc-dev-ceremony').
    // Generator: packages/circuits/scripts/gen-test-vector.js — re-run after any
    // circuit or trusted-setup change.
    //
    // Public signals layout: [merkleRoot, nullifierHash, vaultAddress, beneficiaryDest]
    //
    // pi_a = (A.x, A.y) — G1 point
    uint256 internal constant A_X = 16057720112079300361057091886386683663302150775256395504809396826218394137926;
    uint256 internal constant A_Y = 19779871859296154783900103124428920297950366712130759811188777512292122101766;

    // pi_b — layout as expected by snarkjs-generated Solidity verifier calldata:
    // _pB = [[x.c1, x.c0], [y.c1, y.c0]]. Coordinates extracted directly from
    // snarkjs.exportSolidityCallData so there is no guess-work about ordering.
    uint256 internal constant B_X1 = 812323663297958548872328325126837989226143425019847035728642417418677187295;
    uint256 internal constant B_X0 = 8217486068500222541241721143817159374649444622201054525252487117043278393041;
    uint256 internal constant B_Y1 = 21669293286796568513935466960952122987866018374075497520584520300724354204733;
    uint256 internal constant B_Y0 = 6685279747673920216360439196720232929330962235660814903931879256571386774950;

    // pi_c = (C.x, C.y) — G1 point
    uint256 internal constant C_X = 9172729287204939335054017209933202082922600184446181780350119291063945465419;
    uint256 internal constant C_Y = 12134982273341535780629109343134087327371781305771463651423426908653063552761;

    // Public signals [merkleRoot, nullifierHash, vaultAddress_uint160, beneficiaryDest_uint160]
    uint256 internal constant PUB_0 = 17444204900052998062376695351910386082298755158547180308695296975527653160809;
    uint256 internal constant PUB_1 = 11185046449344603297183102735202405064970949800920656159166448941772465254933;
    uint256 internal constant PUB_2 = 103929005307927756724354605802047639613112342136;
    uint256 internal constant PUB_3 = 1158896792795502070752211396329834747757200325310;

    function setUp() public {
        verifier = new Groth16VerifierProduction();
    }

    function _buildValidProof() internal pure returns (
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[4] memory input
    ) {
        a = [A_X, A_Y];
        b = [[B_X1, B_X0], [B_Y1, B_Y0]];
        c = [C_X, C_Y];
        input = [PUB_0, PUB_1, PUB_2, PUB_3];
    }

    /// @dev Sanity: the contract identifies itself as PRODUCTION grade.
    function test_verifierGrade_isProduction() public view {
        assertEq(verifier.VERIFIER_GRADE(), keccak256("PRODUCTION"));
        assertTrue(verifier.IS_PRODUCTION_VERIFIER());
    }

    /// @dev The real proof + real public inputs verify cryptographically.
    ///      This exercises precompile 0x08 (ec_pairing) end-to-end.
    function test_verifyProof_validProof_returnsTrue() public view {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[4] memory input
        ) = _buildValidProof();
        assertTrue(verifier.verifyProof(a, b, c, input));
    }

    /// @dev Same proof with a mutated public input → pairing mismatch → false.
    function test_verifyProof_mutatedPublicInput_returnsFalse() public view {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[4] memory input
        ) = _buildValidProof();
        // was PUB_1 (real nullifierHash); replacing with an arbitrary in-field value
        input[1] = 99;
        assertFalse(verifier.verifyProof(a, b, c, input));
    }

    /// @dev Same inputs with a mutated proof element → pairing mismatch → false.
    function test_verifyProof_mutatedA_returnsFalse() public view {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[4] memory input
        ) = _buildValidProof();
        a[0] = addmod(a[0], 1, 21888242871839275222246405745257275088696311157297823662689037894645226208583);
        assertFalse(verifier.verifyProof(a, b, c, input));
    }

    /// @dev Mutated C element → pairing mismatch → false.
    function test_verifyProof_mutatedC_returnsFalse() public view {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[4] memory input
        ) = _buildValidProof();
        c[1] = addmod(c[1], 7, 21888242871839275222246405745257275088696311157297823662689037894645226208583);
        assertFalse(verifier.verifyProof(a, b, c, input));
    }

    /// @dev Public input ≥ scalar field size r → checkField revert-via-return(0).
    ///      The assembly implementation returns `false` by writing 0 and
    ///      returning early from the function body.
    function test_verifyProof_publicInputOutOfField_returnsFalse() public view {
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[4] memory input
        ) = _buildValidProof();
        // r = BN254 scalar field size
        input[0] = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        assertFalse(verifier.verifyProof(a, b, c, input));
    }

    /// @dev Zero proof elements → trivially rejected.
    function test_verifyProof_zeroProof_returnsFalse() public view {
        uint256[2] memory a   = [uint256(0), uint256(0)];
        uint256[2][2] memory b = [[uint256(0), uint256(0)], [uint256(0), uint256(0)]];
        uint256[2] memory c   = [uint256(0), uint256(0)];
        uint256[4] memory input = [uint256(0), uint256(0), uint256(0), uint256(0)];
        assertFalse(verifier.verifyProof(a, b, c, input));
    }
}
