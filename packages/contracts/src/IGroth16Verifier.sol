// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

/// @title IGroth16Verifier
/// @notice Interface for the Groth16 proof verifier used by TransferVault.
///
/// @dev Two implementations exist:
///
///      1. Groth16Verifier (staging, IS_PRODUCTION_VERIFIER = false):
///         Checks that proof components (a, b, c) match a deployment fixture.
///         Does NOT cryptographically bind public inputs; they are enforced
///         separately by TransferVault.execute().
///
///      2. Production verifier (IS_PRODUCTION_VERIFIER = true):
///         Full BN254 Groth16 pairing verifier compiled from the circuit
///         packages/circuits/beneficiary_entitlement/circuit.circom via snarkjs.
///         Cryptographically enforces all four public inputs simultaneously via the
///         BN254 pairing check. publicInputs[3] = uint160(beneficiaryDest), enforced
///         both by this verifier and independently by TransferVault.execute().
///
///      Public inputs layout (4 scalars, BN254 field elements):
///
///        [0] merkleRoot
///              On-chain: must equal vault.beneficiaryRoot (checked by TransferVault).
///              Circuit: committed at vault configuration time; the prover must know a
///              leaf and Merkle path that opens to this root.
///
///        [1] nullifierHash
///              On-chain: must equal bytes32 cast of nullifier parameter (TransferVault),
///              and must not be spent in NullifierRegistry.
///              Circuit: derived from beneficiary secret; prevents double-spend.
///
///        [2] vaultAddress
///              MVP encoding: uint256(uint160(address(vault))).
///              On-chain: checked by TransferVault — prevents proof replay across vaults.
///              Production: same encoding; the circuit enforces this value is committed
///              in the beneficiary's leaf, preventing proof portability to other vaults.
///
///        [3] beneficiaryDest (destination binding)
///              Encoding: uint256(uint160(beneficiaryDest)) — destination address as field element.
///              On-chain: checked by TransferVault.execute() (BeneficiaryDestMismatch).
///              Sprint 6 circuit: beneficiaryDest is embedded in the Merkle leaf as the third
///              Poseidon input — leaf = Poseidon(secret, entitlement, beneficiaryDest). The proof
///              proves the prover knew beneficiaryDest such that this leaf opens to beneficiaryRoot.
///              A valid proof cannot be reused with a different beneficiaryDest; substitution
///              invalidates the Groth16 pairing check.
///              Note: private secret, entitlement, Merkle path, and beneficiary identity data
///              remain hidden. The destination address is visible at execution time and in
///              the audit trail, consistent with Claim 10(d) and the replacement description.
interface IGroth16Verifier {
    /// @notice Verify a Groth16 proof.
    /// @param a            Proof element A (G1 point, 2 field elements)
    /// @param b            Proof element B (G2 point, 2×2 field elements)
    /// @param c            Proof element C (G1 point, 2 field elements)
    /// @param publicInputs The 4 public input scalars (see layout above)
    /// @return True iff the proof is valid for the given public inputs
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[4] calldata publicInputs
    ) external view returns (bool);
}
