// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "./IGroth16Verifier.sol";

/// @title Groth16Verifier
/// @notice MVP staging-grade verifier: fixture proof-shape acceptor only.
///
/// @dev STAGING VERIFIER — NOT a real BN254 pairing verifier.
///
///      Design: this contract checks that the Groth16 proof COMPONENTS (a, b, c)
///      match a single deterministic fixture set compiled at deployment time. It
///      does NOT include public inputs in its acceptance hash, because the semantic
///      meaning of each public input is enforced directly and explicitly by
///      TransferVault.execute() (merkleRoot, nullifierHash, vaultAddress,
///      beneficiaryDest). Separating these concerns makes every enforcement rule
///      auditable and testable independently.
///
///      What this contract enforces:
///        ✓  Proof components (a, b, c) match the deployment fixture exactly
///        ✓  Trivially invalid proofs (a = [0, 0]) are rejected
///        ✗  Public input semantics — delegated to TransferVault.execute()
///        ✗  Real BN254 pairing arithmetic — deferred to production verifier
///
///      What TransferVault.execute() enforces (runtime, caller-independent):
///        ✓  publicInputs[0] = merkleRoot == vault.beneficiaryRoot
///        ✓  publicInputs[1] = nullifierHash, must match nullifier parameter
///        ✓  publicInputs[2] = uint256(uint160(vault_address)), vault binding
///        ✓  publicInputs[3] = uint256(uint160(beneficiaryDest)), destination binding
///
///      Production upgrade path:
///        Replace this contract with the snarkjs-generated Groth16 verifier compiled
///        from packages/circuits/beneficiary_entitlement/circuit.circom. The real
///        verifier enforces all four public inputs cryptographically via BN254 pairing,
///        and publicInputs[3] becomes Poseidon(beneficiarySecret, destinationSalt),
///        providing zero-knowledge destination binding. All on-chain semantic checks
///        in TransferVault.execute() remain in force alongside the real ZK proof.
///
///      IS_PRODUCTION_VERIFIER = false signals this programmatically.
///      DO NOT deploy this contract on any live network.
contract Groth16Verifier is IGroth16Verifier {
    /// @notice Runtime guard: always false for this staging verifier.
    ///         Set to true only by the production BN254 pairing verifier.
    bool public constant IS_PRODUCTION_VERIFIER = false;

    /// @notice Explicit verifier-grade metadata. Machine-checkable label
    ///         that deployment tooling reads to decide whether a non-demo
    ///         runtime is allowed to proceed. The bytes32 encoding is
    ///         keccak256("STAGING") so downstream contracts and tooling
    ///         can compare without string parsing.
    ///
    ///         STAGING  = fixture-proof acceptor, chain-locked to 31337
    ///         PRODUCTION = real BN254 pairing verifier from trusted setup
    bytes32 public constant VERIFIER_GRADE = keccak256("STAGING");

    /// @notice keccak256(abi.encode(a, b, c)) of the one accepted fixture proof.
    ///         Deliberately excludes public inputs: public input semantics are
    ///         enforced independently by TransferVault.execute(), not here.
    ///         Computed in Deploy.s.sol from deterministic test constants.
    bytes32 public immutable fixtureProofHash;

    /// @param fixtureProofHash_ keccak256(abi.encode(a, b, c)) of the fixture proof components.
    ///        Does NOT include public inputs. See Deploy.s.sol for computation.
    ///
    /// @dev Sprint 21 P0 — Task 4: HARD chain-id lock.
    ///      This constructor reverts on any chain other than local Anvil (chainid 31337).
    ///      The staging verifier is a fixture-proof acceptor and MUST NEVER be deployed
    ///      on a live network, testnet, or mainnet. Deploy scripts that target any
    ///      non-local chain will revert at contract creation time.
    ///
    ///      STAGING ONLY. Production deployments must use Groth16VerifierProduction.sol
    ///      (the real BN254 pairing verifier generated from the trusted setup).
    constructor(bytes32 fixtureProofHash_) {
        require(block.chainid == 31337, "STAGING VERIFIER ONLY");
        fixtureProofHash = fixtureProofHash_;
    }

    /// @inheritdoc IGroth16Verifier
    /// @dev Staging logic:
    ///      1. Reject trivially invalid proofs (a = [0, 0]).
    ///      2. Accept iff keccak256(abi.encode(a, b, c)) == fixtureProofHash.
    ///         Public inputs are NOT checked here — they are enforced by TransferVault.execute().
    ///
    ///      Why this split:
    ///        In a real Groth16 verifier, the pairing check cryptographically binds
    ///        proof components to public inputs simultaneously. The staging verifier
    ///        cannot do this, so it defers input checking to the calling contract,
    ///        making each enforcement rule explicit and independently auditable.
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[4] calldata /*publicInputs*/
    ) external view returns (bool) {
        // Reject trivially invalid proof (all-zero commitment point)
        if (a[0] == 0 && a[1] == 0) return false;
        // Accept iff proof components match the fixture
        return keccak256(abi.encode(a, b, c)) == fixtureProofHash;
    }
}
