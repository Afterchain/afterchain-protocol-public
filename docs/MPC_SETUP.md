# MPC Trusted Setup — Afterchain ZK Circuit

## Production requirement

> **Production deployment requires a ptau file from an industry MPC ceremony with >= 5 independent contributors.**
> The development-grade single-contributor ceremony shipped by the circuit build tooling is sandbox-only.
> Operators must source a multi-party ceremony transcript (e.g., Hermez Perpetual Powers of Tau, pot23+)
> for any non-sandbox deployment. The on-chain `Groth16VerifierProduction.IS_PRODUCTION_VERIFIER()`
> flag distinguishes production-grade artifacts from sandbox artifacts.

## Overview

The Afterchain protocol uses a Groth16 BN254 zero-knowledge proof to verify beneficiary entitlement at execution time. The security of this proof system depends critically on the trusted setup ceremony:

- **What it is:** A one-time multi-party computation (MPC) ceremony that generates the proving key (`circuit_final.zkey`) and verification key (`verification_key.json`).
- **Why it matters:** The party who knows the "toxic waste" (random values from the ceremony) can produce valid proofs for ANY statement — not just honest ones. The ceremony must be structured so that no single party (including the ceremony coordinator) can reconstruct the toxic waste.
- **Guarantee:** With N contributors, the setup is secure as long as at least 1 contributor destroys their contribution secret. With Hermez Perpetual Powers of Tau (thousands of contributors), this is as close to trustless as cryptographically achievable.

## Ceremony Grades

| Grade | Description |
|-------|-------------|
| `mpc-dev-ceremony` | `mpc-setup.sh` was run — single contributor, proper MPC ceremony structure |
| `dev-single-contributor` | `build.sh` was run — direct groth16 setup, no ceremony |
| `none` | No artifacts — sandbox/staging mode |

---

## Sandbox: Dev Ceremony

For sandbox and demo purposes, the reference circuit tooling lives in the
full protocol repository (not included in this public shell). The sandbox
ceremony script invokes `snarkjs powersoftau new`, a phase 1 contribution,
a DRAND-equivalent beacon, and a phase 2 contribution, then exports
`circuit_final.zkey` and `verification_key.json`.

This:
1. Generates a fresh powers-of-tau (pot12, up to 4096 constraints)
2. Runs phase 1 with a single contributor (entropy: time-based + PRNG)
3. Applies a DRAND-equivalent beacon for final randomness
4. Runs phase 2 (circuit-specific) with snarkjs contribution + beacon
5. Exports `circuit_final.zkey` and `verification_key.json`
6. Writes `ceremony_transcript.json` (human-readable ceremony record)

After running, the generated `ceremony_transcript.json` records the grade
as `mpc-dev-ceremony` and the deployed `Groth16VerifierProduction.sol` is
usable for sandbox proofs only.

**Security disclosure:** This is still a single-contributor ceremony. It is NOT production-grade. Use for sandbox/demo only.

---

## Production: Multi-Party Ceremony

For a real production deployment, follow these steps:

### Phase 1: Hermez Perpetual Powers of Tau

The Hermez Perpetual Powers of Tau is a pre-existing, publicly audited phase 1 with thousands of contributors. Use it instead of generating your own.

```bash
# Download pot23 (supports up to 2^23 ≈ 8M constraints)
curl -O https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_23.ptau

# Verify the download (compare with known hash from Hermez repo)
snarkjs powersoftau verify powersOfTau28_hez_final_23.ptau
```

For the Afterchain circuit (< 4096 constraints), pot12 is sufficient. However, using a larger ptau is always safe and increases confidence in the phase 1 security.

Known ptau file hashes (from Hermez GitHub):
- pot12: `1c6502ce2592ae56a00e6f7e7f24dabc34d0d1b47b7a4539d9fcee00c5a4fa4` (SHA-256)

Always verify before use: `sha256sum powersOfTau28_hez_final_12.ptau`

### Phase 2: Circuit-Specific Multi-Party Ceremony

Each contributor must:
1. Be a separate, independent party (different organizations preferred)
2. Run the contribution on an air-gapped machine
3. Destroy the machine or prove entropy destruction after contribution
4. Publish their contribution attestation (name + contribution hash) publicly

```bash
# Coordinator: initialize phase 2 from ptau + r1cs
snarkjs zkey new circuit.r1cs powersOfTau28_hez_final_12.ptau circuit_0.zkey

# Contributor 1
snarkjs zkey contribute circuit_0.zkey circuit_1.zkey \
  --name="Contributor 1 — Organization A" -e="<fresh random entropy>"

# Contributor 2  
snarkjs zkey contribute circuit_1.zkey circuit_2.zkey \
  --name="Contributor 2 — Organization B" -e="<fresh random entropy>"

# ... repeat for each contributor ...

# Finalize with beacon (DRAND or ETH block hash)
DRAND_RANDOMNESS=$(curl -s https://drand.cloudflare.com/public/1000000 | jq -r '.randomness')
snarkjs zkey beacon circuit_N.zkey circuit_final.zkey \
  "$DRAND_RANDOMNESS" 10 -n="DRAND beacon round 1000000"

# Export verification key
snarkjs zkey export verificationkey circuit_final.zkey verification_key.json

# Export Solidity verifier (for Groth16VerifierProduction.sol)
snarkjs zkey export solidityverifier circuit_final.zkey Groth16VerifierProduction.sol
```

### Transcript

Each contributor publishes:
- Their name / organization
- The SHA-256 hash of their input zkey
- The SHA-256 hash of their output zkey
- A signed statement of contribution and entropy destruction

The coordinator assembles these into a public `ceremony_transcript.json` and publishes it alongside the final zkey and verification key for independent audit.

### Verification

Anyone can verify the ceremony:
```bash
snarkjs zkey verify circuit.r1cs powersOfTau28_hez_final_12.ptau circuit_final.zkey
# → [INFO] ZKey Ok!
```

---

## Verification Key Audit

The `verification_key.json` contains the elliptic curve points that define the on-chain verification. These are embedded in `Groth16VerifierProduction.sol`. After ceremony completion:

1. Verify `snarkjs zkey verify` passes
2. Extract the alpha/beta/gamma/delta points from `verification_key.json`
3. Compare against the constants in `Groth16VerifierProduction.sol`
4. Deploy `Groth16VerifierProduction.sol` using your deployment tooling of choice
5. Verify `IS_PRODUCTION_VERIFIER()` returns `true` on-chain

---

## Why This Matters

The Afterchain protocol's ZK execution path provides these guarantees when the trusted setup is correct:

1. **Soundness:** Only a party who knows the beneficiary secret (Poseidon preimage) can produce a valid proof. A malicious party cannot forge entitlement.

2. **Zero-knowledge:** The proof reveals nothing about the beneficiary identity, secret, or entitlement value beyond what the public inputs already reveal (vault address, destination address, Merkle root, nullifier hash).

3. **Binding:** The nullifier prevents double-claiming. The vault address prevents cross-vault replay. The destination prevents destination substitution.

If the trusted setup is compromised (toxic waste known), guarantee #1 breaks — a malicious prover can execute vaults they don't own. Guarantees #2 and #3 (and all on-chain enforcement in TransferVault) remain intact regardless of ZK setup quality.

---

## Summary: Sandbox vs Production

| Property | Sandbox (mpc-setup.sh) | Production |
|----------|------------------------|------------|
| Phase 1 source | Locally generated | Hermez Perpetual PoT |
| Phase 1 verifiability | No (local generation) | Yes (thousands of contributors) |
| Phase 2 contributors | 1 (coordinator) | ≥5 independent parties |
| Entropy source | time-based PRNG | Cryptographically fresh, air-gapped |
| Beacon | Local hash | DRAND public randomness |
| Transcript | ceremony_transcript.json | Publicly published + signed |
| `trustedSetupGrade` | `mpc-dev-ceremony` | `mpc-production` (future) |
| Suitable for | sandbox/demo | production asset execution |
