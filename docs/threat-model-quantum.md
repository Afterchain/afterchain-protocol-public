# Afterchain — Quantum Risk Threat Model

## Overview

This document supplements the core threat model with an assessment of cryptographic risk
under quantum computational attack. It covers the active cryptographic suite, quantum threat
timeline, attack impact analysis, and documented migration extension points.

**Non-negotiable constraints respected throughout:**
- The active Groth16-BN254 proof path is unchanged.
- The active ECDSA-secp256k1 oracle signing path is unchanged.
- No PQC algorithm is active or claims production status.
- This document is additive; the active execution path remains intact.

---

## Active Cryptographic Algorithms

| Role | Algorithm | Quantum Threat | Threat Actor | Near-Term Risk |
|------|-----------|---------------|-------------|----------------|
| Oracle attestation signing | ECDSA-secp256k1 / EIP-712 | Shor's algorithm breaks ECDLP | CRQC required | LOW (10–20+ years) |
| ZK beneficiary proof | Groth16 / BN254 pairing | Shor's algorithm breaks bilinear pairing | CRQC required | LOW (10–20+ years) |
| Beneficiary commitment | Poseidon hash (BN254-Fr) | Grover's halves bits (128→64) | Large quantum computer | VERY LOW |
| Nullifier hash | Poseidon hash (BN254-Fr) | Same as above | Same | VERY LOW |
| Evidence integrity | SHA-256 | Grover's halves preimage (256→128 bits) | Large quantum computer | VERY LOW |
| IPP integrity | SHA-256 | Same as above | Same | VERY LOW |
| Webhook signature | HMAC-SHA256 | Grover on keyed hash (O(2^128)) | Large quantum computer | VERY LOW |
| Secret encryption | AES-256-GCM | Grover halves key (256→128 bits) | Large quantum computer | VERY LOW |

---

## Threat Classification

### CRQC (Cryptographically Relevant Quantum Computer)
A fault-tolerant quantum computer capable of running Shor's algorithm at scale.
**Status:** Not yet demonstrated. Expert consensus: 10–20+ year horizon for RSA/ECC scale.

**Affected algorithms:** ECDSA-secp256k1 (oracle signing), BN254 pairing (Groth16 verifier).

**Impact if attacker has CRQC:**
- Oracle attestation forgery: adversary could forge `attest()` calls without access to oracle private key.
- ZK proof forgery: adversary could create valid Groth16 proofs without knowing beneficiary secret.

**Residual protection even under CRQC attack:**
- On-chain Merkle root check: attacker must still know `beneficiaryRoot` (committed at vault creation).
- Nullifier anti-replay: `NullifierRegistry.isSpent()` prevents double-execution regardless of ZK setup.
- Non-custodial model: no admin key controls funds; attacker must call `execute()` publicly on-chain.
- Challenge window: vault owner can call `challengeProofOfLife()` to reset during the window.

**Defense-in-depth conclusion:** A CRQC threat weakens the oracle attestation and ZK proof layers,
but does not eliminate all on-chain guards. The non-custodial, pull-based execution model provides
residual protection that does not depend on the cryptographic security of the proof system.

### NISQ / Grover's Algorithm
Near-term quantum computers can run Grover's algorithm, which halves the effective security bits
of symmetric and hash primitives.

**Affected algorithms:** Poseidon, SHA-256, HMAC-SHA256, AES-256-GCM.

**Impact:** SHA-256 preimage resistance drops from 256 to ~128 bits. AES-256 drops from 256 to ~128-bit key.

**Assessment:** 128-bit effective security is the current NIST minimum for long-term security.
Near-term risk is negligible. A straightforward upgrade (SHA-384, SHA3-256, AES-256) doubles
effective security at trivial implementation cost.

---

## Migration Extension Points (NOT ACTIVE)

### EP-1: Oracle Signature Suite (replaces ECDSA-secp256k1)

**Extension point:**
The oracle signer roster data model can be extended with a `key_algorithm`
field tagged per signer, defaulted to `secp256k1` for compatibility.

**Service layer:** The off-chain governance API already supports per-signer
metadata. The `proposeNewSigner` operation can be extended to accept a
`keyAlgorithm` parameter.

**Contract layer:** `AttestationVerifier.verifyAttestation()` calls `ecrecover()` directly.
A post-quantum upgrade requires deploying a new `AttestationVerifier` contract and re-initializing
`TransferVaultFactory` with the new address. The factory constructor accepts this as a parameter.

**Migration path:** Add `key_algorithm` to the signer roster data model → service validates against registered algorithm →
deploy new verifier contract → update factory reference (requires governance action on factory).

**Candidates:** NIST FIPS-205 ML-DSA (Dilithium), FIPS-206 SLH-DSA (Sphincs+).

**Status:** NOT_IMPLEMENTED. Documentation-only extension point.

---

### EP-2: ZK Proof System (replaces Groth16-BN254)

**Extension point:**
The `TransferVaultFactory` constructor takes `groth16Verifier_` as a parameter.
A new proof system requires: (a) new circuit, (b) new verifier contract, (c) new factory deployment.

```solidity
// TransferVaultFactory already accepts this at construction:
constructor(
    address attestationVerifier_,
    address nullifierRegistry_,
    address groth16Verifier_,     // ← swap this for new proof system verifier
    bytes32 templateId_,
    address multiSigVerifier_
)
```

A ZK proof system substitution requires a new circuit, a new verifier
contract, and a new factory deployment. The current active path is
anchored to Groth16-BN254. This extension point is documented for future
migration planning only.

**Candidates:** STARKs (transparent setup, no toxic waste), PLONK (universal SRS), Lattice-based ZK.

**Status:** NOT_IMPLEMENTED. Documentation-only extension point.

---

### EP-3: IPP Integrity Hash (replaces SHA-256)

**Extension point:** Add `hashAlgorithm` field to IPP schema alongside a `schemaVersion` bump.

```json
{
  "schemaVersion": "1.1.0-staging",
  "hashAlgorithm": "sha384",
  "integrityHash": "0x..."
}
```

**Impact:** Non-breaking schema change. Downstream verifiers check `hashAlgorithm` before validating.

**Status:** NOT_IMPLEMENTED. Documentation-only extension point.

---

## Migration Posture

| Property | Current State |
|----------|--------------|
| Migration posture | `crypto-agile-prepared` |
| Active path changed | NO — all active algorithms unchanged |
| Extension points documented | YES — EP-1 through EP-3 above |
| PQC algorithms active | NO |
| False production-safe claims | NONE |
| Patent path affected | NO |

---

## Recommendations (Not Implementation Work)

1. **Monitor NIST PQC finalization.** FIPS-205 (ML-DSA) and FIPS-206 (SLH-DSA) are finalized.
   Track vendor library availability for production-grade implementations.

2. **Schedule EP-1 for Phase 4.** Oracle signer roster already has per-signer metadata support.
   The `key_algorithm` column addition is the lowest-friction migration path.

3. **SHA-384 upgrade for IPP.** A `hashAlgorithm` field addition to the IPP schema is a
   one-sprint effort with no breaking changes. Doubles effective quantum resistance.

4. **Do not rush ZK proof system migration.** Groth16-BN254 has no near-term quantum threat.
   Any substitution has patent implications. Phase 5+ at earliest.

5. **Periodically re-evaluate CRQC timeline.** Current NIST guidance suggests 10–20 years minimum.
   Reassess at each annual planning cycle.

---

*This threat model is additive documentation. No active cryptographic path
has been modified for this analysis. The protocol's patented execution
semantics remain unchanged.*
