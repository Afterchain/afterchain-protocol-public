# Afterchain Protocol — Public Security Model

| Field            | Value                                                                  |
| ---------------- | ---------------------------------------------------------------------- |
| Document version | public-shell-1.0                                                       |
| Status           | Public review edition                                                  |
| Audience         | External security reviewers                                            |
| Authority basis  | `AfterchainGovernance` — 3-of-5 on-chain multisig + 24 h on-chain timelock |
| Scope            | On-chain execution rail only; off-chain services are out of scope here |

---

## Preamble

This document is the public-facing statement of the Afterchain Protocol's
on-chain security model. It exists so that external reviewers can form an
independent opinion of the contract-enforced invariants without needing
access to the private off-chain orchestration layer.

Every claim in this document is implemented in the contract source
shipped in `packages/contracts/src/` and covered by tests in
`packages/contracts/test/`. Section numbering is preserved wherever
possible so that reviewers comparing this document against third-party
audit reports can line up section references cleanly.

---

## §1 — The Non-Custodial Invariant

### §1.1 Statement

> The Afterchain on-chain contracts **MUST NEVER** hold user funds as
> economic collateral, escrow, or any form of bond. Every authority a
> vault holds is a permission to credit beneficiary withdrawals, never a
> permission to seize, slash, or redirect funds.

### §1.2 Why no slashing bond

The challenge-window griefing vector — an adversarial vault owner
repeatedly invoking `challengeProofOfLife()` to delay execution — has a
textbook fix: require the owner to post a slashing bond and burn it on
misuse. We **explicitly reject this design**:

1. **Custody violation.** A slashing bond requires the contract to take
   custody of staked funds. Once the contract holds custody, every other
   invariant becomes harder to defend: governance could redirect the
   bond, an upgrade bug could lock it, a malicious operator could freeze
   it. Non-custody is the protocol's strongest defensive moat — we
   prefer to surrender the bond mechanism than to surrender the moat.

2. **Regulatory exposure.** A custodial bond turns the contract into a
   regulated custodian under multiple jurisdictions' custody
   legislation. The protocol is designed precisely to keep the on-chain
   contracts outside the custodial regulatory perimeter.

3. **Adversarial economic uncertainty.** A bond's deterrent value
   depends on its size being painful relative to the griefer's expected
   gain. In the inheritance context the griefer is the legitimate owner
   attempting to delay an attestation; the "gain" is qualitative
   (preserving life-status optionality), not denominated in tokens. A
   bond size that deters a griefer would also deter every legitimate
   proof-of-life reset.

### §1.3 How liveness is guaranteed instead

`TransferVault.MAX_CHALLENGES = 3` is the entire mitigation. The
relevant on-chain code (`packages/contracts/src/TransferVault.sol`):

```solidity
uint8 public constant MAX_CHALLENGES = 3;
uint8 public challengeCount;

function challengeProofOfLife() external onlyOwner inState(VaultState.ATTESTED) {
    if (block.timestamp > challengeWindowEnd) revert ChallengeWindowClosed();
    if (challengeCount >= MAX_CHALLENGES) {
        revert ChallengeCapReached(challengeCount, MAX_CHALLENGES);
    }
    unchecked { challengeCount += 1; }
    _state = VaultState.ACTIVE;
    challengeWindowEnd = 0;
    emit ProofOfLifeReceived(owner, block.timestamp);
}
```

**Liveness theorem.** Even an adversarial owner can reset the vault at
most three times before the `ATTESTED → CLAIMABLE → EXECUTED`
progression becomes irreversible. The fourth call reverts
deterministically with `ChallengeCapReached(3, 3)` and the next
`markClaimable()` after the window expires settles the vault. There is
no infinite-DoS path — the bound is mathematical, not economic — and no
funds are ever staked, escrowed, or seized.

**Regression coverage.** `test_proofOfLife_capReached_reverts` (in
`packages/contracts/test/TransferVault.t.sol`) exercises three
legitimate resets, asserts `challengeCount == 3` after each, asserts the
fourth call reverts with `ChallengeCapReached(3, 3)`, and asserts
`markClaimable()` still finishes the progression after window expiry.
Liveness is verified, not assumed.

---

## §2 — Oracle Trust Boundaries

### §2.1 What the on-chain layer enforces

`TransferVault._validateFeeTermsParameters` and `FeeTerms.sol` enforce
contract-level minimum fee parameters as hard-coded constants. If an
oracle signs a fee-terms payload whose fee parameters fall below the
hard-coded minima, the vault reverts at the contract layer **before any
state mutation** with `FeeTermsBelowMinimumBps` or
`FeeTermsBelowMinimumFloor`. The minimum is contract-enforced, not
service-enforced: an oracle compromise cannot drop the protocol fee
below the baseline committed in source.

The hard-coded minimum is the only fee-domain quantity the on-chain
contract takes responsibility for. Every other commercial parameter is
deferred to the off-chain oracle service.

### §2.2 What the on-chain layer does NOT enforce (and why)

The on-chain contract has **no native fiat oracle** and intentionally
avoids one. Adding a Chainlink-style price feed would import the feed's
full trust surface into the protocol: feed downtime, feed manipulation,
feed governance changes, and feed-side economic attacks would all
become protocol-side risks. We elected to keep the on-chain contracts
dependency-free.

The fiat valuation for each execution therefore arrives **inside the
EIP-712 fee-terms payload**, signed by the oracle multisig. The
contract commits to the integer the oracle signed and stops there.

### §2.3 The mitigations the on-chain contract DOES enforce

Even though the fiat valuation is delegated, the contract narrows the
oracle's authority along four dimensions:

1. **Cryptographic binding.** The fiat valuation is part of the EIP-712
   typed payload and therefore cannot be tampered with after the oracle
   signs. An attacker cannot drift the value between the quote and
   execution.

2. **Hard-coded minimum.** Even a fully compromised oracle cannot drop
   the execution fee below the source-committed baseline (§2.1). The
   compromise can affect the upper bound and the low-balance
   classification, but not the floor.

3. **Degenerate-state rejection.**
   `lowBalanceThresholdEurCents == 0` is rejected with
   `FeeTermsParameterOutOfRange` so a degenerate "everything is low
   balance" payload cannot be smuggled in.

4. **Non-custody.** The vault never holds custody of the fiat value —
   it acts only on the EIP-712-bound integer to compute pull-based
   withdrawal credits. There is no reservoir of fiat value at risk.

### §2.4 Multi-key oracle requirement

The oracle is not a single key. The on-chain contract layer supports a
**3-of-5 threshold** through `MultiSigAttestationVerifier` and
`FeeTermsVerifier`, both of which recover distinct signer addresses
from a set of submitted signatures and deduplicate before counting.
`TransferVault.executeWithFees()` calls
`_feeTermsVerifier.verifyDigestMultiSig(digest, signatures)` and rejects
any payload that fails to recover three independent authorised signers.

A single oracle compromise therefore cannot produce a fraudulent
valuation. The attacker must compromise three independent keys and
survive the on-chain de-duplication check inside
`verifyMultiSigForVault(bytes[])`.

All verifier roster mutations (add / remove / rotate signer) are gated
by `AfterchainGovernance`, which itself is a 3-of-5 multisig with a
24-hour on-chain timelock. There is no administrative path by which a
single operator can swap signers atomically.

---

## §3 — Jurisdiction Enforcement

### §3.1 Statement

> Every successful `executeWithFees()` execution carries a
> cryptographically-bound jurisdiction tier enum that is part of the
> EIP-712 type hash, range-checked on-chain, and emitted in an indexed
> event.

### §3.2 EIP-712 binding

`FeeTermsPayload` is a 15-field struct. The 15th field is
`uint8 jurisdictionTier`. The enum is part of the canonical EIP-712
type string:

```solidity
bytes32 internal constant FEE_TERMS_TYPE_HASH = keccak256(
    "FeeTermsPayload(bytes32 feeTermsId,address vault,uint256 chainId,bytes32 templateId,"
    "uint8 feeModel,address feeRecipientAfterchain,address feeRecipientLicensee,"
    "uint256 executionFeeBps,uint256 executionFeeFloorEurCents,uint256 afterchainMinEurCents,"
    "uint256 lowBalanceThresholdEurCents,uint256 fxQuoteEurValueCents,uint256 fxQuoteTimestamp,"
    "uint256 feeTermsExpiry,uint8 jurisdictionTier)"
);
```

An adversary cannot tamper with the tier without invalidating the
oracle multisig signature. The vault's typed-data digest binds
(`vault`, `chainId`, `templateId`, `expiresAt`, `payloadHash`,
**`jurisdictionTier`**) so the oracle commits to the tier at signing
time and the contract enforces the commitment.

### §3.3 On-chain enforcement and audit emission

`TransferVault._validateFeeTermsParameters` range-checks the tier
(`tier > TIER_MAX` reverts with `FeeTermsParameterOutOfRange`) before
any fee math runs. `executeWithFees()` then emits an indexed event:

```solidity
event JurisdictionTierAccepted(bytes32 indexed feeTermsId, uint8 tier);
```

Every successful execution leaves an immutable on-chain log of the tier
under which it ran. Off-chain indexers and regulators can subscribe to
this event for per-jurisdiction execution-volume reporting.

The mapping from end-user data (e.g. country of residence) to tier
enum is an off-chain service convention and is **out of scope for
this public document**. The on-chain layer enforces only the enum
value that the oracle multisig signed.

### §3.4 Cross-chain replay protection

The `TransferVault` contracts perform an explicit chain-id check at
every state-transitioning entry point:
`require(block.chainid == vaultChainId, "ChainMismatch")`. This
prevents signature-copying attacks where a proof from a different chain
is replayed on the production vault.

**Implementation.** Each `TransferVault` captures `block.chainid` into
an immutable `vaultChainId` field at construction time. The captured
value is then re-checked at every external entry point that mutates
state:

- `attest(bytes signedAttestation)`
- `attestMultiSig(bytes32, bytes[], uint256)`
- `attestMultiSigTyped(bytes32, uint256, bytes32, bytes[], uint256)`
- `markClaimable()`
- `execute(bytes, uint256[], bytes32, address)`
- `executeWithFees(bytes, uint256[], bytes32, address, bytes, bytes[])`

Any mismatch reverts deterministically with
`ChainMismatch(uint256 expected, uint256 actual)`. There is no path by
which a vault deployed on chain A can transition state on chain B.

**Defence in depth.** The chain-id binding is enforced at three
independent layers:

1. **`AttestationVerifier`** — `decoded.chainId != block.chainid`
   returns `(false, _)` from `verify()`.
2. **`FeeTermsVerifier`** — `terms.chainId != block.chainid` reverts
   with `FeeTermsChainMismatch` inside `executeWithFees()`.
3. **`TransferVault.vaultChainId`** — `block.chainid != vaultChainId`
   reverts with `ChainMismatch` at every entry point.

The `AttestationVerifier` and `FeeTermsVerifier` checks protect against
an adversary who tries to submit a valid signed payload from chain A on
chain B. The `vaultChainId` check protects against the more subtle
case where the entire vault state has been replayed onto a forked chain
(e.g., a chain split, a testnet replay, or a malicious RPC redirect):
even if the signed payload's `chainId` field claims the original chain,
the vault's own immutable `vaultChainId` records the chain of
*creation*, and the on-chain `block.chainid` at execution time is
checked against that. A fork replay therefore reverts even though the
payload internally still claims the original chain.

**Regression coverage.** `test_markClaimable_chainMismatch_reverts`,
`test_attestMultiSig_chainMismatch_reverts`, and
`test_vaultChainId_immutable_setAtCreation` (in
`packages/contracts/test/`) verify the binding holds at the boundary,
both for the legacy and the typed multisig paths.

---

## §4 — Operational Requirements

The L1 contracts cannot enforce every property that a production
deployment depends on. This section enumerates the operational
preconditions that the integrator is responsible for delivering. Any
production deployment that does not meet them inherits residual risks
that the on-chain layer does not — and intentionally cannot — mitigate.

### §4.1 HSM-based oracle key management

The on-chain contracts hold no private keys. The oracle signing keys
(five, sized to match the 3-of-5 threshold) are operated entirely by
the integrator. A production-grade integration must provide:

1. **Hardware-backed storage.** Each oracle key MUST be stored in a
   FIPS 140-2 Level 3 (or higher) hardware security module. Keys MUST
   NOT exist in plaintext on any disk, in any process memory dump, or
   in any backup not also encrypted by an HSM-rooted key.

2. **Independent signer custody.** No single operator may hold more
   than one oracle key. The five keys MUST be operated by five
   organisationally distinct individuals or sub-teams, with separation
   of duties enforced by the integrator's identity-and-access policy.

3. **Per-signature audit log.** Every signing operation MUST emit a
   tamper-evident audit log entry to a write-once medium. The on-chain
   protocol verifies that three distinct signers signed; the off-chain
   operator verifies that each signing operation was authorised by
   their internal controls.

4. **Compromise response runbook.** The integrator MUST maintain a
   rotation runbook capable of revoking any single oracle key via
   `AfterchainGovernance.submitAction(verifier, removeSigner.selector, signer)`
   within the 24-hour on-chain timelock window. A compromised key
   cannot be exploited if the rotation completes before the next
   attestation window.

### §4.2 Production MPC trusted-setup ceremony

The Groth16 proving system depends on a one-time multi-party
computation (MPC) ceremony that generates the proving key
(`circuit_final.zkey`) and verification key (`verification_key.json`).
The security of the proof system depends critically on at least one
ceremony contributor honestly destroying their contribution secret.

**Production deployment requires a ptau file from an industry MPC
ceremony with ≥ 5 independent contributors.** A development-grade
single-contributor ceremony is sandbox-only. The integrator is
responsible for:

1. Sourcing or coordinating an MPC ceremony with ≥ 5 independent
   contributors. Hermez Perpetual Powers of Tau (pot23+) is the
   canonical reference.
2. Validating each contributor's identity, organisational
   independence, and willingness to publicly attest to their
   contribution.
3. Publishing the ceremony transcript so any third party can verify
   the contribution chain.
4. Refusing to invoke any production deployment until the ceremony
   grade is production-grade.

Auditors should treat any production deployment whose trusted-setup
grade is not a full multi-party production ceremony as
**not in compliance with this document**.

---

## §5 — Declaration

The properties claimed in this document are:

1. **Deliberate engineering decisions**, not omissions or technical
   debt.
2. **Implemented in code** in `packages/contracts/src/` and **covered
   by automated tests** in `packages/contracts/test/`.
3. **Explicit in the trust boundary**: any future change requires an
   architecture review, a corresponding update to this document, a
   regression-test update, and an independent audit review.

In the event of conflict between this document and any source-code
comment, this document prevails.

---

## Appendix A — Regression test references

| Section | Test file | Test name | What it proves |
| ------- | --------- | --------- | -------------- |
| §1.3 | `packages/contracts/test/TransferVault.t.sol` | `test_proofOfLife_capReached_reverts` | `MAX_CHALLENGES = 3` cap; fourth call reverts; `markClaimable()` still finishes the progression |
| §2.1 | `packages/contracts/test/FeeTerms.t.sol` | `test_feeTerms_belowMinimumBps_reverts` | `executionFeeBps` below the source-committed minimum reverts with `FeeTermsBelowMinimumBps` |
| §2.1 | `packages/contracts/test/FeeTerms.t.sol` | `test_feeTerms_belowMinimumFloor_reverts` | `executionFeeFloorEurCents` below the source-committed minimum reverts with `FeeTermsBelowMinimumFloor` |
| §2.4 | `packages/contracts/test/Governance.t.sol` | `test_sec10_attestationVerifier_setThreshold_then_singleSig_blocked` | Single-sig path fails when threshold > 1 |
| §3.2 | `packages/contracts/test/FeeTerms.t.sol` | `test_feeTerms_unsetTemplateMode_reverts` | Templates without a pinned fee mode reject `executeWithFees` |
| §3.4 | `packages/contracts/test/TransferVault.t.sol` | `test_markClaimable_chainMismatch_reverts` | Cross-chain replay reverts with `ChainMismatch` at every state-transitioning entry point |
| §3.4 | `packages/contracts/test/TransferVault.t.sol` | `test_vaultChainId_immutable_setAtCreation` | `vaultChainId` immutable captured at construction equals `block.chainid` |
| §3.4 | `packages/contracts/test/MultiSigAttestation.t.sol` | `test_attestMultiSig_chainMismatch_reverts` | Multi-sig path also rejects cross-chain replay |

---

*End of document — Afterchain Protocol Public Security Model,
public-shell-1.0.*
