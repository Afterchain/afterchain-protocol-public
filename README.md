# Afterchain Protocol — Public Shell

**Public review edition.** This repository contains the on-chain
execution rail of the Afterchain Protocol and the cryptographic
tests that cover it. The off-chain orchestration layer (oracle
attestation service, evidence package assembly, operator console,
deployment infrastructure) is **intentionally not included**.

This repository is not sufficient to run a production deployment of Afterchain.

---

## What Afterchain is

Afterchain is a deterministic, non-custodial, privacy-preserving
post-mortem digital asset execution protocol. A `TransferVault`
configured by an asset owner transitions through a strict on-chain
state machine — `ACTIVE → ATTESTED → CLAIMABLE → EXECUTED` —
gated by cryptographic attestations, a proof-of-life challenge
window, an EIP-712 fee-terms commitment, a Groth16 beneficiary
proof, and a spent-nullifier registry. At no point does any
contract hold custody of user funds as collateral, bond, or
escrow. Execution is deterministic and single-use.

Read `docs/PUBLIC_SECURITY_MODEL.md` for the canonical public
statement of the on-chain security model, including the
non-custodial invariant, oracle trust boundaries, jurisdiction
binding, cross-chain replay protection, and integrator operational
requirements.

## What's in this repository

```
packages/contracts/
  src/         — Solidity source (20 files)
  test/        — Foundry regression tests (10 files)
  foundry.toml — Foundry project config
  remappings.txt

docs/
  PUBLIC_SECURITY_MODEL.md   — public security model
  MPC_SETUP.md               — Groth16 trusted-setup ceremony guidance
  threat-model-quantum.md    — quantum-risk analysis

services/mock-verifier/
  index.ts                   — non-functional mock stub
  MOCK_DISCLOSURE.md         — explicit non-production disclosure

.env.example                 — minimal environment template
LICENSE.md                   — Business Source License 1.1
```

**Not included** in this public shell:
- the production verifier API service
- the oracle signing service
- the evidence package assembly pipeline
- the operator console UI
- deployment infrastructure (Docker, Postgres, Redis, dev orchestration)
- ceremony transcripts, proving keys, and witness generators
- any commercial licensing material

## Prerequisites

- Foundry — `curl -L https://foundry.paradigm.xyz | bash && foundryup`
- Node.js ≥ 20 (only if you want to interact with the mock verifier stub)
- pnpm ≥ 9 (only for workspace scripts)

## Running the on-chain regression tests

```bash
# Install forge-std as a git submodule (one-time)
cd packages/contracts
forge install foundry-rs/forge-std

# Run the full test suite
forge test -vvv
```

The test suite exercises the state machine, attestation verifier,
nullifier registry, fee-terms verifier, multi-sig attestation path,
governance timelock, cross-chain replay protection, and jurisdiction
binding.

All tests use Foundry's standard Anvil default development keys
(public, documented in the Foundry documentation). These are not
secrets.

## Licensing

This public shell is distributed under the Business Source License
1.1 (see `LICENSE.md`). Non-commercial review, academic research,
and security audits are permitted without a separate commercial
agreement. Production use that generates execution revenue or
third-party integration requires a commercial agreement with the
licensor.

## Scope boundary

This repository exists so that external security reviewers can form
an independent opinion of Afterchain's on-chain security model
without access to the private off-chain orchestration layer. It is
not a tutorial, not a product, and not an integration guide. The
full protocol architecture, commercial terms, and integrator
responsibilities are documented separately and are not in scope for
this public shell.
