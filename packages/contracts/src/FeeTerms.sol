// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

/// @title FeeTerms — Afterchain execution fee commercial rules (SEC-6)
/// @notice Canonical fee-terms payload signed by the Afterchain oracle and
///         enforced by TransferVault.executeWithFees().
///
///         The structure is intentionally SELF-CONTAINED: every binding
///         (vault, chain, template, FX quote, expiry, recipients, mode,
///         basis-points, floor, afterchain minimum, low-balance threshold)
///         is part of the signed blob. An attacker who forks the open L1
///         rail can mint their own vaults and skip fees entirely, but they
///         cannot produce a signature that the official Afterchain oracle
///         would emit — meaning they cannot reuse the official attestation
///         path (oracle + death-verification pipeline) without honoring the
///         commercial terms.
///
///         Commercial rules (enforced by TransferVault):
///           LICENSED_SPLIT : total fee = max(bps%, floor in EUR),
///                            80% licensee / 20% afterchain,
///                            afterchain minimum EUR 50 unless wallet < EUR 250.
///           DIRECT_PROTOCOL: total fee = max(bps%, floor in EUR),
///                            100% afterchain, no licensee split.
///           LOW_BALANCE    : wallet < EUR 250 → zero fee, zero afterchain share.
///
///         The fee is applied pro-rata to every asset the vault holds, using
///         the signed fxQuoteEurValueCents as the denominator:
///           feeFraction       = feeEurCents / walletValueEurCents
///           feeAmountForAsset = assetBalance × feeEurCents / walletValueEurCents
///
///         Third-party verification / oracle costs are explicitly OUT OF
///         SCOPE of this fee calculation — they remain pass-through costs
///         handled by the licensee outside protocol execution.
library FeeTerms {
    // ── Fee model enum ───────────────────────────────────────────────────────
    //
    // Encoded as uint8 in the on-chain struct because Solidity ABI encoding
    // of enum across external signature boundaries is fragile.

    uint8 internal constant FEE_MODEL_LICENSED_SPLIT  = 0;
    uint8 internal constant FEE_MODEL_DIRECT_PROTOCOL = 1;
    uint8 internal constant FEE_MODEL_LOW_BALANCE     = 2;

    // ── DD Sprint C — Finding 4.1: commercial baseline (Licensing.pdf §3.4) ──
    //
    // Hard-coded floors enforced by TransferVault._validateFeeTermsParameters.
    // An oracle that signs a payload below these minima is rejected by the
    // vault before any state mutation. The licensing strategy document is the
    // single source of truth; raising the floors requires a contract upgrade.
    //
    //   MIN_EXECUTION_FEE_BPS               = 200    (2.00 %)
    //   MIN_EXECUTION_FEE_FLOOR_EUR_CENTS   = 25_000 (EUR 250.00)
    uint256 internal constant MIN_EXECUTION_FEE_BPS             = 200;
    uint256 internal constant MIN_EXECUTION_FEE_FLOOR_EUR_CENTS = 25_000;

    // ── Jurisdiction tier enum (Sprint SEC-10) ───────────────────────────────
    //
    // Mirrors services/common/licensing-config.ts JurisdictionTier. Encoded as
    // uint8 in the signed payload so the on-chain verifier can enforce binding
    // without trusting any string field. Values:
    //   0 = GREEN, 1 = AMBER, 2 = RED, 3 = JAPAN
    uint8 internal constant TIER_GREEN = 0;
    uint8 internal constant TIER_AMBER = 1;
    uint8 internal constant TIER_RED   = 2;
    uint8 internal constant TIER_JAPAN = 3;
    uint8 internal constant TIER_MAX   = 3;

    // ── Canonical payload struct ────────────────────────────────────────────

    /// @notice Signed fee-terms payload.
    /// @dev Encoded layout for off-chain signing and on-chain verification uses
    ///      abi.encode(FeeTermsPayload) — 15 × 32 bytes = 480 bytes.
    ///      Field order MUST match the type hash exactly.
    /// @dev Sprint SEC-10 — `jurisdictionTier` is now an EXPLICIT field
    ///      cryptographically bound by the oracle signature. Prior to SEC-10
    ///      the tier was only implicit through the IPP fee value.
    struct FeeTermsPayload {
        bytes32 feeTermsId;                // unique per-execution identifier
        address vault;                     // bound to this vault address
        uint256 chainId;                   // bound to this chain id
        bytes32 templateId;                // bound to vault template
        uint8   feeModel;                  // FEE_MODEL_* constant
        address feeRecipientAfterchain;    // MUST NOT be address(0) in LICENSED_SPLIT / DIRECT_PROTOCOL
        address feeRecipientLicensee;      // address(0) in DIRECT_PROTOCOL / LOW_BALANCE
        uint256 executionFeeBps;           // basis points (200 = 2.00%)
        uint256 executionFeeFloorEurCents; // minimum fee in EUR cents (25_000 = EUR 250.00)
        uint256 afterchainMinEurCents;     // afterchain floor EUR cents (5_000 = EUR 50.00)
        uint256 lowBalanceThresholdEurCents; // wallet value below which fees are waived
        uint256 fxQuoteEurValueCents;      // total wallet value (all assets) in EUR cents
        uint256 fxQuoteTimestamp;          // unix seconds
        uint256 feeTermsExpiry;            // unix seconds — payload is invalid at/after this
        uint8   jurisdictionTier;          // Sprint SEC-10: 0=GREEN 1=AMBER 2=RED 3=JAPAN
    }

    // ── EIP-712 type hashes ──────────────────────────────────────────────────

    /// @dev keccak256 of the canonical EIP-712 type string for FeeTermsPayload.
    ///      Every field in the struct above must appear here in the same order.
    bytes32 internal constant FEE_TERMS_TYPE_HASH = keccak256(
        "FeeTermsPayload("
            "bytes32 feeTermsId,"
            "address vault,"
            "uint256 chainId,"
            "bytes32 templateId,"
            "uint8 feeModel,"
            "address feeRecipientAfterchain,"
            "address feeRecipientLicensee,"
            "uint256 executionFeeBps,"
            "uint256 executionFeeFloorEurCents,"
            "uint256 afterchainMinEurCents,"
            "uint256 lowBalanceThresholdEurCents,"
            "uint256 fxQuoteEurValueCents,"
            "uint256 fxQuoteTimestamp,"
            "uint256 feeTermsExpiry,"
            "uint8 jurisdictionTier"
        ")"
    );

    // ── Pure helpers ─────────────────────────────────────────────────────────

    /// @notice Compute the canonical EIP-712 struct hash.
    /// @dev This is byte-equivalent to
    ///      keccak256(abi.encode(FEE_TERMS_TYPE_HASH, ... 14 fields)).
    ///      Implemented in inline assembly because the 15-argument
    ///      abi.encode() push/pop sequence overflows the legacy yul stack
    ///      limit when inlined into TransferVault.executeWithFees(). The
    ///      assembly allocates a 15 × 32 = 480-byte scratch buffer, copies
    ///      the 14 struct fields from the already-contiguous memory layout
    ///      of FeeTermsPayload directly after the type hash, and hashes the
    ///      whole region in one shot — yielding exactly the same digest an
    ///      EIP-712 signer computes with its reference implementation.
    function hashStruct(FeeTermsPayload memory p) internal pure returns (bytes32 h) {
        // Sprint SEC-10: 15 head-only fields. Layout = 15 × 32 = 480 bytes.
        // Output: keccak256(TYPE_HASH || 15 × 32-byte fields) = 16 × 32 = 512 bytes.
        bytes32 typeHash = FEE_TERMS_TYPE_HASH;
        assembly ("memory-safe") {
            let buf := mload(0x40)
            mstore(buf, typeHash)
            let dst := add(buf, 32)
            for { let i := 0 } lt(i, 480) { i := add(i, 32) } {
                mstore(add(dst, i), mload(add(p, i)))
            }
            h := keccak256(buf, 512)
            mstore(0x40, add(buf, 544))
        }
    }

    /// @notice Decode a tightly-encoded FeeTermsPayload from calldata.
    /// @dev The wire format is abi.encode(FeeTermsPayload) which is a sequence
    ///      of 14 × 32-byte fields in struct order. We cannot use
    ///      `abi.decode(encoded, (FeeTermsPayload))` here because the yul IR
    ///      ABI decoder for a 14-field struct pushes past the evm stack-depth
    ///      limit when inlined into TransferVault.executeWithFees(). Manual
    ///      field-by-field decoding sidesteps that entirely and also makes
    ///      the wire layout explicit for off-chain signers.
    function decode(bytes calldata encoded) internal pure returns (FeeTermsPayload memory p) {
        require(encoded.length == 15 * 32, "FeeTerms: bad length"); // SEC-10
        assembly ("memory-safe") {
            calldatacopy(p, encoded.offset, 480)
        }
    }
}
