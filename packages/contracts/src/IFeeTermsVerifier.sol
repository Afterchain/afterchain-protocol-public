// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

/// @title IFeeTermsVerifier — signed fee-terms verification interface (SEC-6).
/// @notice Called by TransferVault.executeWithFees() to validate that the
///         EIP-712 digest of a FeeTermsPayload was signed by an authorized
///         Afterchain oracle.
///
/// @dev The interface is digest-based (not struct-based) to avoid passing a
///      14-field memory struct across the external call boundary. That keeps
///      the yul IR stack within limits when this is inlined into
///      TransferVault.executeWithFees(). TransferVault computes the struct
///      hash locally via FeeTerms.hashStruct(), wraps it with the verifier's
///      DOMAIN_SEPARATOR, and asks this contract to recover and authorize
///      the signer.
interface IFeeTermsVerifier {
    /// @notice Recover the signer of a signed EIP-712 digest and report
    ///         whether they are on the authorized fee-terms roster.
    /// @param digest    The full EIP-712 digest: keccak256(0x19 || 0x01 ||
    ///                  DOMAIN_SEPARATOR || structHash).
    /// @param signature 65-byte r,s,v secp256k1 signature.
    /// @return valid    true iff ecrecover yields a roster member and the
    ///                  signature is non-malleable (EIP-2).
    /// @return signer   The recovered address (or address(0) on failure).
    function verifyDigest(
        bytes32 digest,
        bytes calldata signature
    ) external view returns (bool valid, address signer);

    /// @notice Sprint SEC-9 — verify a threshold of unique authorized
    ///         signatures over the same EIP-712 digest.
    /// @return valid             true iff uniqueAuthorized >= threshold
    /// @return uniqueAuthorized  number of unique authorized signers recovered
    function verifyDigestMultiSig(
        bytes32 digest,
        bytes[] calldata signatures
    ) external view returns (bool valid, uint256 uniqueAuthorized);

    /// @notice Sprint SEC-9 — current threshold required by verifyDigestMultiSig.
    function threshold() external view returns (uint256);

    /// @notice Whether `signer` is currently on the authorized fee-terms roster.
    function isAuthorizedSigner(address signer) external view returns (bool);

    /// @notice The EIP-712 domain separator used to sign fee-terms payloads.
    function DOMAIN_SEPARATOR() external view returns (bytes32);

    /// @notice Immutable protocol treasury address set at verifier deployment.
    ///         Used as a fallback when a signed fee-terms payload supplies
    ///         address(0) for the afterchain recipient.
    function PROTOCOL_TREASURY() external view returns (address);
}
