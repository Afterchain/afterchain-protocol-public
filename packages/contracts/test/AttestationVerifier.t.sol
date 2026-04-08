// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/AttestationVerifier.sol";
import "../src/IAttestationVerifier.sol";

contract AttestationVerifierTest is Test {
    AttestationVerifier internal verifier;
    address internal owner = address(this);

    // Oracle keypair (Anvil account 1)
    uint256 internal oracleKey = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    address internal oracleAddr;

    address internal vaultAddr = address(0xBEEF0001);
    address internal wrongVault = address(0xBEEF0002);

    uint256 internal chainId;
    bytes32 internal demoTemplateId = keccak256("afterchain.demo.v1");

    function setUp() public {
        // Warp to a realistic timestamp so relative arithmetic doesn't underflow
        vm.warp(1_700_000_000);
        oracleAddr = vm.addr(oracleKey);
        // Sprint SEC-10 — governance pattern. Test contract IS the governance.
        // Threshold = 1 keeps the legacy single-sig path active (sandbox).
        address[] memory signers = new address[](1);
        signers[0] = oracleAddr;
        verifier = new AttestationVerifier(owner, signers, 1);
        chainId = block.chainid;
    }

    // ── verify() — vault-only on-chain path ─────────────────────────────────

    function test_verify_validAttestation() public {
        (bytes memory payload, bytes memory sig) = _makeAndSplit(
            oracleKey, vaultAddr, chainId, block.timestamp, block.timestamp + 1 days
        );
        vm.prank(vaultAddr);
        (bool valid, IAttestationVerifier.DecodedAttestation memory decoded) =
            verifier.verify(payload, sig);
        assertTrue(valid);
        assertEq(decoded.vault, vaultAddr);
        assertEq(decoded.chainId, chainId);
        assertEq(decoded.signer, oracleAddr);
    }

    function test_verify_wrongSigner_returnsFalse() public {
        // Anvil account 0 — not in the authorized signer list
        uint256 wrongKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        (bytes memory payload, bytes memory sig) = _makeAndSplit(
            wrongKey, vaultAddr, chainId, block.timestamp, block.timestamp + 1 days
        );
        vm.prank(vaultAddr);
        (bool valid,) = verifier.verify(payload, sig);
        assertFalse(valid);
    }

    function test_verify_expiredAttestation_returnsFalse() public {
        (bytes memory payload, bytes memory sig) = _makeAndSplit(
            oracleKey, vaultAddr, chainId, block.timestamp - 100, block.timestamp - 1
        );
        vm.prank(vaultAddr);
        (bool valid,) = verifier.verify(payload, sig);
        assertFalse(valid);
    }

    function test_verify_wrongChain_returnsFalse() public {
        (bytes memory payload, bytes memory sig) = _makeAndSplit(
            oracleKey, vaultAddr, 1 /* mainnet */, block.timestamp, block.timestamp + 1 days
        );
        vm.prank(vaultAddr);
        (bool valid,) = verifier.verify(payload, sig);
        assertFalse(valid);
    }

    function test_verify_wrongVault_returnsFalse() public {
        // Attestation issued for vaultAddr, but called by wrongVault
        (bytes memory payload, bytes memory sig) = _makeAndSplit(
            oracleKey, vaultAddr, chainId, block.timestamp, block.timestamp + 1 days
        );
        vm.prank(wrongVault); // msg.sender != vaultAddr
        (bool valid,) = verifier.verify(payload, sig);
        assertFalse(valid);
    }

    function test_verify_calledDirectly_returnsFalse() public {
        // address(this) != vaultAddr
        (bytes memory payload, bytes memory sig) = _makeAndSplit(
            oracleKey, vaultAddr, chainId, block.timestamp, block.timestamp + 1 days
        );
        // no prank — msg.sender is the test contract
        (bool valid,) = verifier.verify(payload, sig);
        assertFalse(valid);
    }

    // ── decodeAttestation() — inspection path ────────────────────────────────

    function test_decodeAttestation_validSig() public {
        (bytes memory payload, bytes memory sig) = _makeAndSplit(
            oracleKey, vaultAddr, chainId, block.timestamp, block.timestamp + 1 days
        );
        IAttestationVerifier.AttestationInspection memory inspection =
            verifier.decodeAttestation(payload, sig);
        assertTrue(inspection.sigValid);
        assertFalse(inspection.expired);
        assertTrue(inspection.chainMatch);
        assertEq(inspection.decoded.vault, vaultAddr);
        assertEq(inspection.decoded.signer, oracleAddr);
    }

    function test_decodeAttestation_expiredSig() public {
        (bytes memory payload, bytes memory sig) = _makeAndSplit(
            oracleKey, vaultAddr, chainId, block.timestamp - 100, block.timestamp - 1
        );
        IAttestationVerifier.AttestationInspection memory inspection =
            verifier.decodeAttestation(payload, sig);
        assertTrue(inspection.sigValid);
        assertTrue(inspection.expired);
        assertTrue(inspection.chainMatch);
    }

    function test_decodeAttestation_wrongChain() public {
        (bytes memory payload, bytes memory sig) = _makeAndSplit(
            oracleKey, vaultAddr, 1, block.timestamp, block.timestamp + 1 days
        );
        IAttestationVerifier.AttestationInspection memory inspection =
            verifier.decodeAttestation(payload, sig);
        assertFalse(inspection.chainMatch);
    }

    function test_decodeAttestation_noVaultBindingCheck() public {
        // Inspection path does NOT check vault binding — any caller can get decoded data
        (bytes memory payload, bytes memory sig) = _makeAndSplit(
            oracleKey, vaultAddr, chainId, block.timestamp, block.timestamp + 1 days
        );
        // Called from address(this), not vaultAddr — still returns sigValid=true
        IAttestationVerifier.AttestationInspection memory inspection =
            verifier.decodeAttestation(payload, sig);
        assertTrue(inspection.sigValid);
        assertEq(inspection.decoded.vault, vaultAddr);
    }

    // ── Signer management ────────────────────────────────────────────────────

    function test_addSigner_nonGovernance_reverts() public {
        address rando = address(0x1234);
        vm.prank(rando);
        vm.expectRevert(abi.encodeWithSelector(AttestationVerifier.NotGovernance.selector, rando));
        verifier.addSigner(address(0xABCD));
    }

    function test_removeSigner_revokesAuthorization() public {
        // SEC-10: removeSigner would break quorum (signerCount-1 < threshold)
        // unless another signer exists. Add a placeholder so the removal is
        // permitted by the new governance invariant.
        verifier.addSigner(address(0xCAFE));
        verifier.removeSigner(oracleAddr);
        assertFalse(verifier.isAuthorizedSigner(oracleAddr));

        (bytes memory payload, bytes memory sig) = _makeAndSplit(
            oracleKey, vaultAddr, chainId, block.timestamp, block.timestamp + 1 days
        );
        vm.prank(vaultAddr);
        (bool valid,) = verifier.verify(payload, sig);
        assertFalse(valid);
    }

    function test_addSigner_zeroAddress_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(AttestationVerifier.ZeroAddress.selector));
        verifier.addSigner(address(0));
    }

    function test_isAuthorizedSigner_returnsCorrectly() public view {
        assertTrue(verifier.isAuthorizedSigner(oracleAddr));
        assertFalse(verifier.isAuthorizedSigner(address(0xDEAD)));
    }

    // ── ECDSA hardening ──────────────────────────────────────────────────────

    function test_verify_invalidV_returnsFalse() public {
        (bytes memory payload, bytes memory sig) = _makeAndSplit(
            oracleKey, vaultAddr, chainId, block.timestamp, block.timestamp + 1 days
        );
        // Replace v byte with an invalid value (29 is not 27 or 28)
        sig[64] = bytes1(uint8(29));
        vm.prank(vaultAddr);
        (bool valid,) = verifier.verify(payload, sig);
        assertFalse(valid);
    }

    function test_verify_highS_returnsFalse() public {
        (bytes memory payload, bytes memory sig) = _makeAndSplit(
            oracleKey, vaultAddr, chainId, block.timestamp, block.timestamp + 1 days
        );
        // Compute the malleable high-s variant: s' = n - s, v' = 55 - v (flips 27↔28)
        // secp256k1 group order n
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(31, mload(add(sig, 96)))
        }
        bytes32 highS = bytes32(n - uint256(s));
        uint8 flippedV = (v == 27) ? 28 : 27;
        sig = abi.encodePacked(r, highS, flippedV);

        vm.prank(vaultAddr);
        (bool valid,) = verifier.verify(payload, sig);
        assertFalse(valid);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// @dev Returns (payload, sig) as separate bytes memory values.
    ///      Cannot use memory slice notation; uses assembly to copy.
    function _makeAndSplit(
        uint256 privKey,
        address vault,
        uint256 cid,
        uint256 issuedAt,
        uint256 expiresAt
    ) internal view returns (bytes memory payload, bytes memory sig) {
        bytes32 id = keccak256(abi.encode(vault, cid, issuedAt));
        bytes32 evidenceHash = keccak256("evidence");
        payload = abi.encode(id, vault, cid, issuedAt, expiresAt, demoTemplateId, evidenceHash);
        assertEq(payload.length, 224, "payload must be 224 bytes");

        bytes32 structHash = keccak256(abi.encode(
            verifier.ATTESTATION_TYPE_HASH(),
            id,
            vault,
            cid,
            issuedAt,
            expiresAt,
            demoTemplateId,
            evidenceHash
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", verifier.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, digest);
        sig = abi.encodePacked(r, s, v);
        assertEq(sig.length, 65, "sig must be 65 bytes");
    }
}
