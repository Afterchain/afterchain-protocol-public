// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/NullifierRegistry.sol";

contract NullifierRegistryTest is Test {
    NullifierRegistry internal registry;
    address internal owner = address(this);
    address internal operator = address(0xA11CE);
    address internal vault1 = address(0xBEEF);
    address internal vault2 = address(0xCAFE);
    address internal rando = address(0xDEAD);

    function setUp() public {
        registry = new NullifierRegistry(owner);
    }

    // ── setOperator ──────────────────────────────────────────────────────────

    function test_setOperator_byOwner_succeeds() public {
        registry.setOperator(operator);
        assertEq(registry.operator(), operator);
    }

    function test_setOperator_byNonOwner_reverts() public {
        // DD Sprint A: bootstrap window — rando is neither the bootstrap
        // deployer nor governance, so the call reverts with NotBootstrapDeployer.
        vm.prank(rando);
        vm.expectRevert(abi.encodeWithSelector(NullifierRegistry.NotBootstrapDeployer.selector, rando));
        registry.setOperator(operator);
    }

    function test_setOperator_postBootstrap_byNonGovernance_reverts() public {
        // DD Sprint A: after the deployer's one-shot bootstrap call, only
        // governance can rotate the operator. The test contract is BOTH the
        // bootstrap deployer AND the governance, so we use a fresh registry
        // whose governance is a different address.
        address gov = address(0xBEEF1234);
        NullifierRegistry r = new NullifierRegistry(gov);
        // Bootstrap call by the deployer (this contract).
        r.setOperator(operator);
        assertTrue(r.operatorBootstrapSealed());
        // Subsequent rotation by the deployer is no longer permitted.
        vm.expectRevert(abi.encodeWithSelector(NullifierRegistry.NotGovernance.selector, address(this)));
        r.setOperator(address(0xABCD));
    }

    // ── authorizeVault ───────────────────────────────────────────────────────

    function test_authorizeVault_byOperator_succeeds() public {
        registry.setOperator(operator);
        vm.prank(operator);
        registry.authorizeVault(vault1);
        assertTrue(registry.isAuthorizedVault(vault1));
    }

    function test_authorizeVault_byOwner_reverts() public {
        // Owner cannot directly authorize vaults — only operator can.
        // This prevents owner from authorizing a rogue contract to pre-spend nullifiers.
        registry.setOperator(operator);
        vm.expectRevert(abi.encodeWithSelector(NullifierRegistry.NotOperator.selector, owner));
        registry.authorizeVault(vault1);
    }

    function test_authorizeVault_byRando_reverts() public {
        registry.setOperator(operator);
        vm.prank(rando);
        vm.expectRevert(abi.encodeWithSelector(NullifierRegistry.NotOperator.selector, rando));
        registry.authorizeVault(vault1);
    }

    function test_authorizeVault_beforeOperatorSet_reverts() public {
        // operator is address(0) initially — msg.sender != address(0), so reverts
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(NullifierRegistry.NotOperator.selector, operator));
        registry.authorizeVault(vault1);
    }

    // ── isSpent / spend ──────────────────────────────────────────────────────

    function test_freshNullifier_isNotSpent() public view {
        bytes32 nullifier = keccak256("test-nullifier");
        assertFalse(registry.isSpent(nullifier));
    }

    function test_freshNullifier_spendSucceeds() public {
        _authorizeVault(vault1);
        bytes32 nullifier = keccak256("test-nullifier");

        vm.prank(vault1);
        registry.spend(nullifier);

        assertTrue(registry.isSpent(nullifier));
    }

    function test_freshNullifier_spendEmitsEvent() public {
        _authorizeVault(vault1);
        bytes32 nullifier = keccak256("test-nullifier");

        vm.expectEmit(true, true, false, false);
        emit INullifierRegistry.NullifierSpent(nullifier, vault1);

        vm.prank(vault1);
        registry.spend(nullifier);
    }

    function test_duplicateNullifier_reverts() public {
        _authorizeVault(vault1);
        bytes32 nullifier = keccak256("test-nullifier");

        vm.prank(vault1);
        registry.spend(nullifier);

        vm.prank(vault1);
        vm.expectRevert(abi.encodeWithSelector(INullifierRegistry.NullifierAlreadySpent.selector, nullifier));
        registry.spend(nullifier);
    }

    function test_nonAuthorizedVault_spend_reverts() public {
        bytes32 nullifier = keccak256("test-nullifier");
        vm.prank(rando);
        vm.expectRevert(abi.encodeWithSelector(INullifierRegistry.UnauthorizedCaller.selector, rando));
        registry.spend(nullifier);
    }

    /// @notice DD Sprint A — Finding 3.1: an MEV bot or any external EOA
    /// cannot pre-spend a legitimate beneficiary's nullifier. The on-chain
    /// access-control check rejects the call BEFORE any state mutation, so
    /// the legitimate vault's subsequent spend() still succeeds.
    function test_mevBot_cannot_pre_spend_then_legitimate_vault_can() public {
        _authorizeVault(vault1);
        bytes32 nullifier = keccak256("legitimate-nullifier");

        // MEV bot tries to front-run the legitimate vault by pre-spending.
        address mevBot = address(0xDEAD1010);
        vm.prank(mevBot);
        vm.expectRevert(abi.encodeWithSelector(INullifierRegistry.UnauthorizedCaller.selector, mevBot));
        registry.spend(nullifier);

        // Nullifier is still unspent — the bot's call did not mutate state.
        assertFalse(registry.isSpent(nullifier));

        // The legitimate authorized vault successfully spends.
        vm.prank(vault1);
        registry.spend(nullifier);
        assertTrue(registry.isSpent(nullifier));
    }

    function test_differentNullifiers_independentlyTracked() public {
        _authorizeVault(vault1);
        bytes32 n1 = keccak256("nullifier-1");
        bytes32 n2 = keccak256("nullifier-2");

        vm.prank(vault1);
        registry.spend(n1);

        assertTrue(registry.isSpent(n1));
        assertFalse(registry.isSpent(n2));
    }

    function test_operatorChange_doesNotAffectExistingVaults() public {
        _authorizeVault(vault1);
        bytes32 nullifier = keccak256("nullifier");

        // Change operator
        address newOperator = address(0x9999);
        registry.setOperator(newOperator);

        // Previously authorized vault1 can still spend
        vm.prank(vault1);
        registry.spend(nullifier);
        assertTrue(registry.isSpent(nullifier));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    function _authorizeVault(address vault) internal {
        registry.setOperator(operator);
        vm.prank(operator);
        registry.authorizeVault(vault);
    }
}
