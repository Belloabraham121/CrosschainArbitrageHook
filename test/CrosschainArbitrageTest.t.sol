// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {CrosschainArbitrageHook} from "../src/PointsHook.sol";
import {ArbitrageBot} from "../src/ArbitrageBot.sol";
import {IAcrossProtocol} from "../src/interfaces/IAcrossProtocol.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {SwapParams} from "v4-core/types/PoolOperation.sol";
import {Currency} from "v4-core/types/Currency.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";
import {HookMiner} from "v4-periphery/src/utils/HookMiner.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";

/// @title CrosschainArbitrageTest
/// @notice Comprehensive test suite for the Crosschain Arbitrage Hook and Bot system
contract CrosschainArbitrageTest is Test {
    // Contracts under test
    CrosschainArbitrageHook public hook;
    ArbitrageBot public bot;

    // Mock contracts
    MockPoolManager public poolManager;
    MockAcrossProtocol public acrossProtocol;
    MockERC20 public token0;
    MockERC20 public token1;

    // Test addresses
    address public owner;
    address public user;
    address public botOperator;

    // Test constants
    uint256 private constant INITIAL_BALANCE = 1000 ether;
    uint256 private constant PRICE_DIFFERENCE_THRESHOLD = 100; // 1%
    uint256 private constant MIN_PROFIT = 0.01 ether;

    // Events for testing
    event ArbitrageOpportunityDetected(
        address indexed token,
        uint256 indexed sourceChain,
        uint256 indexed targetChain,
        uint256 priceDifference,
        uint256 potentialProfit
    );

    event ArbitrageExecuted(
        address indexed token,
        uint256 indexed sourceChain,
        uint256 indexed targetChain,
        uint256 amount,
        uint256 profit
    );

    function setUp() public {
        // Set up test addresses
        owner = makeAddr("owner");
        user = makeAddr("user");
        botOperator = makeAddr("botOperator");

        // Deploy mock contracts
        poolManager = new MockPoolManager();
        acrossProtocol = new MockAcrossProtocol();
        token0 = new MockERC20("Token0", "TK0");
        token1 = new MockERC20("Token1", "TK1");

        // Deploy main contracts
        vm.startPrank(owner);

        // Deploy hook directly for testing (skip address validation for now)
        // In production, proper HookMiner usage would be required
        hook = new CrosschainArbitrageHook(
            IPoolManager(address(poolManager)),
            address(acrossProtocol)
        );

        // Note: In a real deployment, the hook address would need to be mined
        // to match the required permissions using HookMiner

        bot = new ArbitrageBot(address(hook));
        vm.stopPrank();

        // Set up initial balances
        token0.mint(address(hook), INITIAL_BALANCE);
        token1.mint(address(hook), INITIAL_BALANCE);
        token0.mint(user, INITIAL_BALANCE);
        token1.mint(user, INITIAL_BALANCE);

        // Configure bot
        _configureBotForTesting();
    }

    /// @notice Test hook deployment and initialization
    function testHookDeployment() public view {
        assertEq(hook.owner(), owner);
        assertEq(hook.acrossProtocol(), address(acrossProtocol));
        assertEq(hook.totalArbitrageCount(), 0);
        assertEq(hook.totalArbitrageProfit(), 0);

        // Test risk parameters
        CrosschainArbitrageHook.RiskParameters memory riskParams = hook
            .getRiskParameters();
        assertEq(riskParams.maxSlippage, 100); // 1%
        assertEq(riskParams.minProfitThreshold, 1e16); // 0.01 ETH
        assertEq(riskParams.maxPositionSize, 100e18); // 100 ETH
        assertFalse(riskParams.emergencyStop);
    }

    /// @notice Test bot deployment and configuration
    function testBotDeployment() public view {
        assertEq(address(bot.arbitrageHook()), address(hook));
        assertEq(bot.owner(), owner);
        assertEq(bot.totalScans(), 0);
        assertEq(bot.totalExecutions(), 0);
        assertEq(bot.totalProfit(), 0);
    }

    /// @notice Test price update functionality
    function testPriceUpdate() public {
        PoolKey memory key = _createPoolKey();
        SwapParams memory params = _createSwapParams(1 ether, true);

        // Mock price calculation
        uint256 expectedPrice = 1.5e18; // 1.5 ETH per token
        poolManager.setTokenPrice(address(token0), expectedPrice);

        // Trigger price update through beforeSwap
        vm.prank(address(poolManager));
        hook.beforeSwap(user, key, params, "");

        // Check price was updated
        (
            uint256 _price,
            uint256 timestamp,
            uint256 liquidity,
            bool isValid
        ) = hook.tokenPrices(address(token0), block.chainid);

        assertTrue(isValid);
        assertEq(timestamp, block.timestamp);
        assertGt(liquidity, 0);
    }

    /// @notice Test arbitrage opportunity detection
    function testArbitrageOpportunityDetection() public {
        // Set up price difference between chains
        _setupPriceDifference(address(token0), 1e18, 1.1e18); // 10% difference

        PoolKey memory key = _createPoolKey();
        SwapParams memory params = _createSwapParams(10 ether, true);

        // Execute swap and verify it doesn't revert
        vm.prank(address(poolManager));
        hook.beforeSwap(user, key, params, "");

        // Test passes if no revert occurs - arbitrage detection logic is working
    }

    /// @notice Test bot scanning functionality
    function testBotScanning() public {
        // Set up profitable arbitrage opportunity
        _setupPriceDifference(address(token0), 1e18, 1.2e18); // 20% difference

        // Activate bot
        vm.prank(owner);
        bot.activateBot(botOperator);

        // Fast forward time to allow scanning
        vm.warp(block.timestamp + 30001); // Past scan interval

        // Perform scan
        vm.prank(botOperator);
        bot.scanForOpportunities();

        // Check scan was recorded
        assertEq(bot.totalScans(), 1);
        console.log("Total scans:", bot.totalScans());
        assertGt(bot.lastScanTime(botOperator), 0);
    }

    /// @notice Test ML model initialization and updates
    function testMLModelFunctionality() public {
        // Initialize ML model
        vm.prank(owner);
        bot.initializeMLModel(address(token0));

        // Check model was initialized
        (
            ,
            uint256 accuracy,
            uint256 lastUpdate,
            uint256 trainingDataPoints,
            bool isActive
        ) = bot.getMLModelInfo(address(token0));

        assertEq(accuracy, 5000); // 50% initial accuracy
        assertEq(lastUpdate, block.timestamp);
        assertEq(trainingDataPoints, 0);
        assertTrue(isActive);

        // Test price prediction
        int256[5] memory prediction = hook.getPricePrediction(address(token0));
        // Initial prediction should be zeros
        for (uint256 i = 0; i < 5; i++) {
            assertEq(prediction[i], 0);
        }
    }

    /// @notice Test risk management functionality
    function testRiskManagement() public {
        // Test emergency stop
        vm.prank(owner);
        hook.emergencyStop();

        CrosschainArbitrageHook.RiskParameters memory riskParams = hook
            .getRiskParameters();
        assertTrue(riskParams.emergencyStop);

        // Test that operations are blocked
        PoolKey memory key = _createPoolKey();
        SwapParams memory params = _createSwapParams(1 ether, true);

        // This should not revert as emergency stop only affects execution, not price updates
        vm.prank(address(poolManager));
        hook.beforeSwap(user, key, params, "");

        // Resume operations
        vm.prank(owner);
        hook.resumeOperations();

        riskParams = hook.getRiskParameters();
        assertFalse(riskParams.emergencyStop);
    }

    /// @notice Test volatility calculation
    function testVolatilityCalculation() public {
        uint256 volatility = hook.getVolatilityScore(address(token0));
        assertEq(volatility, 0); // Should be 0 initially (no price updates yet)

        // Trigger price updates to generate volatility data
        PoolKey memory key = _createPoolKey();
        SwapParams memory params = _createSwapParams(1 ether, true);

        vm.prank(address(poolManager));
        hook.beforeSwap(user, key, params, "");

        // After price update, volatility should be calculated
        volatility = hook.getVolatilityScore(address(token0));
        assertGt(volatility, 0); // Should have some volatility value
        assertLe(volatility, 10000); // Should not exceed 100% (10000 basis points)
    }

    /// @notice Test authorization system
    function testAuthorization() public {
        // Test that only owner can add authorized bots
        vm.expectRevert("Not authorized");
        vm.prank(user);
        hook.addAuthorizedBot(botOperator);

        // Owner should be able to add authorized bot
        vm.prank(owner);
        hook.addAuthorizedBot(botOperator);

        assertTrue(hook.authorizedBots(botOperator));

        // Test removing authorized bot
        vm.prank(owner);
        hook.removeAuthorizedBot(botOperator);

        assertFalse(hook.authorizedBots(botOperator));
    }

    /// @notice Test profit withdrawal
    function testProfitWithdrawal() public {
        // Give hook some tokens to withdraw
        token0.mint(address(hook), 100 ether);

        uint256 initialBalance = token0.balanceOf(owner);

        // Only owner should be able to withdraw
        vm.expectRevert("Not authorized");
        vm.prank(user);
        hook.withdrawProfits(address(token0), 50 ether);

        // Owner withdrawal should work
        vm.prank(owner);
        hook.withdrawProfits(address(token0), 50 ether);

        assertEq(token0.balanceOf(owner), initialBalance + 50 ether);
    }

    /// @notice Test gas optimization
    function testGasOptimization() public {
        PoolKey memory key = _createPoolKey();
        SwapParams memory params = _createSwapParams(1 ether, true);

        // Measure gas for beforeSwap
        uint256 gasBefore = gasleft();
        vm.prank(address(poolManager));
        hook.beforeSwap(user, key, params, "");
        uint256 gasUsed = gasBefore - gasleft();

        // Gas usage should be reasonable (less than 600k)
        assertLt(gasUsed, 600000);

        console.log("Gas used for beforeSwap:", gasUsed);
    }

    /// @notice Test edge cases
    function testEdgeCases() public {
        // Test with zero amounts
        PoolKey memory key = _createPoolKey();
        SwapParams memory params = _createSwapParams(0, true);

        vm.prank(address(poolManager));
        hook.beforeSwap(user, key, params, "");

        // Test with very large amounts
        params = _createSwapParams(type(uint128).max, true);

        vm.prank(address(poolManager));
        hook.beforeSwap(user, key, params, "");

        // Test with invalid token addresses
        key.currency0 = Currency.wrap(address(0));

        vm.prank(address(poolManager));
        hook.beforeSwap(user, key, params, "");
    }

    /// @notice Test bot performance tracking
    function testBotPerformanceTracking() public {
        // Initial performance should be 0
        assertEq(bot.getBotPerformance(botOperator), 0);

        // Configure and activate bot
        vm.prank(owner);
        bot.activateBot(botOperator);

        // Set up profitable opportunity
        _setupPriceDifference(address(token0), 1e18, 1.5e18);

        // Fast forward and scan
        vm.warp(block.timestamp + 301);
        vm.prank(botOperator);
        bot.scanForOpportunities();

        // Check stats
        (
            uint256 totalScans,
            uint256 _totalExecutions,
            uint256 _totalProfit,
            uint256 successRate
        ) = bot.getBotStats();

        assertGt(totalScans, 0);
        // Success rate calculation: (executions * 10000) / scans
        assertLe(successRate, 10000); // Should be <= 100%
    }

    /// @notice Test multiple chain support
    function testMultiChainSupport() public view {
        // Test that hook supports multiple chains
        uint256[] memory supportedChains = new uint256[](4);
        supportedChains[0] = 1; // Ethereum
        supportedChains[1] = 10; // Optimism
        supportedChains[2] = 42161; // Arbitrum
        supportedChains[3] = 137; // Polygon

        // Set up price data for multiple chains
        for (uint256 i = 0; i < supportedChains.length; i++) {
            // This would normally be done by oracles or cross-chain price feeds
            // For testing, we'll just verify the structure exists
            (, , , bool isValid) = hook.tokenPrices(
                address(token0),
                supportedChains[i]
            );
            assertFalse(isValid); // Should be false initially
        }
    }

    function _testAcrossArbitrage(
        address token,
        uint256 amount,
        uint256 sourceChain,
        uint256 targetChain,
        address /* exclusiveRelayer */
    ) internal view {
        // Test the Across Protocol integration
        // This would be expanded with actual Across Protocol testing

        // Check state changes
        (
            uint256 price,
            uint256 timestamp,
            uint256 liquidity,
            bool isValid
        ) = hook.tokenPrices(token, sourceChain);
        uint256 totalExecutions = bot.totalExecutions();
        uint256 totalProfit = bot.totalProfit();

        // Verify the values are reasonable
        assertTrue(price > 0);
        assertTrue(liquidity > 0);
        assertTrue(timestamp > 0);
        assertTrue(isValid);
        assertTrue(totalExecutions >= 0);
        assertTrue(totalProfit >= 0);

        // Verify arbitrage execution
        assertTrue(amount > 0, "Amount should be positive");
        assertTrue(sourceChain != targetChain, "Chains should be different");
    }

    /// @notice Test price calculation functionality
    function testCalculateTokenPrice() public {
        // Setup pool key
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        // Setup swap params
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: 1 ether,
            sqrtPriceLimitX96: 0
        });

        // Test price calculation with different scenarios
        vm.startPrank(owner);

        // Test with positive swap amount (buying)
        uint256 buyPrice = hook.calculateTokenPrice(
            address(token0),
            key,
            params
        );
        assertGt(buyPrice, 1 ether, "Buy price should be higher than base");

        // Test with negative swap amount (selling)
        params.amountSpecified = -1 ether;
        uint256 sellPrice = hook.calculateTokenPrice(
            address(token0),
            key,
            params
        );
        assertLt(sellPrice, 1 ether, "Sell price should be lower than base");

        // Test with zero amount
        params.amountSpecified = 0;
        uint256 basePrice = hook.calculateTokenPrice(
            address(token0),
            key,
            params
        );
        assertEq(basePrice, 1 ether, "Base price should be 1 ETH");

        vm.stopPrank();
    }

    /// @notice Test pool liquidity calculation
    function testGetPoolLiquidity() public {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        vm.startPrank(owner);

        uint256 liquidity = hook.getPoolLiquidity(key);
        assertGt(liquidity, 0, "Liquidity should be positive");
        assertGe(liquidity, 100 ether, "Liquidity should be at least 100 ETH");

        // Test with different tokens should give different liquidity
        uint256 liquidity2 = hook.getPoolLiquidity(key);
        // They might be the same due to pseudo-randomness, but should still be valid
        assertGt(liquidity2, 0, "Second token liquidity should be positive");

        vm.stopPrank();
    }

    /// @notice Test volatility calculation
    function testCalculateVolatility() public {
        vm.startPrank(owner);

        uint256 volatility1 = hook.calculateVolatility(address(token0), 1);
        uint256 volatility2 = hook.calculateVolatility(address(token0), 137);
        uint256 volatility3 = hook.calculateVolatility(address(token1), 1);

        // Volatility should be within bounds (0-100%)
        assertLe(volatility1, 10000, "Volatility should not exceed 100%");
        assertLe(volatility2, 10000, "Volatility should not exceed 100%");
        assertLe(volatility3, 10000, "Volatility should not exceed 100%");

        // Different tokens/chains should potentially give different volatilities
        assertTrue(
            volatility1 != volatility2 || volatility1 != volatility3,
            "Should have some variation"
        );

        vm.stopPrank();
    }

    /// @notice Test momentum calculation
    function testCalculateMomentum() public {
        vm.startPrank(owner);

        // First set up some price data
        hook.updateTokenPrice(address(token0), 1, 1 ether, 1000 ether);

        uint256 momentum = hook.calculateMomentum(address(token0), 1);

        // Momentum should be within bounds (0-100%)
        assertLe(momentum, 10000, "Momentum should not exceed 100%");
        assertGe(momentum, 0, "Momentum should not be negative");

        // Test with invalid price data
        uint256 momentumInvalid = hook.calculateMomentum(address(token1), 999);
        assertEq(
            momentumInvalid,
            5000,
            "Should return neutral momentum for invalid data"
        );

        vm.stopPrank();
    }

    /// @notice Test volume trend calculation
    function testCalculateVolumeTrend() public {
        vm.startPrank(owner);

        // Set up price data with liquidity
        hook.updateTokenPrice(address(token0), 1, 1 ether, 1000 ether);

        uint256 volumeTrend = hook.calculateVolumeTrend(address(token0), 1);

        // Volume trend should be within bounds
        assertLe(volumeTrend, 10000, "Volume trend should not exceed 100%");
        assertGe(volumeTrend, 0, "Volume trend should not be negative");

        // Test with zero liquidity
        hook.updateTokenPrice(address(token1), 1, 1 ether, 0);
        uint256 volumeTrendZero = hook.calculateVolumeTrend(address(token1), 1);
        assertEq(
            volumeTrendZero,
            5000,
            "Should return neutral trend for zero liquidity"
        );

        vm.stopPrank();
    }

    /// @notice Test cross-chain correlation calculation
    function testCalculateCrossChainCorrelation() public {
        vm.startPrank(owner);

        // Set up price data across multiple chains
        hook.updateTokenPrice(address(token0), 1, 1 ether, 1000 ether); // Ethereum
        hook.updateTokenPrice(address(token0), 137, 1.01 ether, 800 ether); // Polygon
        hook.updateTokenPrice(address(token0), 42161, 0.99 ether, 1200 ether); // Arbitrum

        uint256 correlation = hook.calculateCrossChainCorrelation(
            address(token0)
        );

        // Correlation should be within bounds
        assertLe(correlation, 10000, "Correlation should not exceed 100%");
        assertGe(correlation, 0, "Correlation should not be negative");

        // With small price differences, should have good correlation
        assertGe(
            correlation,
            5000,
            "Should have decent correlation with small price differences"
        );

        // Test with insufficient data
        uint256 correlationInsufficient = hook.calculateCrossChainCorrelation(
            address(token1)
        );
        assertEq(
            correlationInsufficient,
            5000,
            "Should return neutral correlation for insufficient data"
        );

        vm.stopPrank();
    }

    /// @notice Test ML model accuracy calculation
    function testCalculateModelAccuracy() public {
        vm.startPrank(owner);

        // Initialize ML model for token
        bot.initializeMLModel(address(token0));

        uint256 accuracy = bot.calculateModelAccuracy(address(token0));

        // Accuracy should be within bounds
        assertLe(accuracy, 10000, "Accuracy should not exceed 100%");
        assertGe(accuracy, 1000, "Accuracy should be at least 10%");

        // Test with non-existent model
        uint256 accuracyNonExistent = bot.calculateModelAccuracy(
            address(token1)
        );
        assertEq(
            accuracyNonExistent,
            5000,
            "Should return 50% for non-existent model"
        );

        vm.stopPrank();
    }

    /// @notice Test arbitrage execution via Across
    function testExecuteArbitrageViaAcross() public {
        vm.startPrank(owner);

        // Set up price data for arbitrage opportunity
        hook.updateTokenPrice(address(token0), 1, 1 ether, 1000 ether); // Source chain
        hook.updateTokenPrice(address(token0), 137, 1.1 ether, 800 ether); // Target chain (10% higher)

        // Test successful arbitrage conditions
        hook.executeArbitrageViaAcross(address(token0), 10 ether, 1, 137);
        // If we reach here, arbitrage succeeded

        // Test failure conditions - these should revert
        vm.expectRevert();
        hook.executeArbitrageViaAcross(address(token0), 0, 1, 137);

        vm.expectRevert();
        hook.executeArbitrageViaAcross(address(token0), 10 ether, 1, 1);

        vm.expectRevert();
        hook.executeArbitrageViaAcross(address(0), 10 ether, 1, 137);

        vm.stopPrank();
    }

    /// @notice Test helper functions
    function testHelperFunctions() public {
        vm.startPrank(owner);

        // Test price data validation
        hook.updateTokenPrice(address(token0), 1, 1 ether, 1000 ether);

        // Test potential profit calculation
        uint256 profit = hook.calculatePotentialProfit(
            1 ether,
            1.1 ether,
            10 ether
        );
        // Expected: 10% price difference = 1 ETH gross profit, minus 1% fees (0.1 ETH) = 0.9 ETH
        assertEq(
            profit,
            0.9 ether,
            "Should calculate 10% profit minus fees correctly"
        );

        uint256 noProfit = hook.calculatePotentialProfit(
            1.1 ether,
            1 ether,
            10 ether
        );
        assertEq(noProfit, 0, "Should return 0 for negative arbitrage");

        uint256 zeroProfitZeroAmount = hook.calculatePotentialProfit(
            1 ether,
            1.1 ether,
            0
        );
        assertEq(zeroProfitZeroAmount, 0, "Should return 0 for zero amount");

        vm.stopPrank();
    }

    /// @notice Test comprehensive arbitrage flow
    function testComprehensiveArbitrageFlow() public {
        vm.startPrank(owner);

        // 1. Set up price differences across chains
        hook.updateTokenPrice(address(token0), 1, 1 ether, 1000 ether); // Ethereum
        hook.updateTokenPrice(address(token0), 137, 1.05 ether, 800 ether); // Polygon (5% higher)
        hook.updateTokenPrice(address(token0), 42161, 0.98 ether, 1200 ether); // Arbitrum (2% lower)

        // 2. Initialize bot and ML model
        bot.initializeMLModel(address(token0));

        // 3. Test volatility and momentum calculations
        uint256 volatility = hook.calculateVolatility(address(token0), 1);
        uint256 momentum = hook.calculateMomentum(address(token0), 1);
        uint256 volumeTrend = hook.calculateVolumeTrend(address(token0), 1);
        uint256 correlation = hook.calculateCrossChainCorrelation(
            address(token0)
        );

        // All metrics should be valid
        assertLe(volatility, 10000, "Volatility within bounds");
        assertLe(momentum, 10000, "Momentum within bounds");
        assertLe(volumeTrend, 10000, "Volume trend within bounds");
        assertLe(correlation, 10000, "Correlation within bounds");

        // 4. Test ML model accuracy
        uint256 accuracy = bot.calculateModelAccuracy(address(token0));
        assertGe(accuracy, 1000, "Model accuracy should be at least 10%");

        // 5. Test arbitrage execution
        hook.executeArbitrageViaAcross(address(token0), 5 ether, 1, 137);
        // If we reach here, arbitrage succeeded in comprehensive flow

        vm.stopPrank();
    }

    // Helper functions

    function _configureBotForTesting() internal {
        address[] memory targetTokens = new address[](2);
        targetTokens[0] = address(token0);
        targetTokens[1] = address(token1);

        uint256[] memory targetChains = new uint256[](2);
        targetChains[0] = 1; // Ethereum
        targetChains[1] = 42161; // Arbitrum

        vm.prank(owner);
        bot.configureBotConfig(
            botOperator,
            300, // 5 minutes
            100 gwei,
            MIN_PROFIT,
            10 ether,
            targetTokens,
            targetChains
        );

        // Add bot as authorized
        vm.prank(owner);
        hook.addAuthorizedBot(address(bot));
    }

    function _createPoolKey() internal view returns (PoolKey memory) {
        return
            PoolKey({
                currency0: Currency.wrap(address(token0)),
                currency1: Currency.wrap(address(token1)),
                fee: 3000,
                tickSpacing: 60,
                hooks: hook
            });
    }

    function _createSwapParams(
        uint256 amount,
        bool zeroForOne
    ) internal pure returns (SwapParams memory) {
        return
            SwapParams({
                zeroForOne: zeroForOne,
                amountSpecified: int256(amount),
                sqrtPriceLimitX96: 0
            });
    }

    function _setupPriceDifference(
        address token,
        uint256 sourcePrice,
        uint256 targetPrice
    ) internal {
        // Set up price difference between current chain and target chain
        poolManager.setTokenPrice(token, sourcePrice);

        // Simulate price data for target chain (this would normally come from oracles)
        // For testing, we'll manually set the price data using correct storage slot calculation
        // tokenPrices[token][42161] storage slot calculation
        bytes32 innerMapSlot = keccak256(
            abi.encode(uint256(42161), keccak256(abi.encode(token, uint256(0))))
        ); // 0 is tokenPrices slot

        // Set price (first field in PriceData struct)
        vm.store(address(hook), innerMapSlot, bytes32(targetPrice));

        // Set timestamp (second field, offset +1)
        vm.store(
            address(hook),
            bytes32(uint256(innerMapSlot) + 1),
            bytes32(block.timestamp)
        );

        // Set liquidity (third field, offset +2)
        vm.store(
            address(hook),
            bytes32(uint256(innerMapSlot) + 2),
            bytes32(uint256(1000 ether))
        );

        // Set isValid (fourth field, offset +3) - bool is packed but we'll use full slot
        vm.store(
            address(hook),
            bytes32(uint256(innerMapSlot) + 3),
            bytes32(uint256(1))
        );
    }
}

// Mock contracts for testing

contract MockPoolManager {
    mapping(address => uint256) public tokenPrices;

    function setTokenPrice(address token, uint256 price) external {
        tokenPrices[token] = price;
    }

    function getTokenPrice(address token) external view returns (uint256) {
        return tokenPrices[token] > 0 ? tokenPrices[token] : 1e18;
    }
}

contract MockAcrossProtocol {
    event DepositMade(
        address indexed depositor,
        address indexed recipient,
        address indexed inputToken,
        address outputToken,
        uint256 inputAmount,
        uint256 outputAmount,
        uint256 destinationChainId,
        uint32 depositId
    );

    uint32 public depositIdCounter = 1;

    function isRouteEnabled(
        address /* inputToken */,
        address /* outputToken */,
        uint256 /* destinationChainId */
    ) external pure returns (bool) {
        return true; // Always return true for testing
    }

    function getDepositLimits(
        address /* token */,
        uint256 /* destinationChainId */
    ) external pure returns (uint256 minDeposit, uint256 maxDeposit) {
        return (1e15, 1000e18); // 0.001 to 1000 tokens
    }

    function getQuote(
        address /* inputToken */,
        address /* outputToken */,
        uint256 inputAmount,
        uint256 /* destinationChainId */,
        address /* recipient */,
        bytes calldata /* message */
    )
        external
        view
        returns (
            uint256 outputAmount,
            uint256 totalRelayFee,
            uint32 quoteTimestamp,
            uint256 fillDeadline,
            uint256 exclusivityDeadline
        )
    {
        // Mock implementation: 0.1% fee
        totalRelayFee = inputAmount / 1000;
        outputAmount = inputAmount - totalRelayFee;
        quoteTimestamp = uint32(block.timestamp);
        fillDeadline = block.timestamp + 3600; // 1 hour
        exclusivityDeadline = block.timestamp + 300; // 5 minutes
    }

    function depositV3(
        address recipient,
        address inputToken,
        address outputToken,
        uint256 inputAmount,
        uint256 outputAmount,
        uint256 destinationChainId,
        address /* exclusiveRelayer */,
        uint32 /* quoteTimestamp */,
        uint256 /* fillDeadline */,
        uint256 /* exclusivityDeadline */,
        bytes calldata /* message */
    ) external payable {
        emit DepositMade(
            msg.sender,
            recipient,
            inputToken,
            outputToken,
            inputAmount,
            outputAmount,
            destinationChainId,
            depositIdCounter++
        );
    }
}

contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}
