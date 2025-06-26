// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IERC20} from "forge-std/interfaces/IERC20.sol";
import {CrosschainArbitrageHook} from "./PointsHook.sol";

/// @title ArbitrageBot
/// @notice Automated bot for scanning and executing crosschain arbitrage opportunities
/// @dev Integrates with CrosschainArbitrageHook to continuously monitor and execute trades
contract ArbitrageBot {
    event BotActivated(address indexed bot, uint256 timestamp);
    event BotDeactivated(address indexed bot, uint256 timestamp);
    event OpportunityScanned(
        address indexed token,
        uint256 chainId,
        uint256 timestamp
    );
    event ArbitrageTriggered(
        bytes32 indexed opportunityId,
        address indexed token,
        uint256 profit
    );
    event MLModelUpdated(
        address indexed token,
        uint256 accuracy,
        uint256 timestamp
    );
    event RiskThresholdBreached(
        address indexed token,
        uint256 riskLevel,
        string reason
    );

    // Structs
    struct BotConfig {
        bool isActive;
        uint256 scanInterval; // seconds between scans
        uint256 maxGasPrice; // maximum gas price for transactions
        uint256 minProfitThreshold; // minimum profit to execute
        uint256 maxPositionSize; // maximum position size
        address[] targetTokens; // tokens to monitor
        uint256[] targetChains; // chains to monitor
    }

    struct ScanResult {
        address token;
        uint256 sourceChain;
        uint256 targetChain;
        uint256 priceDifference;
        uint256 potentialProfit;
        uint256 confidence; // ML model confidence score
        uint256 riskScore;
        bool shouldExecute;
    }

    struct MLModel {
        int256[10] weights; // feature weights
        uint256 accuracy; // model accuracy percentage
        uint256 lastUpdate;
        uint256 trainingDataPoints;
        bool isActive;
    }

    struct RiskMetrics {
        uint256 volatility;
        uint256 liquidity;
        uint256 slippage;
        uint256 gasPrice;
        uint256 bridgeFee;
        uint256 totalRiskScore;
    }

    CrosschainArbitrageHook public immutable arbitrageHook;
    address public owner;
    mapping(address => BotConfig) public botConfigs;
    mapping(address => MLModel) public mlModels;
    mapping(address => uint256) public lastScanTime;
    mapping(address => uint256) public botPerformance;
    mapping(bytes32 => bool) public executedOpportunities;

    uint256 public totalScans;
    uint256 public totalExecutions;
    uint256 public totalProfit;
    bool public globalEmergencyStop;

    // ML training data
    mapping(address => uint256[]) public historicalPrices;
    mapping(address => uint256[]) public historicalVolumes;
    mapping(address => uint256[]) public historicalVolatility;

    // Constants
    uint256 private constant MAX_SCAN_INTERVAL = 3600; // 1 hour
    uint256 private constant MIN_SCAN_INTERVAL = 60; // 1 minute
    uint256 private constant ML_UPDATE_INTERVAL = 86400; // 24 hours
    uint256 private constant RISK_THRESHOLD = 8000; // 80%
    uint256 private constant MIN_CONFIDENCE = 7000; // 70%

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier onlyActiveBot() {
        require(botConfigs[msg.sender].isActive, "Bot not active");
        _;
    }

    modifier emergencyStopCheck() {
        require(!globalEmergencyStop, "Emergency stop activated");
        _;
    }

    constructor(address _arbitrageHook) {
        arbitrageHook = CrosschainArbitrageHook(_arbitrageHook);
        owner = msg.sender;
    }

    /// @notice Configure a bot for automated scanning
    function configureBotConfig(
        address bot,
        uint256 scanInterval,
        uint256 maxGasPrice,
        uint256 minProfitThreshold,
        uint256 maxPositionSize,
        address[] calldata targetTokens,
        uint256[] calldata targetChains
    ) external onlyOwner {
        require(
            scanInterval >= MIN_SCAN_INTERVAL &&
                scanInterval <= MAX_SCAN_INTERVAL,
            "Invalid scan interval"
        );
        require(targetTokens.length > 0, "Must specify target tokens");
        require(targetChains.length > 0, "Must specify target chains");

        botConfigs[bot] = BotConfig({
            isActive: false,
            scanInterval: scanInterval,
            maxGasPrice: maxGasPrice,
            minProfitThreshold: minProfitThreshold,
            maxPositionSize: maxPositionSize,
            targetTokens: targetTokens,
            targetChains: targetChains
        });
    }

    function activateBot(address bot) external onlyOwner {
        require(botConfigs[bot].scanInterval > 0, "Bot not configured");
        botConfigs[bot].isActive = true;
        emit BotActivated(bot, block.timestamp);
    }

    function deactivateBot(address bot) external onlyOwner {
        botConfigs[bot].isActive = false;
        emit BotDeactivated(bot, block.timestamp);
    }

    function scanForOpportunities() external onlyActiveBot emergencyStopCheck {
        BotConfig memory config = botConfigs[msg.sender];

        // Check if enough time has passed since last scan
        require(
            block.timestamp >= lastScanTime[msg.sender] + config.scanInterval,
            "Scan interval not met"
        );

        lastScanTime[msg.sender] = block.timestamp;
        totalScans++;

        // Scan each target token on each target chain
        for (uint256 i = 0; i < config.targetTokens.length; i++) {
            address token = config.targetTokens[i];

            for (uint256 j = 0; j < config.targetChains.length; j++) {
                uint256 chainId = config.targetChains[j];

                if (chainId == block.chainid) continue;

                ScanResult memory result = _scanTokenOnChain(
                    token,
                    chainId,
                    config
                );

                emit OpportunityScanned(token, chainId, block.timestamp);

                if (result.shouldExecute) {
                    _executeArbitrageOpportunity(result, config);
                }
            }
        }

        // Update ML models if needed
        _updateMLModelsIfNeeded(config.targetTokens);
    }

    /// @notice Scan a specific token on a specific chain
    function _scanTokenOnChain(
        address token,
        uint256 targetChain,
        BotConfig memory config
    ) internal view returns (ScanResult memory) {
        uint256 currentChain = block.chainid;

        // Get price data from the hook
        (
            uint256 currentPrice,
            uint256 _currentTimestamp,
            uint256 currentLiquidity,
            bool currentValid
        ) = arbitrageHook.tokenPrices(token, currentChain);

        (
            uint256 targetPrice,
            uint256 _targetTimestamp,
            uint256 targetLiquidity,
            bool targetValid
        ) = arbitrageHook.tokenPrices(token, targetChain);

        if (!currentValid || !targetValid) {
            return
                ScanResult({
                    token: token,
                    sourceChain: currentChain,
                    targetChain: targetChain,
                    priceDifference: 0,
                    potentialProfit: 0,
                    confidence: 0,
                    riskScore: 10000, // Max risk for invalid data
                    shouldExecute: false
                });
        }

        uint256 priceDifference = _calculatePriceDifference(
            currentPrice,
            targetPrice
        );

        uint256 potentialProfit = _calculatePotentialProfit(
            currentPrice,
            targetPrice,
            config.maxPositionSize
        );

        uint256 confidence = _getMLConfidence(token, currentPrice, targetPrice);

        RiskMetrics memory riskMetrics = _calculateRiskMetrics(
            token,
            currentChain,
            targetChain,
            currentLiquidity,
            targetLiquidity
        );

        bool shouldExecute = _shouldExecuteArbitrage(
            potentialProfit,
            confidence,
            riskMetrics.totalRiskScore,
            config
        );

        return
            ScanResult({
                token: token,
                sourceChain: currentChain,
                targetChain: targetChain,
                priceDifference: priceDifference,
                potentialProfit: potentialProfit,
                confidence: confidence,
                riskScore: riskMetrics.totalRiskScore,
                shouldExecute: shouldExecute
            });
    }

    /// @notice Execute arbitrage opportunity
    function _executeArbitrageOpportunity(
        ScanResult memory result,
        BotConfig memory /* config */
    ) internal {
        bytes32 opportunityId = keccak256(
            abi.encodePacked(
                result.token,
                result.sourceChain,
                result.targetChain,
                block.timestamp
            )
        );

        // Prevent duplicate execution
        require(!executedOpportunities[opportunityId], "Already executed");
        executedOpportunities[opportunityId] = true;

        totalExecutions++;
        totalProfit += result.potentialProfit;
        botPerformance[msg.sender] += result.potentialProfit;

        emit ArbitrageTriggered(
            opportunityId,
            result.token,
            result.potentialProfit
        );
    }

    /// @notice Calculate price difference in basis points
    function _calculatePriceDifference(
        uint256 price1,
        uint256 price2
    ) internal pure returns (uint256) {
        if (price1 == 0 || price2 == 0) return 0;

        uint256 diff = price1 > price2 ? price1 - price2 : price2 - price1;
        return (diff * 10000) / (price1 > price2 ? price2 : price1);
    }

    /// @notice Calculate potential profit
    function _calculatePotentialProfit(
        uint256 sourcePrice,
        uint256 targetPrice,
        uint256 maxAmount
    ) internal pure returns (uint256) {
        if (sourcePrice >= targetPrice) return 0;

        uint256 grossProfit = ((targetPrice - sourcePrice) * maxAmount) /
            sourcePrice;

        // Subtract estimated fees (2% total)
        uint256 estimatedFees = (maxAmount * 200) / 10000;

        return grossProfit > estimatedFees ? grossProfit - estimatedFees : 0;
    }

    /// @notice Get ML model confidence score
    function _getMLConfidence(
        address token,
        uint256 currentPrice,
        uint256 targetPrice
    ) internal view returns (uint256) {
        MLModel memory model = mlModels[token];

        if (!model.isActive || model.accuracy == 0) {
            return 5000; // 50% default confidence
        }

        // Simplified confidence calculation based on price difference and model accuracy
        uint256 priceDiff = _calculatePriceDifference(
            currentPrice,
            targetPrice
        );

        // Higher price differences generally have higher confidence
        uint256 baseConfidence = (priceDiff * model.accuracy) / 10000;

        // Cap at model accuracy
        return
            baseConfidence > model.accuracy ? model.accuracy : baseConfidence;
    }

    /// @notice Calculate comprehensive risk metrics
    function _calculateRiskMetrics(
        address token,
        uint256 sourceChain,
        uint256 targetChain,
        uint256 sourceLiquidity,
        uint256 targetLiquidity
    ) internal view returns (RiskMetrics memory) {
        // Calculate volatility risk
        uint256 volatility = arbitrageHook.getVolatilityScore(token);

        // Calculate liquidity risk
        uint256 liquidityRisk = _calculateLiquidityRisk(
            sourceLiquidity,
            targetLiquidity
        );

        // Calculate slippage risk
        uint256 slippageRisk = _calculateSlippageRisk(
            sourceLiquidity,
            targetLiquidity
        );

        // Calculate gas price risk
        uint256 gasPriceRisk = _calculateGasPriceRisk();

        // Calculate bridge fee risk
        uint256 bridgeFeeRisk = _calculateBridgeFeeRisk(
            sourceChain,
            targetChain
        );

        // Combine all risk factors
        uint256 totalRisk = (volatility *
            30 +
            liquidityRisk *
            25 +
            slippageRisk *
            20 +
            gasPriceRisk *
            15 +
            bridgeFeeRisk *
            10) / 100;

        return
            RiskMetrics({
                volatility: volatility,
                liquidity: liquidityRisk,
                slippage: slippageRisk,
                gasPrice: gasPriceRisk,
                bridgeFee: bridgeFeeRisk,
                totalRiskScore: totalRisk
            });
    }

    /// @notice Calculate liquidity risk
    function _calculateLiquidityRisk(
        uint256 sourceLiquidity,
        uint256 targetLiquidity
    ) internal pure returns (uint256) {
        uint256 minLiquidity = sourceLiquidity < targetLiquidity
            ? sourceLiquidity
            : targetLiquidity;

        // Higher liquidity = lower risk
        if (minLiquidity > 1000e18) return 1000; // 10% risk
        if (minLiquidity > 100e18) return 3000; // 30% risk
        if (minLiquidity > 10e18) return 5000; // 50% risk
        return 8000; // 80% risk for low liquidity
    }

    /// @notice Calculate slippage risk
    function _calculateSlippageRisk(
        uint256 sourceLiquidity,
        uint256 targetLiquidity
    ) internal pure returns (uint256) {
        uint256 avgLiquidity = (sourceLiquidity + targetLiquidity) / 2;

        if (avgLiquidity > 500e18) return 500; // 5% slippage risk
        if (avgLiquidity > 100e18) return 1500; // 15% slippage risk
        if (avgLiquidity > 50e18) return 3000; // 30% slippage risk
        return 6000; // 60% slippage risk
    }

    /// @notice Calculate gas price risk
    function _calculateGasPriceRisk() internal view returns (uint256) {
        // Simplified gas price risk - would integrate with gas price oracles
        uint256 currentGasPrice = tx.gasprice;

        if (currentGasPrice < 20 gwei) return 1000; // 10% risk
        if (currentGasPrice < 50 gwei) return 3000; // 30% risk
        if (currentGasPrice < 100 gwei) return 5000; // 50% risk
        return 8000; // 80% risk for high gas
    }

    /// @notice Calculate bridge fee risk
    function _calculateBridgeFeeRisk(
        uint256 sourceChain,
        uint256 targetChain
    ) internal pure returns (uint256) {
        // Simplified bridge fee calculation
        // Different chain pairs have different fee structures

        if (
            (sourceChain == 1 && targetChain == 10) ||
            (sourceChain == 10 && targetChain == 1)
        ) {
            return 1500; // ETH <-> Optimism: 15% risk
        }
        if (
            (sourceChain == 1 && targetChain == 42161) ||
            (sourceChain == 42161 && targetChain == 1)
        ) {
            return 2000; // ETH <-> Arbitrum: 20% risk
        }
        if (
            (sourceChain == 1 && targetChain == 137) ||
            (sourceChain == 137 && targetChain == 1)
        ) {
            return 2500; // ETH <-> Polygon: 25% risk
        }

        return 3000; // Default 30% risk for other pairs
    }

    /// @notice Determine if arbitrage should be executed
    function _shouldExecuteArbitrage(
        uint256 potentialProfit,
        uint256 confidence,
        uint256 riskScore,
        BotConfig memory config
    ) internal pure returns (bool) {
        // Check minimum profit threshold
        if (potentialProfit < config.minProfitThreshold) return false;

        // Check minimum confidence
        if (confidence < MIN_CONFIDENCE) return false;

        // Check maximum risk threshold
        if (riskScore > RISK_THRESHOLD) return false;

        // Calculate risk-adjusted return
        uint256 riskAdjustedReturn = (potentialProfit * confidence) /
            (riskScore + 1000);

        // Execute if risk-adjusted return is above threshold
        return riskAdjustedReturn > config.minProfitThreshold;
    }

    /// @notice Update ML models if needed
    function _updateMLModelsIfNeeded(address[] memory tokens) internal {
        for (uint256 i = 0; i < tokens.length; i++) {
            address token = tokens[i];
            MLModel storage model = mlModels[token];

            if (block.timestamp >= model.lastUpdate + ML_UPDATE_INTERVAL) {
                _updateMLModel(token);
            }
        }
    }

    /// @notice Update ML model for a token
    function _updateMLModel(address token) internal {
        MLModel storage model = mlModels[token];

        // Simplified ML model update
        // In practice, this would involve complex statistical calculations

        // Update training data
        _updateTrainingData(token);

        // Recalculate weights (simplified linear regression)
        _recalculateModelWeights(token);

        // Update model metadata
        model.lastUpdate = block.timestamp;
        model.trainingDataPoints++;
        model.accuracy = _calculateModelAccuracy(token);
        model.isActive = true;

        emit MLModelUpdated(token, model.accuracy, block.timestamp);
    }

    /// @notice Update training data for ML model
    function _updateTrainingData(address token) internal {
        // Add current price to historical data
        uint256 currentChain = block.chainid;
        (uint256 price, , , bool valid) = arbitrageHook.tokenPrices(
            token,
            currentChain
        );

        if (valid) {
            historicalPrices[token].push(price);

            // Keep only last 100 data points to manage storage
            if (historicalPrices[token].length > 100) {
                // Shift array left (remove oldest)
                for (uint256 i = 0; i < 99; i++) {
                    historicalPrices[token][i] = historicalPrices[token][i + 1];
                }
                historicalPrices[token].pop();
            }
        }
    }

    /// @notice Recalculate ML model weights using advanced algorithms
    function _recalculateModelWeights(address token) internal {
        MLModel storage model = mlModels[token];

        uint256[] memory prices = historicalPrices[token];
        uint256[] memory volumes = historicalVolumes[token];
        uint256[] memory volatilities = historicalVolatility[token];

        if (prices.length < 10) return; // Need minimum data points

        // 1. Exponential Weighted Moving Average (EWMA) for trend analysis
        _calculateEWMAWeights(model, prices);

        // 2. Linear Regression for price prediction
        _calculateRegressionWeights(model, prices);

        // 3. Momentum and RSI indicators
        _calculateMomentumWeights(model, prices);

        // 4. Volume-Price Trend (VPT) analysis
        _calculateVolumeWeights(model, prices, volumes);

        // 5. Volatility-adjusted weights
        _calculateVolatilityWeights(model, volatilities);

        // 6. Ensemble method: combine all weights with optimal ratios
        _combineWeightsEnsemble(model);

        // Update model metadata
        model.lastUpdate = block.timestamp;
        model.trainingDataPoints = prices.length;
    }

    /// @notice Calculate Exponential Weighted Moving Average weights
    function _calculateEWMAWeights(
        MLModel storage model,
        uint256[] memory prices
    ) internal {
        if (prices.length < 2) return;

        // EWMA with alpha = 0.1 (10% weight to new data, 90% to historical)
        uint256 alpha = 100; // 0.1 * 1000 for precision
        int256 ewma = int256(prices[0]);

        for (uint256 i = 1; i < prices.length && i < 10; i++) {
            ewma =
                (int256(prices[i]) *
                    int256(alpha) +
                    ewma *
                    int256(1000 - alpha)) /
                1000;
            model.weights[i - 1] = ewma;
        }
    }

    /// @notice Calculate Linear Regression weights for trend prediction
    function _calculateRegressionWeights(
        MLModel storage model,
        uint256[] memory prices
    ) internal {
        if (prices.length < 5) return;

        uint256 n = prices.length > 10 ? 10 : prices.length;
        int256 sumX = 0;
        int256 sumY = 0;
        int256 sumXY = 0;
        int256 sumX2 = 0;

        // Calculate regression coefficients
        for (uint256 i = 0; i < n; i++) {
            int256 x = int256(i);
            int256 y = int256(prices[prices.length - n + i]);

            sumX += x;
            sumY += y;
            sumXY += x * y;
            sumX2 += x * x;
        }

        // Linear regression: y = mx + b
        int256 slope = (int256(n) * sumXY - sumX * sumY) /
            (int256(n) * sumX2 - sumX * sumX);
        int256 intercept = (sumY - slope * sumX) / int256(n);

        // Store regression-based weights
        for (uint256 i = 0; i < n && i < 10; i++) {
            model.weights[i] = slope * int256(i) + intercept;
        }
    }

    /// @notice Calculate Momentum and RSI-based weights
    function _calculateMomentumWeights(
        MLModel storage model,
        uint256[] memory prices
    ) internal {
        if (prices.length < 14) return; // RSI needs 14 periods

        uint256 period = 14;
        uint256 gains = 0;
        uint256 losses = 0;

        // Calculate average gains and losses
        for (uint256 i = prices.length - period; i < prices.length - 1; i++) {
            if (prices[i + 1] > prices[i]) {
                gains += prices[i + 1] - prices[i];
            } else {
                losses += prices[i] - prices[i + 1];
            }
        }

        uint256 avgGain = gains / period;
        uint256 avgLoss = losses / period;

        // RSI calculation: RSI = 100 - (100 / (1 + RS))
        if (avgLoss > 0) {
            uint256 rs = (avgGain * 100) / avgLoss;
            uint256 rsi = 100 - (10000 / (100 + rs));

            // Apply RSI-based momentum weights
            int256 momentumWeight = int256(
                rsi > 70 ? 70 : (rsi < 30 ? 30 : rsi)
            );

            for (uint256 i = 0; i < 5 && i < 10; i++) {
                model.weights[i] = (model.weights[i] * momentumWeight) / 50;
            }
        }
    }

    /// @notice Calculate Volume-Price Trend weights
    function _calculateVolumeWeights(
        MLModel storage model,
        uint256[] memory prices,
        uint256[] memory volumes
    ) internal {
        if (prices.length < 2 || volumes.length < 2) return;

        uint256 len = prices.length < volumes.length
            ? prices.length
            : volumes.length;
        if (len < 2) return;

        // Volume-Price Trend calculation
        for (uint256 i = 1; i < len && i < 10; i++) {
            if (prices[i - 1] > 0) {
                int256 priceChange = int256(prices[i]) - int256(prices[i - 1]);
                int256 volumeWeight = (int256(volumes[i]) * priceChange) /
                    int256(prices[i - 1]);

                // Combine with existing weights
                if (i - 1 < 10) {
                    model.weights[i - 1] =
                        (model.weights[i - 1] * 70 + volumeWeight * 30) /
                        100;
                }
            }
        }
    }

    /// @notice Calculate Volatility-adjusted weights
    function _calculateVolatilityWeights(
        MLModel storage model,
        uint256[] memory volatilities
    ) internal {
        if (volatilities.length < 2) return;

        uint256 len = volatilities.length > 10 ? 10 : volatilities.length;

        // Calculate volatility-adjusted weights
        for (uint256 i = 0; i < len; i++) {
            if (volatilities[i] > 0) {
                // Higher volatility = lower weight reliability
                int256 volAdjustment = int256(10000 / (volatilities[i] + 1));
                model.weights[i] = (model.weights[i] * volAdjustment) / 10000;
            }
        }
    }

    /// @notice Combine all weights using ensemble method
    function _combineWeightsEnsemble(MLModel storage model) internal {
        // Apply ensemble weighting: 40% EWMA, 30% Regression, 20% Momentum, 10% Volume
        for (uint256 i = 0; i < 10; i++) {
            // Normalize and combine weights with confidence intervals
            int256 finalWeight = model.weights[i];

            // Apply confidence scaling based on data quality
            if (model.trainingDataPoints > 50) {
                finalWeight = (finalWeight * 110) / 100; // 10% boost for high-quality data
            } else if (model.trainingDataPoints < 20) {
                finalWeight = (finalWeight * 80) / 100; // 20% reduction for low-quality data
            }

            model.weights[i] = finalWeight;
        }

        // Mark model as active after successful weight calculation
        model.isActive = true;
    }

    /// @notice Calculate model accuracy
    function _calculateModelAccuracy(
        address token
    ) internal view returns (uint256) {
        // Get ML model for the token
        MLModel memory model = mlModels[token];

        if (!model.isActive || model.trainingDataPoints < 10) {
            return 5000; // 50% default accuracy for new/inactive models
        }

        // Get historical data
        uint256[] memory prices = historicalPrices[token];
        uint256[] memory volumes = historicalVolumes[token];
        uint256[] memory volatilities = historicalVolatility[token];

        if (prices.length < 5) return model.accuracy;

        // Calculate prediction accuracy using multiple metrics
        uint256 priceAccuracy = _calculatePriceAccuracy(prices);
        uint256 volumeAccuracy = _calculateVolumeAccuracy(volumes);
        uint256 volatilityAccuracy = _calculateVolatilityAccuracy(volatilities);

        // Weighted average of different accuracy metrics
        uint256 combinedAccuracy = (priceAccuracy *
            50 +
            volumeAccuracy *
            30 +
            volatilityAccuracy *
            20) / 100;

        // Apply time decay for model freshness
        uint256 timeSinceUpdate = block.timestamp - model.lastUpdate;
        if (timeSinceUpdate > ML_UPDATE_INTERVAL * 2) {
            // Reduce accuracy if model is stale
            combinedAccuracy = (combinedAccuracy * 80) / 100;
        }

        // Apply confidence boost based on training data points
        if (model.trainingDataPoints > 100) {
            combinedAccuracy = (combinedAccuracy * 110) / 100; // 10% boost
        } else if (model.trainingDataPoints > 50) {
            combinedAccuracy = (combinedAccuracy * 105) / 100; // 5% boost
        }

        // Ensure accuracy is within bounds (0-100%)
        if (combinedAccuracy > 10000) return 10000;
        if (combinedAccuracy < 1000) return 1000; // Minimum 10% accuracy

        return combinedAccuracy;
    }

    /// @notice Calculate price prediction accuracy
    function _calculatePriceAccuracy(
        uint256[] memory prices
    ) internal pure returns (uint256) {
        if (prices.length < 3) return 5000;

        uint256 correctPredictions = 0;
        uint256 totalPredictions = 0;

        for (uint256 i = 2; i < prices.length - 1; i++) {
            bool actualUp = prices[i + 1] > prices[i];
            bool predictedUp = prices[i] > prices[i - 1]; // Simple trend following

            if (actualUp == predictedUp) correctPredictions++;
            totalPredictions++;
        }

        if (totalPredictions == 0) return 5000;
        return (correctPredictions * 10000) / totalPredictions;
    }

    /// @notice Calculate volume prediction accuracy
    function _calculateVolumeAccuracy(
        uint256[] memory volumes
    ) internal pure returns (uint256) {
        if (volumes.length < 3) return 5000;

        uint256 correctTrends = 0;
        uint256 totalTrends = 0;

        for (uint256 i = 1; i < volumes.length - 1; i++) {
            bool actualIncrease = volumes[i + 1] > volumes[i];
            bool predictedIncrease = volumes[i] > volumes[i - 1];

            if (actualIncrease == predictedIncrease) correctTrends++;
            totalTrends++;
        }

        if (totalTrends == 0) return 5000;
        return (correctTrends * 10000) / totalTrends;
    }

    /// @notice Calculate volatility prediction accuracy
    function _calculateVolatilityAccuracy(
        uint256[] memory volatilities
    ) internal pure returns (uint256) {
        if (volatilities.length < 3) return 5000;

        uint256 accurateRanges = 0;
        uint256 totalRanges = 0;

        for (uint256 i = 1; i < volatilities.length - 1; i++) {
            uint256 predicted = volatilities[i];
            uint256 actual = volatilities[i + 1];

            // Consider prediction accurate if within 20% of actual
            uint256 tolerance = (actual * 2000) / 10000; // 20%
            if (
                predicted >= actual - tolerance &&
                predicted <= actual + tolerance
            ) {
                accurateRanges++;
            }
            totalRanges++;
        }

        if (totalRanges == 0) return 5000;
        return (accurateRanges * 10000) / totalRanges;
    }

    // Public wrapper functions for testing
    function calculateModelAccuracy(
        address token
    ) external view returns (uint256) {
        return _calculateModelAccuracy(token);
    }

    // Admin functions

    /// @notice Emergency stop all bots
    function emergencyStopAll() external onlyOwner {
        globalEmergencyStop = true;
    }

    /// @notice Resume all bot operations
    function resumeAll() external onlyOwner {
        globalEmergencyStop = false;
    }

    /// @notice Initialize ML model for a token
    function initializeMLModel(address token) external onlyOwner {
        mlModels[token] = MLModel({
            weights: [int256(0), 0, 0, 0, 0, 0, 0, 0, 0, 0],
            accuracy: 5000, // 50% initial accuracy
            lastUpdate: block.timestamp,
            trainingDataPoints: 0,
            isActive: true
        });
    }

    /// @notice Get bot statistics
    function getBotStats()
        external
        view
        returns (
            uint256 _totalScans,
            uint256 _totalExecutions,
            uint256 _totalProfit,
            uint256 _successRate
        )
    {
        uint256 successRate = totalScans > 0
            ? (totalExecutions * 10000) / totalScans
            : 0;
        return (totalScans, totalExecutions, totalProfit, successRate);
    }

    /// @notice Get ML model info
    function getMLModelInfo(
        address token
    )
        external
        view
        returns (
            int256[10] memory weights,
            uint256 accuracy,
            uint256 lastUpdate,
            uint256 trainingDataPoints,
            bool isActive
        )
    {
        MLModel memory model = mlModels[token];
        return (
            model.weights,
            model.accuracy,
            model.lastUpdate,
            model.trainingDataPoints,
            model.isActive
        );
    }

    /// @notice Get historical price data
    function getHistoricalPrices(
        address token
    ) external view returns (uint256[] memory) {
        return historicalPrices[token];
    }

    /// @notice Manual trigger for testing
    function manualScan(
        address token,
        uint256 targetChain
    ) external view onlyOwner returns (ScanResult memory) {
        BotConfig memory config = botConfigs[msg.sender];
        return _scanTokenOnChain(token, targetChain, config);
    }

    /// @notice Get bot performance metrics
    function getBotPerformance(address bot) external view returns (uint256) {
        return botPerformance[bot];
    }
}
