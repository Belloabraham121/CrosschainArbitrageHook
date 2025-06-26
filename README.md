# Crosschain Arbitrage Hook

A sophisticated Uniswap V4 hook that identifies and exploits price discrepancies across chains by bridging assets using Across Protocol. This system combines automated price monitoring, machine learning-based prediction models, and risk management protocols to execute profitable crosschain arbitrage opportunities.

## 🚀 Features

### Core Functionality

- **Real-time Price Monitoring**: Continuously monitors token prices across multiple chains during swap operations
- **Automated Arbitrage Detection**: Identifies profitable price discrepancies using configurable thresholds
- **Crosschain Execution**: Leverages Across Protocol for fast and efficient asset bridging
- **Machine Learning Integration**: Uses ML models to predict price movements and optimize execution timing
- **Risk Management**: Comprehensive risk assessment including volatility, liquidity, and slippage analysis

### Advanced Features

- **Multi-chain Support**: Works across Ethereum, Optimism, Arbitrum, Polygon, and Base
- **Automated Bot System**: Configurable bots for continuous opportunity scanning
- **Emergency Controls**: Circuit breakers and emergency stop mechanisms
- **Performance Analytics**: Detailed tracking of arbitrage success rates and profitability
- **Gas Optimization**: Efficient execution to maximize net profits

## 📋 Table of Contents

- [Architecture](#architecture)
- [Installation](#installation)
- [Deployment](#deployment)
- [Configuration](#configuration)
- [Usage](#usage)
- [Testing](#testing)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## 🏗️ Architecture

### System Components

1. **CrosschainArbitrageHook**: Main hook contract that integrates with Uniswap V4
2. **ArbitrageBot**: Automated scanning and execution bot
3. **IAcrossProtocol**: Interface for Across Protocol integration
4. **ML Models**: Price prediction and risk assessment algorithms

### Data Flow

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Uniswap V4    │───▶│ Arbitrage Hook   │───▶│ Across Protocol │
│     Swap        │    │                  │    │    Bridge       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ Arbitrage Bot    │
                       │ - Price Monitor  │
                       │ - ML Prediction  │
                       │ - Risk Analysis  │
                       └──────────────────┘
```

### Key Contracts

#### CrosschainArbitrageHook

- Implements Uniswap V4 hook interface
- Monitors price changes in `beforeSwap` and `afterSwap`
- Detects arbitrage opportunities across chains
- Manages risk parameters and emergency controls
- Integrates with Across Protocol for bridging

#### ArbitrageBot

- Automated scanning for arbitrage opportunities
- ML-based price prediction and confidence scoring
- Risk assessment and position sizing
- Performance tracking and optimization

## 🛠️ Installation

### Prerequisites

- [Foundry](https://getfoundry.sh/) (latest version)
- [Node.js](https://nodejs.org/) (v16 or later)
- [Git](https://git-scm.com/)

### Setup

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd points-hook
   ```

2. **Install dependencies**

   ```bash
   forge install
   ```

3. **Set up environment variables**

   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Compile contracts**

   ```bash
   forge build
   ```

5. **Run tests**
   ```bash
   forge test
   ```

## 🚀 Deployment

### Environment Configuration

Create a `.env` file with the following variables:

```bash
# Deployment
PRIVATE_KEY=your_private_key_here
ETHERSCAN_API_KEY=your_etherscan_api_key

# Network RPCs
ETHERUM_RPC_URL=https://eth-mainnet.alchemyapi.io/v2/your-api-key
OPTIMISM_RPC_URL=https://opt-mainnet.g.alchemy.com/v2/your-api-key
ARBITRUM_RPC_URL=https://arb-mainnet.g.alchemy.com/v2/your-api-key
POLYGON_RPC_URL=https://polygon-mainnet.g.alchemy.com/v2/your-api-key
BASE_RPC_URL=https://base-mainnet.g.alchemy.com/v2/your-api-key

# Contract Addresses (update with actual addresses)
POOL_MANAGER_ETHEREUM=0x...
POOL_MANAGER_OPTIMISM=0x...
POOL_MANAGER_ARBITRUM=0x...
POOL_MANAGER_POLYGON=0x...
POOL_MANAGER_BASE=0x...
```

### Single Chain Deployment

```bash
# Deploy to Ethereum mainnet
forge script script/DeployCrosschainArbitrage.s.sol:DeployCrosschainArbitrage \
  --rpc-url $ETHEREUM_RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify

# Deploy to Optimism
forge script script/DeployCrosschainArbitrage.s.sol:DeployCrosschainArbitrage \
  --rpc-url $OPTIMISM_RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify
```

### Multi-chain Deployment

For deploying across multiple chains simultaneously:

```bash
# This requires manual network switching or using a deployment framework
forge script script/DeployCrosschainArbitrage.s.sol:DeployCrosschainArbitrage \
  --sig "deployMultichain()" \
  --private-key $PRIVATE_KEY
```

## ⚙️ Configuration

### Hook Configuration

```solidity
// Risk parameters
RiskParameters memory riskParams = RiskParameters({
    maxSlippage: 100,           // 1% max slippage
    minProfitThreshold: 1e16,   // 0.01 ETH minimum profit
    maxPositionSize: 100e18,    // 100 ETH max position
    volatilityThreshold: 5000,  // 50% max volatility
    emergencyStop: false
});

hook.updateRiskParameters(riskParams);
```

### Bot Configuration

```solidity
// Configure bot parameters
address[] memory targetTokens = [WETH, USDC, USDT, WBTC];
uint256[] memory targetChains = [1, 10, 42161, 137, 8453];

bot.configureBotConfig(
    botOperator,
    300,        // 5 minute scan interval
    100 gwei,   // max gas price
    0.01 ether, // min profit threshold
    10 ether,   // max position size
    targetTokens,
    targetChains
);

// Activate the bot
bot.activateBot(botOperator);
```

### ML Model Initialization

```solidity
// Initialize ML models for each target token
for (uint256 i = 0; i < targetTokens.length; i++) {
    bot.initializeMLModel(targetTokens[i]);
}
```

## 📖 Usage

### Basic Arbitrage Detection

The hook automatically monitors prices during Uniswap V4 swaps:

```solidity
// Triggered automatically during swaps
function beforeSwap(
    address sender,
    PoolKey calldata key,
    SwapParams calldata params,
    bytes calldata hookData
) external override returns (bytes4, BeforeSwapDelta, uint24) {
    // Price monitoring and arbitrage detection happens here
    _updatePriceData(key, params);
    _detectArbitrageOpportunity(key, params);
    _updatePricePrediction(Currency.unwrap(key.currency0));

    return (this.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
}
```

### Manual Bot Scanning

```solidity
// Bots can manually trigger scans
bot.scanForOpportunities();

// Or scan specific tokens/chains
ScanResult memory result = bot.manualScan(tokenAddress, targetChainId);
```

### Monitoring and Analytics

```solidity
// Get arbitrage statistics
(uint256 totalProfit, uint256 totalCount) = hook.getArbitrageStats();

// Get bot performance
uint256 botProfit = hook.getBotPerformance(botAddress);

// Get ML model accuracy
(, uint256 accuracy, , , bool isActive) = bot.getMLModelInfo(tokenAddress);
```

### Emergency Controls

```solidity
// Emergency stop all operations
hook.emergencyStop();
bot.emergencyStopAll();

// Resume operations
hook.resumeOperations();
bot.resumeAll();
```

## 🧪 Testing

### Run All Tests

```bash
forge test
```

### Run Specific Test Categories

```bash
# Test hook functionality
forge test --match-contract CrosschainArbitrageTest

# Test with verbose output
forge test -vvv

# Test with gas reporting
forge test --gas-report
```

### Test Coverage

```bash
forge coverage
```

### Integration Testing

```bash
# Test against forked networks
forge test --fork-url $ETHEREUM_RPC_URL
```

## 🔒 Security

### Security Features

1. **Access Controls**: Owner-only functions for critical operations
2. **Emergency Stops**: Circuit breakers for immediate halt of operations
3. **Risk Limits**: Configurable limits on position sizes and slippage
4. **Reentrancy Protection**: Guards against reentrancy attacks
5. **Input Validation**: Comprehensive validation of all inputs

### Security Considerations

- **Oracle Dependency**: Relies on accurate price feeds across chains
- **Bridge Risk**: Dependent on Across Protocol security and availability
- **MEV Exposure**: Arbitrage transactions may be front-run
- **Smart Contract Risk**: Standard smart contract vulnerabilities

### Audit Recommendations

1. **External Audit**: Recommend professional security audit before mainnet deployment
2. **Gradual Rollout**: Start with small position sizes and limited tokens
3. **Monitoring**: Implement comprehensive monitoring and alerting
4. **Insurance**: Consider smart contract insurance coverage

## 📊 Performance Optimization

### Gas Optimization

- Efficient storage patterns
- Batch operations where possible
- Optimized loop structures
- Minimal external calls

### Execution Optimization

- ML-based timing optimization
- Dynamic fee calculation
- Slippage minimization
- Route optimization

## 🤝 Contributing

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Code Standards

- Follow Solidity style guide
- Add comprehensive comments
- Include unit tests
- Update documentation

### Reporting Issues

- Use GitHub issues for bug reports
- Include reproduction steps
- Provide relevant logs and error messages

## 📄 License

This project is licensed under the UNLICENSED License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Uniswap V4](https://github.com/Uniswap/v4-core) for the hook framework
- [Across Protocol](https://across.to/) for crosschain bridging infrastructure
- [Foundry](https://getfoundry.sh/) for development and testing tools

## 📞 Support

For questions and support:

- Create an issue on GitHub
- Join our Discord community
- Check the documentation wiki

---

**⚠️ Disclaimer**: This software is experimental and should be used at your own risk. Always conduct thorough testing and consider professional audits before deploying to mainnet with significant funds.
