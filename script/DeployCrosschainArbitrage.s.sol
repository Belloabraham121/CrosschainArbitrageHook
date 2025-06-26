// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {CrosschainArbitrageHook} from "../src/PointsHook.sol";
import {ArbitrageBot} from "../src/ArbitrageBot.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";

contract DeployCrosschainArbitrage is Script {
    struct NetworkConfig {
        address poolManager;
        address acrossProtocol;
        string name;
        uint256 chainId;
    }

    // Deployment addresses (will be populated during deployment)
    address public crosschainArbitrageHook;
    address public arbitrageBot;

    // Configuration constants
    uint256 private constant DEFAULT_SCAN_INTERVAL = 300;
    uint256 private constant DEFAULT_MAX_GAS_PRICE = 100 gwei;
    uint256 private constant DEFAULT_MIN_PROFIT = 0.01 ether;
    uint256 private constant DEFAULT_MAX_POSITION = 10 ether;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying Crosschain Arbitrage system...");
        console.log("Deployer address:", deployer);
        console.log("Chain ID:", block.chainid);

        vm.startBroadcast(deployerPrivateKey);

        NetworkConfig memory config = getNetworkConfig();

        crosschainArbitrageHook = deployArbitrageHook(config);

        arbitrageBot = deployArbitrageBot();

        configureSystem(config);

        vm.stopBroadcast();

        logDeploymentInfo(config);
    }

    /// @notice Deploy the Crosschain Arbitrage Hook
    function deployArbitrageHook(
        NetworkConfig memory config
    ) internal returns (address) {
        console.log("Deploying CrosschainArbitrageHook...");

        // Calculate the hook address using CREATE2 for deterministic deployment
        bytes32 salt = keccak256(
            abi.encodePacked("CrosschainArbitrageHook", block.chainid)
        );

        CrosschainArbitrageHook hook = new CrosschainArbitrageHook{salt: salt}(
            IPoolManager(config.poolManager),
            config.acrossProtocol
        );

        console.log("CrosschainArbitrageHook deployed at:", address(hook));

        // Verify hook permissions
        Hooks.Permissions memory permissions = hook.getHookPermissions();
        require(permissions.beforeSwap, "beforeSwap permission not set");
        require(permissions.afterSwap, "afterSwap permission not set");

        console.log("Hook permissions verified successfully");

        return address(hook);
    }

    /// @notice Deploy the Arbitrage Bot
    function deployArbitrageBot() internal returns (address) {
        console.log("Deploying ArbitrageBot...");

        ArbitrageBot bot = new ArbitrageBot(crosschainArbitrageHook);

        console.log("ArbitrageBot deployed at:", address(bot));

        return address(bot);
    }

    /// @notice Configure the deployed system
    function configureSystem(NetworkConfig memory config) internal {
        console.log("Configuring system...");

        CrosschainArbitrageHook hook = CrosschainArbitrageHook(
            crosschainArbitrageHook
        );
        ArbitrageBot bot = ArbitrageBot(arbitrageBot);

        // Add the bot as an authorized bot in the hook
        hook.addAuthorizedBot(arbitrageBot);
        console.log("Bot authorized in hook");

        // Configure bot settings
        address[] memory targetTokens = getTargetTokens();
        uint256[] memory targetChains = getTargetChains();

        bot.configureBotConfig(
            address(this), // Bot operator (deployer)
            DEFAULT_SCAN_INTERVAL,
            DEFAULT_MAX_GAS_PRICE,
            DEFAULT_MIN_PROFIT,
            DEFAULT_MAX_POSITION,
            targetTokens,
            targetChains
        );
        console.log("Bot configuration set");

        // Initialize ML models for target tokens
        for (uint256 i = 0; i < targetTokens.length; i++) {
            bot.initializeMLModel(targetTokens[i]);
            console.log("ML model initialized for token:", targetTokens[i]);
        }

        // Activate the bot
        bot.activateBot(address(this));
        console.log("Bot activated");

        console.log("System configuration completed");
    }

    /// @notice Get network-specific configuration
    function getNetworkConfig() internal view returns (NetworkConfig memory) {
        uint256 chainId = block.chainid;

        if (chainId == 1) {
            return
                NetworkConfig({
                    poolManager: 0x0000000000000000000000000000000000000000, // TODO: Update with actual address
                    acrossProtocol: 0x4D9079Bb4165aeb4084c526a32695dCfd2F77381,
                    name: "Ethereum",
                    chainId: 1
                });
        } else if (chainId == 10) {
            return
                NetworkConfig({
                    poolManager: 0x0000000000000000000000000000000000000000, // TODO: Update with actual address
                    acrossProtocol: 0xa420b2d1c0841415A695b81E5B867BCD07Dff8C9,
                    name: "Optimism",
                    chainId: 10
                });
        } else if (chainId == 42161) {
            return
                NetworkConfig({
                    poolManager: 0x0000000000000000000000000000000000000000, // TODO: Update with actual address
                    acrossProtocol: 0xe35e9842fceaCA96570B734083f4a58e8F7C5f2A,
                    name: "Arbitrum",
                    chainId: 42161
                });
        } else if (chainId == 137) {
            return
                NetworkConfig({
                    poolManager: 0x0000000000000000000000000000000000000000, // TODO: Update with actual address
                    acrossProtocol: 0x9295ee1d8C5b022Be115A2AD3c30C72E34e7F096,
                    name: "Polygon",
                    chainId: 137
                });
        } else if (chainId == 8453) {
            return
                NetworkConfig({
                    poolManager: 0x0000000000000000000000000000000000000000, // TODO: Update with actual address
                    acrossProtocol: 0x09aea4b2242abC8bb4BB78D537A67a245A7bEC64,
                    name: "Base",
                    chainId: 8453
                });
        } else if (chainId == 31337) {
            // Local/Anvil
            return
                NetworkConfig({
                    poolManager: 0x0000000000000000000000000000000000000000, // Mock address for testing
                    acrossProtocol: 0x0000000000000000000000000000000000000001, // Mock address for testing
                    name: "Local",
                    chainId: 31337
                });
        } else {
            revert("Unsupported network");
        }
    }

    /// @notice Get target tokens for arbitrage
    function getTargetTokens() internal view returns (address[] memory) {
        uint256 chainId = block.chainid;
        address[] memory tokens;

        if (chainId == 1) {
            // Ethereum tokens
            tokens = new address[](4);
            tokens[0] = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2; // WETH
            tokens[1] = 0xa0B86a33E6417c8F4c8B4B8c4b8c4b8C4B8c4b8c; // USDC
            tokens[2] = 0xdAC17F958D2ee523a2206206994597C13D831ec7; // USDT
            tokens[3] = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599; // WBTC
        } else if (chainId == 10) {
            // Optimism tokens
            tokens = new address[](4);
            tokens[0] = 0x4200000000000000000000000000000000000006; // WETH
            tokens[1] = 0x7F5c764cBc14f9669B88837ca1490cCa17c31607; // USDC
            tokens[2] = 0x94b008aA00579c1307B0EF2c499aD98a8ce58e58; // USDT
            tokens[3] = 0x68f180fcCe6836688e9084f035309E29Bf0A2095; // WBTC
        } else if (chainId == 42161) {
            // Arbitrum tokens
            tokens = new address[](4);
            tokens[0] = 0x82aF49447D8a07e3bd95BD0d56f35241523fBab1; // WETH
            tokens[1] = 0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8; // USDC
            tokens[2] = 0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9; // USDT
            tokens[3] = 0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f; // WBTC
        } else if (chainId == 137) {
            // Polygon tokens
            tokens = new address[](4);
            tokens[0] = 0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619; // WETH
            tokens[1] = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174; // USDC
            tokens[2] = 0xc2132D05D31c914a87C6611C10748AEb04B58e8F; // USDT
            tokens[3] = 0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6; // WBTC
        } else {
            // Default/test tokens
            tokens = new address[](2);
            tokens[0] = 0x0000000000000000000000000000000000000001;
            tokens[1] = 0x0000000000000000000000000000000000000002;
        }

        return tokens;
    }

    /// @notice Get target chains for arbitrage
    function getTargetChains() internal pure returns (uint256[] memory) {
        uint256[] memory chains = new uint256[](5);
        chains[0] = 1; // Ethereum
        chains[1] = 10; // Optimism
        chains[2] = 42161; // Arbitrum
        chains[3] = 137; // Polygon
        chains[4] = 8453; // Base
        return chains;
    }

    /// @notice Log deployment information
    function logDeploymentInfo(NetworkConfig memory config) internal view {
        console.log("\n=== DEPLOYMENT SUMMARY ===");
        console.log("Network:", config.name);
        console.log("Chain ID:", config.chainId);
        console.log("Pool Manager:", config.poolManager);
        console.log("Across Protocol:", config.acrossProtocol);
        console.log("\n=== DEPLOYED CONTRACTS ===");
        console.log("CrosschainArbitrageHook:", crosschainArbitrageHook);
        console.log("ArbitrageBot:", arbitrageBot);
        console.log("\n=== CONFIGURATION ===");
        console.log("Scan Interval:", DEFAULT_SCAN_INTERVAL, "seconds");
        console.log("Max Gas Price:", DEFAULT_MAX_GAS_PRICE / 1 gwei, "gwei");
        console.log(
            "Min Profit Threshold:",
            DEFAULT_MIN_PROFIT / 1 ether,
            "ETH"
        );
        console.log(
            "Max Position Size:",
            DEFAULT_MAX_POSITION / 1 ether,
            "ETH"
        );
        console.log("\n=== NEXT STEPS ===");
        console.log("1. Update Pool Manager addresses in network config");
        console.log("2. Verify Across Protocol addresses are correct");
        console.log("3. Fund the bot with initial capital");
        console.log("4. Monitor bot performance and adjust parameters");
        console.log("5. Set up monitoring and alerting systems");
        console.log("\n=== VERIFICATION COMMANDS ===");
        console.log(
            "forge verify-contract",
            crosschainArbitrageHook,
            "src/PointsHook.sol:CrosschainArbitrageHook"
        );
        console.log(
            "forge verify-contract",
            arbitrageBot,
            "src/ArbitrageBot.sol:ArbitrageBot"
        );
    }

    /// @notice Helper function to deploy on multiple networks
    function deployMultichain() external pure {
        uint256[] memory chainIds = new uint256[](5);
        chainIds[0] = 1; // Ethereum
        chainIds[1] = 10; // Optimism
        chainIds[2] = 42161; // Arbitrum
        chainIds[3] = 137; // Polygon
        chainIds[4] = 8453; // Base

        for (uint256 i = 0; i < chainIds.length; i++) {
            console.log("\nDeploying on chain:", chainIds[i]);
            // Note: This would require switching networks in practice
            // vm.createSelectFork(getRpcUrl(chainIds[i]));
            // run();
        }
    }

    /// @notice Emergency function to pause the system
    function emergencyPause() external {
        require(msg.sender == tx.origin, "Only EOA");

        if (crosschainArbitrageHook != address(0)) {
            CrosschainArbitrageHook(crosschainArbitrageHook).emergencyStop();
            console.log("Hook emergency stopped");
        }

        if (arbitrageBot != address(0)) {
            ArbitrageBot(arbitrageBot).emergencyStopAll();
            console.log("Bot emergency stopped");
        }
    }

    /// @notice Function to resume operations
    function resumeOperations() external {
        require(msg.sender == tx.origin, "Only EOA");

        if (crosschainArbitrageHook != address(0)) {
            CrosschainArbitrageHook(crosschainArbitrageHook).resumeOperations();
            console.log("Hook operations resumed");
        }

        if (arbitrageBot != address(0)) {
            ArbitrageBot(arbitrageBot).resumeAll();
            console.log("Bot operations resumed");
        }
    }

    /// @notice Get deployment addresses for integration
    function getDeploymentAddresses()
        external
        view
        returns (address hook, address bot)
    {
        return (crosschainArbitrageHook, arbitrageBot);
    }
}
