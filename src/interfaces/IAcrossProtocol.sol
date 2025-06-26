// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title IAcrossProtocol
/// @notice Interface for integrating with Across Protocol for crosschain bridging
/// @dev Defines the essential functions needed for crosschain arbitrage operations
interface IAcrossProtocol {
    // Events
    event DepositMade(
        address indexed depositor,
        address indexed recipient,
        address indexed inputToken,
        address outputToken,
        uint256 inputAmount,
        uint256 outputAmount,
        uint256 destinationChainId,
        uint32 depositId,
        uint32 quoteTimestamp,
        uint256 fillDeadline,
        uint256 exclusivityDeadline,
        address exclusiveRelayer,
        bytes message
    );

    event FundsDeposited(
        uint256 amount,
        uint256 originChainId,
        uint256 destinationChainId,
        uint256 relayerFeePct,
        uint32 depositId,
        uint32 quoteTimestamp,
        address inputToken,
        address outputToken,
        address depositor,
        address recipient,
        bytes message
    );

    event FilledRelay(
        uint256 amount,
        uint256 totalFilledAmount,
        uint256 fillAmount,
        uint256 repaymentChainId,
        uint256 originChainId,
        uint256 destinationChainId,
        int64 relayerFeePct,
        int64 realizedLpFeePct,
        uint32 depositId,
        address inputToken,
        address outputToken,
        address depositor,
        address recipient,
        address relayer,
        bool isSlowRelay
    );

    // Structs
    struct DepositData {
        address inputToken;
        address outputToken;
        uint256 inputAmount;
        uint256 outputAmount;
        uint256 destinationChainId;
        address recipient;
        address depositor;
        uint32 quoteTimestamp;
        uint256 fillDeadline;
        uint256 exclusivityDeadline;
        bytes message;
    }

    struct RelayData {
        address depositor;
        address recipient;
        address inputToken;
        address outputToken;
        uint256 inputAmount;
        uint256 outputAmount;
        uint256 originChainId;
        uint32 depositId;
        uint256 fillDeadline;
        uint256 exclusivityDeadline;
        bytes message;
    }

    struct SpokePoolLeaf {
        bool enabled;
        uint32 lastUpdateTime;
        address spokePool;
        uint256 chainId;
    }

    /// @notice Deposit tokens to be bridged to another chain
    /// @param recipient Address that will receive tokens on destination chain
    /// @param inputToken Token being deposited on origin chain
    /// @param outputToken Token to be received on destination chain
    /// @param inputAmount Amount of input tokens to deposit
    /// @param outputAmount Amount of output tokens to receive
    /// @param destinationChainId Chain ID where tokens should be received
    /// @param exclusiveRelayer Relayer that has exclusive right to fill this deposit
    /// @param quoteTimestamp Timestamp of the quote for this deposit
    /// @param fillDeadline Latest timestamp that this deposit can be filled
    /// @param exclusivityDeadline Latest timestamp that the exclusive relayer can fill
    /// @param message Arbitrary message to be passed to recipient
    function depositV3(
        address recipient,
        address inputToken,
        address outputToken,
        uint256 inputAmount,
        uint256 outputAmount,
        uint256 destinationChainId,
        address exclusiveRelayer,
        uint32 quoteTimestamp,
        uint256 fillDeadline,
        uint256 exclusivityDeadline,
        bytes calldata message
    ) external payable;

    /// @notice Fill a deposit on the destination chain
    /// @param relayData Data about the relay being filled
    /// @param repaymentChainId Chain ID where relayer should be repaid
    function fillRelayV3(
        RelayData calldata relayData,
        uint256 repaymentChainId
    ) external;

    /// @notice Get a quote for bridging tokens
    /// @param inputToken Token being bridged from origin chain
    /// @param outputToken Token to be received on destination chain
    /// @param inputAmount Amount of input tokens
    /// @param destinationChainId Destination chain ID
    /// @param recipient Address that will receive tokens
    /// @param message Optional message data
    /// @return outputAmount Amount of output tokens that will be received
    /// @return totalRelayFee Total fee for the relay
    /// @return quoteTimestamp Timestamp of this quote
    /// @return fillDeadline Deadline for filling this relay
    /// @return exclusivityDeadline Deadline for exclusive relayer
    function getQuote(
        address inputToken,
        address outputToken,
        uint256 inputAmount,
        uint256 destinationChainId,
        address recipient,
        bytes calldata message
    )
        external
        view
        returns (
            uint256 outputAmount,
            uint256 totalRelayFee,
            uint32 quoteTimestamp,
            uint256 fillDeadline,
            uint256 exclusivityDeadline
        );

    /// @notice Get the current relay fee for a route
    /// @param inputToken Token being bridged
    /// @param outputToken Token to be received
    /// @param destinationChainId Destination chain
    /// @return relayFeePct Relay fee as a percentage (scaled by 1e18)
    function getRelayFee(
        address inputToken,
        address outputToken,
        uint256 destinationChainId
    ) external view returns (uint64 relayFeePct);

    /// @notice Check if a route is enabled
    /// @param inputToken Input token address
    /// @param outputToken Output token address
    /// @param destinationChainId Destination chain ID
    /// @return enabled Whether the route is enabled
    function isRouteEnabled(
        address inputToken,
        address outputToken,
        uint256 destinationChainId
    ) external view returns (bool enabled);

    /// @notice Get the spoke pool address for a chain
    /// @param chainId Chain ID to get spoke pool for
    /// @return spokePool Address of the spoke pool
    function getSpokePool(
        uint256 chainId
    ) external view returns (address spokePool);

    /// @notice Get deposit details
    /// @param depositId ID of the deposit
    /// @return deposit Deposit data struct
    function getDeposit(
        uint32 depositId
    ) external view returns (DepositData memory deposit);

    /// @notice Check if a deposit has been filled
    /// @param depositId ID of the deposit to check
    /// @return filled Whether the deposit has been filled
    /// @return fillAmount Amount that has been filled
    function getDepositStatus(
        uint32 depositId
    ) external view returns (bool filled, uint256 fillAmount);

    /// @notice Get the current chain ID
    /// @return chainId Current chain ID
    function getCurrentChainId() external view returns (uint256 chainId);

    /// @notice Get supported tokens for a destination chain
    /// @param destinationChainId Destination chain ID
    /// @return inputTokens Array of supported input tokens
    /// @return outputTokens Array of corresponding output tokens
    function getSupportedTokens(
        uint256 destinationChainId
    )
        external
        view
        returns (address[] memory inputTokens, address[] memory outputTokens);

    /// @notice Get the minimum and maximum deposit amounts for a token
    /// @param token Token address
    /// @param destinationChainId Destination chain ID
    /// @return minDeposit Minimum deposit amount
    /// @return maxDeposit Maximum deposit amount
    function getDepositLimits(
        address token,
        uint256 destinationChainId
    ) external view returns (uint256 minDeposit, uint256 maxDeposit);

    /// @notice Get estimated time for a bridge transaction
    /// @param destinationChainId Destination chain ID
    /// @return estimatedTime Estimated time in seconds
    function getEstimatedFillTime(
        uint256 destinationChainId
    ) external view returns (uint256 estimatedTime);

    /// @notice Get the hub pool address
    /// @return hubPool Address of the hub pool
    function getHubPool() external view returns (address hubPool);

    /// @notice Get the current deposit ID counter
    /// @return depositId Current deposit ID
    function getCurrentDepositId() external view returns (uint32 depositId);

    /// @notice Emergency function to pause deposits
    /// @param paused Whether deposits should be paused
    function pauseDeposits(bool paused) external;

    /// @notice Emergency function to pause fills
    /// @param paused Whether fills should be paused
    function pauseFills(bool paused) external;

    /// @notice Check if deposits are currently paused
    /// @return paused Whether deposits are paused
    function areDepositsPaused() external view returns (bool paused);

    /// @notice Check if fills are currently paused
    /// @return paused Whether fills are paused
    function areFillsPaused() external view returns (bool paused);

    /// @notice Get the current root bundle ID
    /// @return rootBundleId Current root bundle ID
    function getCurrentRootBundleId()
        external
        view
        returns (uint32 rootBundleId);

    /// @notice Verify a merkle proof for a relay
    /// @param proof Merkle proof
    /// @param relayData Relay data to verify
    /// @return valid Whether the proof is valid
    function verifyRelayProof(
        bytes32[] calldata proof,
        RelayData calldata relayData
    ) external view returns (bool valid);
}
