use alloy::sol;

sol! {
    #[sol(rpc)]
    contract ERC20 {
        function balanceOf(address owner) public view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
        function transfer(address to, uint256 value) external returns (bool);
        function approve(address spender, uint256 value) external returns (bool);
        function transferFrom(address from, address to, uint256 value) external returns (bool);
    }

    #[sol(rpc)]
    contract ISwapRouter {
        #[derive(Debug)]
        struct ExactInputSingleParams {
            address tokenIn;
            address tokenOut;
            uint24 fee;
            address recipient;
            uint256 deadline;
            uint256 amountIn;
            uint256 amountOutMinimum;
            uint160 sqrtPriceLimitX96;
        }
        function exactInputSingle(ExactInputSingleParams calldata params)
            external payable returns (uint256 amountOut);
    }

    #[sol(rpc)]
    contract UniswapV3Factory {
        function getPool(address tokenA, address tokenB, uint24 fee) external view returns (address pool);
    }
}