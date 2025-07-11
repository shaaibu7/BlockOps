use dotenv::dotenv;
use std::error::Error;
use alloy::{ primitives::{Address, U256}, providers:: { ProviderBuilder}, signers::local::PrivateKeySigner, sol};
use std::{env};
use alloy::transports::http::reqwest::Url;
use blockops::{
    validation, utils, ethereum, erc20, blockchain, cli
};
use blockops::types::{
    MessageResponse,
    OPenAiRequest,
};
use blockops::utils::{
    parse_swap_config
};

use reqwest::Client;
use termimad::MadSkin;

sol!{

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();

    // Load environment variables
    let rpc_endpoint = env::var("RPC_URL").unwrap_or_else(|_| panic!("RPC url not found"));
    let env_private_key = env::var("PRIVATE_KEY").unwrap_or_else(|_| panic!("Private key not found"));
     let api_key = env::var("OPEN_AI_API_KEY")?;
    let open_ai_url = env::var("OPEN_AI_URL")?;
    let router_address = env::var("ROUTER_ADDR").unwrap_or_else(|_| panic!("Private Key not found"));
    let  skin = MadSkin::default();
    // Validate environment private key
    let validated_env_private_key = match validation::validate_private_key(&env_private_key) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("❌ Environment Variable Validation Error: {}", e);
            eprintln!("💡 Please check your .env file and ensure PRIVATE_KEY is valid");
            return Err(Box::new(e) as Box<dyn Error>);
        }
    };

    let rpc_url: Url = rpc_endpoint.parse()?;

    // Build CLI and parse arguments
    let cli = cli::build_cli();
    let matches = cli.get_matches();

    // Handle Ethereum operations
    if let Some((balance_check, transaction_config)) = cli::parse_ethereum_config(&matches) {
        if let Some(wallet_address) = balance_check {
            // Check balance
            let provider = utils::setup_provider(&rpc_url).await?;
            ethereum::check_balance(&provider, &wallet_address).await?;
        } else if let Some((private_key, config)) = transaction_config {
            // Send transaction
            let provider = utils::setup_provider_with_signer(&rpc_url, &private_key).await?;
            ethereum::send_transaction(&provider, &private_key, config).await?;
        }
    }

    // Handle ERC20 operations
    if let Some((token_address, operation)) = cli::parse_erc20_config(&matches) {
        match operation {
            cli::ERC20Operation::CheckBalance(holder_address) => {
                let provider = utils::setup_provider(&rpc_url).await?;
                erc20::check_balance(&provider, &token_address, &holder_address).await?;
            }
            cli::ERC20Operation::CheckAllowance(owner_address, spender_address) => {
                let provider = utils::setup_provider(&rpc_url).await?;
                erc20::check_allowance(&provider, &token_address, &owner_address, &spender_address).await?;
            }
            cli::ERC20Operation::Transfer(config) => {
                let provider = utils::setup_provider_with_signer(&rpc_url, &validated_env_private_key).await?;
                erc20::transfer_tokens(&provider, &token_address, config).await?;
            }
        }
    }

    // Handle block query operations
    if let Some(config) = cli::parse_block_query_config(&matches) {
        let provider = utils::setup_provider(&rpc_url).await?;
        blockchain::query_block(&provider, config).await?;
    }
    
    if let  Some(("chat", arg_matches)) = matches.subcommand() {
            if let Some(cmd_argument) = arg_matches.get_one::<String>("cmd_arg"){
            let body =    OPenAiRequest{
                model: "gpt-4o-mini".to_string(),
                messages: vec![
                    MessageResponse{
                       role:  "user".to_string(),
                        content: cmd_argument.clone()
                    }
                ]
            };
            let client = Client::new();

            let res = client
            .post(open_ai_url)
            .bearer_auth(api_key)
            .json(&body)
            .send()
            .await?;

            let json_response:  serde_json::Value = res.json().await?;
            let content = json_response["choices"][0]["message"]["content"].as_str().unwrap_or("No response from open AI");
            skin.print_text(content);
            }
        
    }

    if let Some(("swap", swap_matches)) = matches.subcommand(){

        let config = parse_swap_config(swap_matches).unwrap();
        let router_addr: Address = router_address.parse().expect("Not a valid addresss");

        let private_key : PrivateKeySigner = config.private_key.parse()?;

        let provider = ProviderBuilder::new()
        .wallet(private_key.clone())
        .connect_http(rpc_url.clone());
        
        let signer_address = private_key.address();
        println!("Signer address: {:?}", signer_address);
        println!("Config.recipient: {:?}", config.recipient);

        // Check if pool exists first
        let factory = UniswapV3Factory::new("0x0227628f3F023bb0B980b67D528571c95c6DaC1c".parse()?, &provider);
        let fee: u32 = config.fee_tier.try_into().expect("fee_tier too large for u32");
        let fee_uint24 = alloy::primitives::Uint::<24, 1>::from_limbs([fee as u64]);
        let pool = factory.getPool(config.token_in, config.token_out, fee_uint24).call().await?;
        println!("Pool address: {:?}", pool);
        if pool == Address::ZERO {
            println!("Pool does not exist for this token pair and fee tier!");
            println!("Try different fee tiers: 500 (0.05%), 3000 (0.3%), 10000 (1%)");
            return Ok(());
        }
        
        let router = ISwapRouter::new(router_addr, &provider);
        let erc20 = ERC20::new(config.token_in, provider.clone());
        let balance = erc20.balanceOf(config.recipient).call().await?;
        println!("USDC Balance: {:?}", balance);
        
        let allowance = erc20.allowance(config.recipient, router_addr).call().await?;
        println!("Allowance: {:?}", allowance);

        if allowance < config.amount_in{
            println!("Owner: {:?}", config.recipient);
            let receipt = erc20.approve(router_addr, config.amount_in).send().await?.get_receipt().await?;
            println!("Approval Transaction Receipt: {:?}", receipt);
        }

        let min_amount_out = config.amount_in * U256::from(10000 - config.slippage_bps) / U256::from(10000);

        let deadlines = U256::from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() + config.deadline_seconds);
        let fee: u32 = config.fee_tier.try_into().expect("fee_tier too large for u32");
        let fee_uint24 = alloy::primitives::Uint::<24, 1>::from_limbs([fee as u64]);
        let sqrt_price_limit = alloy::primitives::Uint::<160, 3>::from_limbs([0u64, 0u64, 0u64]);
        
        let params = ISwapRouter::ExactInputSingleParams{
            tokenIn: config.token_in,
            tokenOut: config.token_out,
            fee: fee_uint24,
            recipient: config.recipient,
            deadline: deadlines,
            amountIn: config.amount_in,
            amountOutMinimum:min_amount_out,
            sqrtPriceLimitX96: sqrt_price_limit
        };
        println!("Params: {:?}", params);
        
        match router.exactInputSingle(params.clone()).estimate_gas().await {
            Ok(gas_estimate) => println!("Gas Estimate: {:?}", gas_estimate),
            Err(e) => {
                println!("Gas estimation failed: {:?}", e);
                // println!("This might indicate the pool has no liquidity or the parameters are invalid");
                return Ok(());
            }
        }
        
        let tx = router.exactInputSingle(params).send().await?;
        let receipt = tx.get_receipt().await?;
        println!("Swap successful! Transaction hash: {:?}", receipt.transaction_hash);

    }

    Ok(())
} 