use dotenv::dotenv;
use std::error::Error;
use std::env;
use alloy::transports::http::reqwest::Url;

use blockops::{
    validation, utils, ethereum, erc20, blockchain, cli
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();

    // Load environment variables
    let rpc_endpoint = env::var("RPC_URL").unwrap_or_else(|_| panic!("RPC url not found"));
    let env_private_key = env::var("PRIVATE_KEY").unwrap_or_else(|_| panic!("Private key not found"));
    
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

    Ok(())
} 