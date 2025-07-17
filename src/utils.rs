use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    transports::http::reqwest::Url,
};
use std::error::Error;
use std::str::FromStr;


use std::{collections::HashMap, env};
use clap::{ArgMatches};
use alloy::{primitives::{U256}, signers::k256::ecdsa::SigningKey};
use alloy::{hex::decode};
use alloy::signers::local::LocalSigner;
use inquire::{Select, Text, CustomType};
use dotenv::dotenv;


/// Setup provider with signer for transactions
pub async fn setup_provider_with_signer(
    rpc_url: &Url,
    private_key: &str,
) -> Result<impl Provider, Box<dyn Error>> {
    let private_key: PrivateKeySigner = private_key.parse()?;
    let provider = ProviderBuilder::new()
        .wallet(private_key)
        .connect_http(rpc_url.clone());
    Ok(provider)
}

/// Setup provider without signer for read operations
pub async fn setup_provider(rpc_url: &Url) -> Result<impl Provider, Box<dyn Error>> {
    let provider = ProviderBuilder::new().connect_http(rpc_url.clone());
    Ok(provider)
}

/// Convert ETH amount to wei
pub fn eth_to_wei(eth_amount: f64) -> Result<u64, Box<dyn Error>> {
    let wei_amount = (eth_amount * 1e18) as u64;
    Ok(wei_amount)
}

/// Convert token amount to smallest unit (assuming 18 decimals)
pub fn token_to_smallest_unit(token_amount: f64, decimals: u8) -> Result<u64, Box<dyn Error>> {
    let multiplier = 10_f64.powi(decimals as i32);
    let smallest_unit = (token_amount * multiplier) as u64;
    Ok(smallest_unit)
}

/// Parse and validate address
pub fn parse_address(address: &str) -> Result<Address, Box<dyn Error>> {
    let address = Address::from_str(address)?;
    Ok(address)
}

/// Format balance for display
pub fn format_balance(balance: u64, decimals: u8) -> f64 {
    let divisor = 10_f64.powi(decimals as i32);
    balance as f64 / divisor
} 


pub fn get_address_from_private_key(private_key_hex: &str) -> Result<Address, String> {

    let key_str = private_key_hex.trim_start_matches("0x");
    let key_bytes = decode(key_str).map_err(|_| "Invalid hex string".to_string())?;
    if key_bytes.len() != 32 {
        return Err("Private key must be 32 bytes".to_string());
    }
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    let signing_key = SigningKey::from_bytes((&key_array).into())
        .map_err(|_| "Invalid private key bytes".to_string())?;
    let signer = LocalSigner::from_signing_key(signing_key);
    Ok(signer.address())
}
#[derive(Debug)]
  pub  struct SwapConfig{
    pub token_in: Address,
    pub token_out: Address,
    pub amount_in: U256,
    pub fee_tier: U256,
    pub slippage_bps: u16,
    pub deadline_seconds: u64,
    pub recipient: Address,
    pub sqrt_price_limit: U256,
    pub private_key: String
}

pub fn parse_swap_config(matches: &ArgMatches)  -> Option< SwapConfig>{
    
if let (Some(token_a),
        Some(token_b),
        Some(amount),
        Some(fee_tier),
        Some(slippage_bps),
        Some(deadline),
        Some(private_key)
    ) = (
    matches.get_one::<String>("token-in"),
    matches.get_one::<String>("token-out"),
    matches.get_one::<String>("amount-in"),
    matches.get_one::<String>("fee-tier"),
    matches.get_one::<String>("slippage-bps"),
    matches.get_one::<String>("deadline"),
    matches.get_one::<String>("private-key")
    ) {

    let user_address = get_address_from_private_key(&private_key).ok().unwrap();

    let token_address = load_tokens_address_from_env();


let config = SwapConfig{
    token_in: token_address.get(token_a.as_str()).unwrap().parse().expect("Invalid token Address for token a"),
    token_out: token_address.get(token_b.as_str()).unwrap().parse().expect("Invalid token Address for token b"),
    amount_in: U256::from(amount.parse::<u64>().expect("Invalid amount") * 1_000_000), // Convert to proper decimals for USDC
    fee_tier: fee_tier.parse().expect("Invalid fee tier"),
    slippage_bps: slippage_bps.parse().expect("Invalid slippage"),
    deadline_seconds: deadline.parse().expect("invalid deadline"),
    recipient: user_address,
    sqrt_price_limit: U256::ZERO,
    private_key:  private_key.parse().expect("invalid deadline")

};

return  Some(config);
}
None
}



pub fn load_tokens_address_from_env() -> HashMap< &'static str, String>{
      dotenv().ok();
    let usdc = env::var("USDC").unwrap_or_else(|_| panic!("USDC ADDRESS NOT FOUND"));
    let weth  = env::var("WETH").unwrap_or_else(|_| panic!("WTH ADDRESS NOT FOUND"));

    let mut tokens = HashMap::new();
    tokens.insert("USDC", usdc);
    tokens.insert("WETH", weth);

    tokens

}

pub fn interactive_swap_config() -> Result<SwapConfig, Box<dyn Error>> {
    println!("🔄 Interactive Token Swap Setup");
    println!("Note: Currently supports USDC → WETH swaps only");
    
    let token_addresses = load_tokens_address_from_env();
    
    // Token In selection (currently only USDC)
    let token_in_options = vec!["USDC"];
    let token_in = Select::new("Select token to swap from:", token_in_options)
        .prompt()?;
    
    // Token Out selection (currently only WETH)
    let token_out_options = vec!["WETH"];
    let token_out = Select::new("Select token to swap to:", token_out_options)
        .prompt()?;
    
    // Amount input
    let amount_input: f64 = CustomType::new("Enter amount to swap (in USDC):")
        .with_help_message("Enter the amount in USDC (e.g., 100.5)")
        .prompt()?;
    
    // Fee tier selection
    let fee_options = vec!["500 (0.05%)", "3000 (0.3%)", "10000 (1%)"];
    let fee_selection = Select::new("Select fee tier:", fee_options)
        .with_help_message("Lower fees may have less liquidity")
        .prompt()?;
    
    let fee_tier = match fee_selection {
        "500 (0.05%)" => 500,
        "3000 (0.3%)" => 3000,
        "10000 (1%)" => 10000,
        _ => 3000,
    };
    
    // Slippage input
    let slippage_input: f64 = CustomType::new("Enter slippage tolerance (%):")
        .with_default(0.5)
        .with_help_message("Default is 0.5% (recommended)")
        .prompt()?;
    
    // Deadline input
    let deadline_input: u64 = CustomType::new("Enter transaction deadline (seconds):")
        .with_default(1800)
        .with_help_message("Default is 1800 seconds (30 minutes)")
        .prompt()?;
    
    // Private key input
    let private_key = Text::new("Enter your private key:")
        .with_help_message("This will be used to sign the transaction")
        .prompt()?;
    
    let user_address = get_address_from_private_key(&private_key)?;
    
    // Convert amount to proper decimals for USDC (6 decimals)
    let amount_in_wei = U256::from((amount_input * 1_000_000.0) as u64);
    
    // Convert slippage from percentage to basis points
    let slippage_bps = (slippage_input * 100.0) as u16;
    
    let config = SwapConfig {
        token_in: token_addresses.get(token_in).unwrap().parse()?,
        token_out: token_addresses.get(token_out).unwrap().parse()?,
        amount_in: amount_in_wei,
        fee_tier: U256::from(fee_tier),
        slippage_bps,
        deadline_seconds: deadline_input,
        recipient: user_address,
        sqrt_price_limit: U256::ZERO,
        private_key: private_key.clone(),
    };
    
    println!("\n📋 Swap Configuration:");
    println!("  From: {} → To: {}", token_in, token_out);
    println!("  Amount: {} USDC", amount_input);
    println!("  Fee Tier: {} basis points", fee_tier);
    println!("  Slippage: {}%", slippage_input);
    println!("  Deadline: {} seconds", deadline_input);
    println!("  Recipient: {:?}", user_address);
    
    Ok(config)
}