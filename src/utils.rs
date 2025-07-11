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