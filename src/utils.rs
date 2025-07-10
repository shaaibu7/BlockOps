use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    transports::http::reqwest::Url,
};
use std::error::Error;
use std::str::FromStr;

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