use alloy::{
    network::TransactionBuilder,
    primitives::U256,
    providers::Provider,
    rpc::types::TransactionRequest,
};
use std::error::Error;

use crate::validation;
use crate::utils;

pub struct EthereumConfig {
    pub recipient: String,
    pub amount: String,
    pub gas_limit: Option<String>,
    pub gas_price: Option<String>,
    pub deadline: Option<String>,
    pub nonce: Option<String>,
}

/// Check ETH balance for a wallet address
pub async fn check_balance(
    provider: &impl Provider,
    wallet_address: &str,
) -> Result<(), Box<dyn Error>> {
    // Validate wallet address
    let validated_address = validation::validate_wallet_address(wallet_address)?;
    
    let eth_balance = provider.get_balance(validated_address.parse()?).await?;
    let eth_balance_res = utils::format_balance(eth_balance.to::<u64>(), 18);
    
    println!("✅ ETH Balance: {} ETH", eth_balance_res);
    Ok(())
}

/// Send ETH transaction
pub async fn send_transaction(
    provider: &impl Provider,
    private_key: &str,
    config: EthereumConfig,
) -> Result<(), Box<dyn Error>> {
    // Validate inputs
    let _validated_private_key = validation::validate_private_key(private_key)?;
    let validated_recipient = validation::validate_wallet_address(&config.recipient)?;
    let validated_amount = validation::validate_amount(&config.amount, Some(0.000001), Some(1000.0))?;

    // Convert amount from ETH to wei
    let amount_in_wei = match validated_amount.parse::<f64>() {
        Ok(eth_amount) => {
            let wei_amount = utils::eth_to_wei(eth_amount)?;
            U256::from(wei_amount)
        }
        Err(_) => {
            return Err(Box::new(validation::ValidationError::InvalidNumericInput(
                "Invalid amount format".to_string(),
            )));
        }
    };

    // Validate and set gas limit
    let gas_limit_value = if let Some(gas_limit) = &config.gas_limit {
        validation::validate_gas_limit(gas_limit)?
    } else {
        21_000u64 // Default gas limit for ETH transfer
    };

    // Validate and set gas price
    let gas_price_value = if let Some(gas_price) = &config.gas_price {
        validation::validate_gas_price(gas_price)?
    } else {
        20_000_000_000u64 // Default 20 gwei in wei
    };

    // Validate deadline if provided
    if let Some(deadline) = &config.deadline {
        validation::validate_deadline(deadline, "timestamp")?;
        println!("✅ Deadline validated: {}", deadline);
    }

    // Validate nonce if provided
    let nonce_value = if let Some(nonce) = &config.nonce {
        Some(validation::validate_positive_integer(nonce, Some(0))?)
    } else {
        None
    };

    // Build transaction
    let mut tx = TransactionRequest::default()
        .with_to(utils::parse_address(&validated_recipient)?)
        .with_value(amount_in_wei)
        .with_gas_price(gas_price_value as u128)
        .with_gas_limit(gas_limit_value);

    // Set nonce if provided
    if let Some(nonce) = nonce_value {
        tx = tx.with_nonce(nonce);
    }

    println!("🔄 Sending transaction...");
    println!("📤 From: Your wallet");
    println!("📥 To: {}", validated_recipient);
    println!("💰 Amount: {} ETH", validated_amount);

    let pending_tx = provider.send_transaction(tx).await?;
    println!("⏳ Pending transaction hash: {}", pending_tx.tx_hash());

    let receipt = pending_tx.get_receipt().await?;
    println!(
        "✅ Transaction successful! Block number: {}",
        receipt.block_number.expect("Failed to get the block number...")
    );
    println!("💰 Sent {} ETH to {}", validated_amount, validated_recipient);

    Ok(())
} 