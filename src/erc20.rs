use inquire::error::InquireResult;
use inquire::{Text, Select, min_length};
use alloy::{
    primitives::{Address, U256},
    providers::Provider,
    sol,
};
use std::error::Error;
use std::str::FromStr;

use crate::validation;
use crate::utils;

sol! {
    #[sol(rpc)]
    contract ERC20 {
        function balanceOf(address owner) public view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
        function transfer(address to, uint256 value) external returns (bool);
        function approve(address spender, uint256 value) external returns (bool);
        function transferFrom(address from, address to, uint256 value) external returns (bool);
    }
}

pub struct TokenTransferConfig {
    pub recipient: String,
    pub amount: String,
    pub gas_limit: Option<String>,
    pub gas_price: Option<String>,
    pub slippage: Option<String>,
}

pub async fn run(provider: &impl Provider) -> InquireResult<()> {
    let op = Select::new("🪙 ERC20 Operation", vec![
        "Check Token Balance",
        "Check Allowance",
        "Transfer Tokens",
        "Back to Main Menu"
    ])
    .with_help_message("Choose an ERC20 token operation.")
    .prompt()?;

    match op.as_ref() {
        "Check Token Balance" => {
            let token_address = Text::new("🏷️ Token contract address:")
                .with_help_message("Paste the ERC20 token contract address.")
                .with_validator(min_length!(5, "Must be a valid address"))
                .prompt()?;
            let holder = Text::new("👤 Token holder address:")
                .with_help_message("Paste the wallet address to check balance for.")
                .with_validator(min_length!(5, "Must be a valid address"))
                .prompt()?;
            check_balance(provider, &token_address, &holder).await.unwrap();
        }
        "Check Allowance" => {
            let token_address = Text::new("🏷️ Token contract address:").prompt()?;
            let owner = Text::new("👤 Token owner address:").prompt()?;
            let spender = Text::new("🤝 Token spender address:").prompt()?;
            check_allowance(provider, &token_address, &owner, &spender).await.unwrap();
        }
        "Transfer Tokens" => {
            let token_address = Text::new("🏷️ Token contract address:").prompt()?;
            let recipient = Text::new("📬 Recipient address:").prompt()?;
            let amount = Text::new("💰 Amount to transfer:").prompt()?;
            let gas_limit = Some("100000".to_string());
                
            let gas_price = Some("200".to_string());
            let slippage = Some("0.5".to_string());

            let config = TokenTransferConfig {
                recipient,
                amount,
                gas_limit,
                gas_price,
                slippage,
            };
            transfer_tokens(provider, &token_address, config).await.unwrap();
        }
        "Back to Main Menu" => {}
        _ => unreachable!(),
    }
    Ok(())
}


/// Check ERC20 token balance
pub async fn check_balance(
    provider: &impl Provider,
    token_address: &str,
    holder_address: &str,
) -> Result<(), Box<dyn Error>> {
    // Validate addresses
    let validated_token_address = validation::validate_wallet_address(token_address)?;
    let validated_holder_address = validation::validate_wallet_address(holder_address)?;

    // Create contract instance
    let token_contract_address = Address::from_str(&validated_token_address)?;
    let erc20 = ERC20::new(token_contract_address, provider);

    // Get balance
    let holder_addr = Address::from_str(&validated_holder_address)?;
    let token_balance = erc20.balanceOf(holder_addr).call().await?;

    println!("🪙 Token balance for {} is: {}", validated_holder_address, token_balance);
    Ok(())
}

/// Check ERC20 token allowance
pub async fn check_allowance(
    provider: &impl Provider,
    token_address: &str,
    owner_address: &str,
    spender_address: &str,
) -> Result<(), Box<dyn Error>> {
    // Validate addresses
    let validated_token_address = validation::validate_wallet_address(token_address)?;
    let validated_owner_address = validation::validate_wallet_address(owner_address)?;
    let validated_spender_address = validation::validate_wallet_address(spender_address)?;

    // Create contract instance
    let token_contract_address = Address::from_str(&validated_token_address)?;
    let erc20 = ERC20::new(token_contract_address, provider);

    // Get allowance
    let owner_addr = Address::from_str(&validated_owner_address)?;
    let spender_addr = Address::from_str(&validated_spender_address)?;
    let token_allowance = erc20.allowance(owner_addr, spender_addr).call().await?;

    println!(
        "🔐 Token allowance for spender {} from owner {} is: {}",
        validated_spender_address, validated_owner_address, token_allowance
    );
    Ok(())
}

///  Transfer ERC20 tokens
pub async fn transfer_tokens(
    provider: &impl Provider,
    token_address: &str,
    config: TokenTransferConfig,
) -> Result<(), Box<dyn Error>> {
    // Validate token contract address
    let validated_token_address = validation::validate_wallet_address(token_address)?;

    // Validate recipient address
    let validated_recipient_address = validation::validate_wallet_address(&config.recipient)?;

    // Validate transfer amount
    let validated_transfer_amount = validation::validate_amount(
        &config.amount,
        Some(0.000001),
        Some(1_000_000.0),
    )?;

    // Validate gas limit
    let _token_gas_limit = if let Some(gas_limit) = &config.gas_limit {
        validation::validate_gas_limit(gas_limit)?
    } else {
        100_000u64 // Default gas limit for token transfer
    };

    // Validate gas price
    let _token_gas_price = if let Some(gas_price) = &config.gas_price {
        validation::validate_gas_price(gas_price)?
    } else {
        20_000_000_000u64 // Default 20 gwei in wei
    };

    // Validate slippage tolerance
    let _slippage_percent = if let Some(slippage) = &config.slippage {
        let percent = validation::validate_percentage(slippage)?;
        println!("✅ Slippage tolerance set to: {}%", percent);
        percent
    } else {
        0.5f64 // Default 0.5% slippage
    };

    // Convert amount to proper format (assuming 18 decimals for ERC20)
    let transfer_amount_transform = match validated_transfer_amount.parse::<f64>() {
        Ok(amount) => {
            let amount_with_decimals = utils::token_to_smallest_unit(amount, 6)?;
            U256::from(amount_with_decimals)
        }
        Err(_) => {
            return Err(Box::new(validation::ValidationError::InvalidNumericInput(
                "Invalid transfer amount format".to_string(),
            )));
        }
    };

    // Setup contract and addresses
    let token_contract_address = Address::from_str(&validated_token_address)?;
    let erc20 = ERC20::new(token_contract_address, provider);
    let recipient_addr = Address::from_str(&validated_recipient_address)?;

    println!("🔄 Initiating token transfer...");
    println!("📤 From: Your wallet");
    println!("📥 To: {}", validated_recipient_address);
    println!("🪙 Amount: {} tokens", validated_transfer_amount);
    println!("🏷️ Token Contract: {}", validated_token_address);

    // Execute transfer
    let transfer_tx = erc20.transfer(recipient_addr, transfer_amount_transform).send().await?;
    println!("⏳ Transaction submitted. Hash: {}", transfer_tx.tx_hash());

    let receipt = transfer_tx.get_receipt().await?;
    println!("✅ Transfer transaction completed successfully!");
    println!("🧾 Transaction hash: {}", receipt.transaction_hash);
    println!("🔗 Block number: {}", receipt.block_number.unwrap_or_default());
    println!(
        "💰 Successfully transferred {} tokens to {}",
        validated_transfer_amount, validated_recipient_address
    );

    Ok(())
} 