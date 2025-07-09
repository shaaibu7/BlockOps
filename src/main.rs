use alloy::{
    network::TransactionBuilder,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
    transports::http::reqwest::Url,
};
use clap::{Arg, Command, command};
use core::panic;
use dotenv::dotenv;
use std::error::Error;
use std::{env, str::FromStr};

// Validation Module
mod validation {
    use regex::Regex;
    use std::error::Error;
    use std::fmt;

    #[derive(Debug)]
    pub enum ValidationError {
        InvalidAddress(String),
        InvalidPrivateKey(String),
        InvalidNumericInput(String),
    }

    impl fmt::Display for ValidationError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                ValidationError::InvalidAddress(msg) => write!(f, "Invalid Address: {}", msg),
                ValidationError::InvalidPrivateKey(msg) => write!(f, "Invalid Private Key: {}", msg),
                ValidationError::InvalidNumericInput(msg) => write!(f, "Invalid Numeric Input: {}", msg),
            }
        }
    }

    impl Error for ValidationError {}

    /// Validates Ethereum wallet address
    /// Must be a valid Ethereum address with optional 0x prefix
    /// Must be exactly 20 bytes / 40 hex characters
    pub fn validate_wallet_address(address: &str) -> Result<String, ValidationError> {
        let address = address.trim();
        
        // Check if address starts with 0x and remove it for validation
        let hex_part = if address.starts_with("0x") || address.starts_with("0X") {
            &address[2..]
        } else {
            address
        };

        // Check length (must be exactly 40 hex characters for 20 bytes)
        if hex_part.len() != 40 {
            return Err(ValidationError::InvalidAddress(format!(
                "Address must be exactly 40 hex characters (20 bytes), got {} characters",
                hex_part.len()
            )));
        }

        // Check if all characters are valid hexadecimal
        let hex_regex = Regex::new(r"^[0-9a-fA-F]+$").unwrap();
        if !hex_regex.is_match(hex_part) {
            return Err(ValidationError::InvalidAddress(
                "Address contains invalid characters. Only hexadecimal characters (0-9, a-f, A-F) are allowed".to_string()
            ));
        }

        // Return normalized address with 0x prefix
        Ok(format!("0x{}", hex_part.to_lowercase()))
    }

    /// Validates private key
    /// Must be a valid private key in hex format
    /// Should be 32 bytes / 64 hex characters
    pub fn validate_private_key(private_key: &str) -> Result<String, ValidationError> {
        let private_key = private_key.trim();
        
        // Remove 0x prefix if present
        let hex_part = if private_key.starts_with("0x") || private_key.starts_with("0X") {
            &private_key[2..]
        } else {
            private_key
        };

        // Check length (must be exactly 64 hex characters for 32 bytes)
        if hex_part.len() != 64 {
            return Err(ValidationError::InvalidPrivateKey(format!(
                "Private key must be exactly 64 hex characters (32 bytes), got {} characters",
                hex_part.len()
            )));
        }

        // Check if all characters are valid hexadecimal
        let hex_regex = Regex::new(r"^[0-9a-fA-F]+$").unwrap();
        if !hex_regex.is_match(hex_part) {
            return Err(ValidationError::InvalidPrivateKey(
                "Private key contains invalid characters. Only hexadecimal characters (0-9, a-f, A-F) are allowed".to_string()
            ));
        }

        // Additional validation: ensure private key is not zero
        if hex_part.chars().all(|c| c == '0') {
            return Err(ValidationError::InvalidPrivateKey(
                "Private key cannot be all zeros".to_string()
            ));
        }

        // Return normalized private key without 0x prefix
        Ok(hex_part.to_lowercase())
    }

    /// Core numeric validation function with comprehensive format checking
    /// Supports integers, decimals, and scientific notation
    pub fn validate_numeric_input(input: &str, allow_decimal: bool) -> Result<String, ValidationError> {
        let input = input.trim();

        if input.is_empty() {
            return Err(ValidationError::InvalidNumericInput(
                "Input cannot be empty".to_string()
            ));
        }

        // Remove common formatting (commas, spaces) for user convenience
        let cleaned_input = input.replace(",", "").replace(" ", "");

        // Comprehensive regex patterns for different numeric formats
        let numeric_regex = if allow_decimal {
            // Supports: 123, 123.456, 1.23e10, 1e-5, .5, 0.5
            Regex::new(r"^(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$").unwrap()
        } else {
            // Supports: 123, 1e5 (integer scientific notation)
            Regex::new(r"^\d+([eE]\+?\d+)?$").unwrap()
        };

        if !numeric_regex.is_match(&cleaned_input) {
            return Err(ValidationError::InvalidNumericInput(format!(
                "Invalid numeric format: '{}'. {}{}",
                input,
                if allow_decimal { 
                    "Only digits, decimal point, and scientific notation (e.g., 1.5e6) are allowed" 
                } else { 
                    "Only digits and scientific notation (e.g., 1e6) are allowed" 
                },
                if input != cleaned_input { " (commas and spaces are automatically removed)" } else { "" }
            )));
        }

        // Parse to validate it's a valid number
        let parsed_value = if allow_decimal {
            cleaned_input.parse::<f64>().map_err(|_| {
                ValidationError::InvalidNumericInput(format!(
                    "Unable to parse '{}' as a valid number", input
                ))
            })?
        } else {
            cleaned_input.parse::<u64>().map_err(|_| {
                ValidationError::InvalidNumericInput(format!(
                    "Unable to parse '{}' as a valid integer", input
                ))
            })? as f64
        };

        // Check for special values
        if parsed_value.is_infinite() {
            return Err(ValidationError::InvalidNumericInput(
                "Number is too large (infinite)".to_string()
            ));
        }

        if parsed_value.is_nan() {
            return Err(ValidationError::InvalidNumericInput(
                "Not a valid number (NaN)".to_string()
            ));
        }

        // Check for negative values (most crypto operations require positive values)
        if parsed_value < 0.0 {
            return Err(ValidationError::InvalidNumericInput(
                "Negative numbers are not allowed".to_string()
            ));
        }

        Ok(cleaned_input)
    }

    /// Validates cryptocurrency amounts (ETH, tokens, etc.)
    pub fn validate_amount(input: &str, min_amount: Option<f64>, max_amount: Option<f64>) -> Result<String, ValidationError> {
        let validated_input = validate_numeric_input(input, true)?;
        
        let amount = validated_input.parse::<f64>().map_err(|_| {
            ValidationError::InvalidNumericInput("Invalid amount format".to_string())
        })?;

        // Check for zero amount
        if amount == 0.0 {
            return Err(ValidationError::InvalidNumericInput(
                "Amount cannot be zero".to_string()
            ));
        }

        // Validate decimal precision (max 18 decimal places for Ethereum)
        if validated_input.contains('.') && !validated_input.contains('e') && !validated_input.contains('E') {
            let parts: Vec<&str> = validated_input.split('.').collect();
            if parts.len() == 2 && parts[1].len() > 18 {
                return Err(ValidationError::InvalidNumericInput(
                    "Decimal precision cannot exceed 18 places".to_string()
                ));
            }
        }

        // Check minimum amount
        if let Some(min) = min_amount {
            if amount < min {
                return Err(ValidationError::InvalidNumericInput(format!(
                    "Amount must be at least {}", min
                )));
            }
        }

        // Check maximum amount
        if let Some(max) = max_amount {
            if amount > max {
                return Err(ValidationError::InvalidNumericInput(format!(
                    "Amount cannot exceed {}", max
                )));
            }
        }

        Ok(validated_input)
    }

    /// Validates gas limits with reasonable bounds
    pub fn validate_gas_limit(input: &str) -> Result<u64, ValidationError> {
        let validated_input = validate_numeric_input(input, false)?;
        
        let gas_limit = validated_input.parse::<u64>().map_err(|_| {
            ValidationError::InvalidNumericInput("Gas limit must be a valid integer".to_string())
        })?;

        // Ethereum gas limit bounds
        const MIN_GAS_LIMIT: u64 = 21_000; // Minimum for ETH transfer
        const MAX_GAS_LIMIT: u64 = 30_000_000; // Reasonable maximum

        if gas_limit < MIN_GAS_LIMIT {
            return Err(ValidationError::InvalidNumericInput(format!(
                "Gas limit must be at least {} (minimum for ETH transfer)", MIN_GAS_LIMIT
            )));
        }

        if gas_limit > MAX_GAS_LIMIT {
            return Err(ValidationError::InvalidNumericInput(format!(
                "Gas limit cannot exceed {} (reasonable maximum)", MAX_GAS_LIMIT
            )));
        }

        Ok(gas_limit)
    }

    /// Validates gas price in gwei
    pub fn validate_gas_price(input: &str) -> Result<u64, ValidationError> {
        let validated_input = validate_numeric_input(input, true)?;
        
        let gas_price_gwei = validated_input.parse::<f64>().map_err(|_| {
            ValidationError::InvalidNumericInput("Gas price must be a valid number".to_string())
        })?;

        // Gas price bounds (in gwei)
        const MIN_GAS_PRICE: f64 = 0.1; // 0.1 gwei minimum
        const MAX_GAS_PRICE: f64 = 2000.0; // 2000 gwei maximum (very high)

        if gas_price_gwei <= 0.0 {
            return Err(ValidationError::InvalidNumericInput(
                "Gas price must be greater than 0".to_string()
            ));
        }

        if gas_price_gwei < MIN_GAS_PRICE {
            return Err(ValidationError::InvalidNumericInput(format!(
                "Gas price must be at least {} gwei", MIN_GAS_PRICE
            )));
        }

        if gas_price_gwei > MAX_GAS_PRICE {
            return Err(ValidationError::InvalidNumericInput(format!(
                "Gas price cannot exceed {} gwei (extremely high)", MAX_GAS_PRICE
            )));
        }

        // Convert gwei to wei (1 gwei = 1e9 wei)
        Ok((gas_price_gwei * 1e9) as u64)
    }

    /// Validates deadlines (timestamps or block numbers)
    pub fn validate_deadline(input: &str, deadline_type: &str) -> Result<u64, ValidationError> {
        let validated_input = validate_numeric_input(input, false)?;
        
        let deadline = validated_input.parse::<u64>().map_err(|_| {
            ValidationError::InvalidNumericInput("Deadline must be a valid integer".to_string())
        })?;

        match deadline_type {
            "timestamp" => {
                // Unix timestamp validation
                const MIN_TIMESTAMP: u64 = 1_600_000_000; // Sept 2020 (reasonable minimum)
                const MAX_TIMESTAMP: u64 = 4_102_444_800; // Jan 2100 (reasonable maximum)

                if deadline < MIN_TIMESTAMP {
                    return Err(ValidationError::InvalidNumericInput(
                        "Timestamp appears to be too old (before Sept 2020)".to_string()
                    ));
                }

                if deadline > MAX_TIMESTAMP {
                    return Err(ValidationError::InvalidNumericInput(
                        "Timestamp appears to be too far in the future (after 2100)".to_string()
                    ));
                }
            }
            "block" => {
                // Block number validation
                if deadline == 0 {
                    return Err(ValidationError::InvalidNumericInput(
                        "Block number cannot be zero".to_string()
                    ));
                }

                const MAX_REASONABLE_BLOCK: u64 = 100_000_000; // Very high block number
                if deadline > MAX_REASONABLE_BLOCK {
                    return Err(ValidationError::InvalidNumericInput(
                        "Block number appears unreasonably high".to_string()
                    ));
                }
            }
            _ => {
                return Err(ValidationError::InvalidNumericInput(
                    "Unknown deadline type. Use 'timestamp' or 'block'".to_string()
                ));
            }
        }

        Ok(deadline)
    }

    /// Validates percentage values (0-100)
    pub fn validate_percentage(input: &str) -> Result<f64, ValidationError> {
        let validated_input = validate_numeric_input(input, true)?;
        
        let percentage = validated_input.parse::<f64>().map_err(|_| {
            ValidationError::InvalidNumericInput("Percentage must be a valid number".to_string())
        })?;

        if percentage < 0.0 || percentage > 100.0 {
            return Err(ValidationError::InvalidNumericInput(
                "Percentage must be between 0 and 100".to_string()
            ));
        }

        Ok(percentage)
    }

    /// Validates positive integers (for counts, indices, etc.)
    pub fn validate_positive_integer(input: &str, min_value: Option<u64>) -> Result<u64, ValidationError> {
        let validated_input = validate_numeric_input(input, false)?;
        
        let value = validated_input.parse::<u64>().map_err(|_| {
            ValidationError::InvalidNumericInput("Must be a valid positive integer".to_string())
        })?;

        if value == 0 {
            return Err(ValidationError::InvalidNumericInput(
                "Value must be greater than zero".to_string()
            ));
        }

        if let Some(min) = min_value {
            if value < min {
                return Err(ValidationError::InvalidNumericInput(format!(
                    "Value must be at least {}", min
                )));
            }
        }

        Ok(value)
    }

    /// Validates block numbers
    pub fn validate_block_number(input: &str) -> Result<u64, ValidationError> {
        let validated_input = validate_numeric_input(input, false)?;
        
        let block_number = validated_input.parse::<u64>().map_err(|_| {
            ValidationError::InvalidNumericInput("Block number must be a valid integer".to_string())
        })?;

        // Block 0 is the genesis block, so it's valid
        const MAX_REASONABLE_BLOCK: u64 = 100_000_000; // Very high block number

        if block_number > MAX_REASONABLE_BLOCK {
            return Err(ValidationError::InvalidNumericInput(
                "Block number appears unreasonably high".to_string()
            ));
        }

        Ok(block_number)
    }



}

sol! {
   // The `rpc` attribute enables contract interaction via the provider.
   #[sol(rpc)]
   contract ERC20 {
        function balanceOf(address owner) public view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
        function transfer(address to, uint256 value) external returns (bool);
        function approve(address spender, uint256 value) external returns (bool);
        function transferFrom(address from, address to, uint256 value) external returns (bool);
   }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();

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
    let private_key: PrivateKeySigner = validated_env_private_key.parse()?;

    let provider_signer = ProviderBuilder::new()
        .wallet(private_key)
        .connect_http(rpc_url.clone());

    let match_result = command!()
        .subcommand(
            Command::new("ether-transaction")
                .arg(
                    Arg::new("wallet-address")
                        .long("wallet-address")
                        .short('w')
                        .required(true)
                        .conflicts_with_all([
                            "private-key",
                            "address-to-send-ether",
                            "amount-to-send",
                        ])
                        .help("wallet address to check ether balance"),
                )
                .arg(
                    Arg::new("private-key")
                        .long("private-key")
                        .short('p')
                        .required(true)
                        .help("private key to sign transactions to be submitted on the blockchain"),
                )
                .arg(
                    Arg::new("address-to-send-ether")
                        .long("user-address")
                        .short('u')
                        .required(true)
                        .help("wallet address to send ether to..."),
                )
                .arg(
                    Arg::new("amount-to-send")
                        .long("amount")
                        .short('a')
                        .required(true)
                        .help("amount of ether to send..."),
                )
                .arg(
                    Arg::new("gas-limit")
                        .long("gas-limit")
                        .short('g')
                        .required(false)
                        .help("custom gas limit for the transaction (default: 21000)"),
                )
                .arg(
                    Arg::new("gas-price")
                        .long("gas-price")
                        .short('P')
                        .required(false)
                        .help("custom gas price in gwei (default: 20 gwei)"),
                )
                .arg(
                    Arg::new("deadline")
                        .long("deadline")
                        .short('d')
                        .required(false)
                        .help("deadline timestamp for the transaction (unix timestamp)"),
                )
                .arg(
                    Arg::new("nonce")
                        .long("nonce")
                        .short('n')
                        .required(false)
                        .help("custom nonce for the transaction (advanced users)"),
                ),
        )
        .subcommand(
            Command::new("erc20-token")
                .arg(
                    Arg::new("token-address")
                        .long("token-address")
                        .short('t')
                        .required(true)
                        .help("contract address of erc20 token"),
                )
                .subcommand(
                    Command::new("token-balance").arg(
                        Arg::new("token-holder")
                            .long("token-holder")
                            .short('u')
                            .required(true)
                            .help("token holder address to check balance"),
                    ),
                )
                .subcommand(
                    Command::new("token-allowance")
                        .arg(
                            Arg::new("token-owner")
                                .long("token-owner")
                                .short('o')
                                .required(true)
                                .help("token owner address to check for allowance"),
                        )
                        .arg(
                            Arg::new("token-spender")
                                .long("token-spender")
                                .short('s')
                                .required(true)
                                .help("token spender address to check for allowance"),
                        ),
                )
                .subcommand(
                    Command::new("token-transfer")
                        .arg(
                            Arg::new("token-recipient")
                                .long("token-recipient")
                                .short('r')
                                .required(true)
                                .help("address of token recipient in transfer operation"),
                        )
                        .arg(
                            Arg::new("transfer-amount")
                                .long("transfer-amount")
                                .short('a')
                                .required(true)
                                .help("amount of tokens to transfer"),
                        )
                        .arg(
                            Arg::new("gas-limit")
                                .long("gas-limit")
                                .short('g')
                                .required(false)
                                .help("custom gas limit for token transfer (default: 100000)"),
                        )
                        .arg(
                            Arg::new("gas-price")
                                .long("gas-price")
                                .short('P')
                                .required(false)
                                .help("custom gas price in gwei (default: 20 gwei)"),
                        )
                        .arg(
                            Arg::new("slippage")
                                .long("slippage")
                                .short('s')
                                .required(false)
                                .help("slippage tolerance percentage (0-100, default: 0.5%)"),
                        ),
                ),
        )
        .subcommand(
            Command::new("block-query")
                .about("Query blockchain information")
                .arg(
                    Arg::new("block-number")
                        .long("block-number")
                        .short('b')
                        .required(false)
                        .help("specific block number to query (default: latest)"),
                )
                .arg(
                    Arg::new("transaction-count")
                        .long("tx-count")
                        .short('c')
                        .required(false)
                        .action(clap::ArgAction::SetTrue)
                        .help("show transaction count for the block"),
                )
                .arg(
                    Arg::new("gas-used")
                        .long("gas-used")
                        .short('G')
                        .required(false)
                        .action(clap::ArgAction::SetTrue)
                        .help("show gas used in the block"),
                ),
        )
        .about(
            "web3 all in one comprehensive cli tool for interacting with the ethereum blockchain",
        )
        .get_matches();

    // ETHER TRANSACTION OPERATION
    let empty = String::from("empty");

    let ether_transaction = match_result.subcommand_matches("ether-transaction");

    let wallet_address = match ether_transaction {
        Some(x) => x.get_one::<String>("wallet-address").unwrap_or(&empty),
        _ => "empty",
    };

    let private_key = match ether_transaction {
        Some(x) => x.get_one::<String>("private-key").unwrap_or(&empty),
        _ => "empty",
    };

    let wallet_address_to_send_ether = match ether_transaction {
        Some(x) => x
            .get_one::<String>("address-to-send-ether")
            .unwrap_or(&empty),
        _ => "empty",
    };

    let amount_of_ether = match ether_transaction {
        Some(x) => x.get_one::<String>("amount-to-send").unwrap_or(&empty),
        _ => "empty",
    };

    let gas_limit_eth = match ether_transaction {
        Some(x) => x.get_one::<String>("gas-limit").unwrap_or(&empty),
        _ => "empty",
    };

    let gas_price_eth = match ether_transaction {
        Some(x) => x.get_one::<String>("gas-price").unwrap_or(&empty),
        _ => "empty",
    };

    let deadline_eth = match ether_transaction {
        Some(x) => x.get_one::<String>("deadline").unwrap_or(&empty),
        _ => "empty",
    };

    let nonce_eth = match ether_transaction {
        Some(x) => x.get_one::<String>("nonce").unwrap_or(&empty),
        _ => "empty",
    };

    let provider = ProviderBuilder::new().connect_http(rpc_url.clone());

    // checking eth balance for a wallet address
    if wallet_address != "empty" {
        // Validate wallet address
        let validated_address = match validation::validate_wallet_address(wallet_address) {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("❌ Validation Error: {}", e);
                return Err(Box::new(e) as Box<dyn Error>);
            }
        };

        let eth_balance = provider.get_balance(validated_address.parse()?).await?;

        let eth_balance_res = f64::from(eth_balance) / f64::from(10e17);
        println!("✅ ETH Balance: {} ETH", eth_balance_res);
    }

    if private_key != "empty"
        && wallet_address_to_send_ether != "empty"
        && amount_of_ether != "empty"
    {
        // Validate private key
        let validated_private_key = match validation::validate_private_key(private_key) {
            Ok(key) => key,
            Err(e) => {
                eprintln!("❌ Validation Error: {}", e);
                return Err(Box::new(e) as Box<dyn Error>);
            }
        };

        // Validate recipient address
        let validated_recipient = match validation::validate_wallet_address(wallet_address_to_send_ether) {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("❌ Validation Error: {}", e);
                return Err(Box::new(e) as Box<dyn Error>);
            }
        };

        // Validate amount using specialized amount validator
        let validated_amount = match validation::validate_amount(amount_of_ether, Some(0.000001), Some(1000.0)) {
            Ok(amt) => amt,
            Err(e) => {
                eprintln!("❌ Validation Error: {}", e);
                return Err(Box::new(e) as Box<dyn Error>);
            }
        };

        let private_key: PrivateKeySigner = validated_private_key.parse()?;

        let provider = ProviderBuilder::new()
            .wallet(private_key)
            .connect_http(rpc_url.clone());

        // Convert amount from ETH to wei
        let amount_in_wei = match validated_amount.parse::<f64>() {
            Ok(eth_amount) => {
                let wei_amount = (eth_amount * 1e18) as u64;
                U256::from(wei_amount)
            }
            Err(_) => {
                eprintln!("❌ Error: Invalid amount format");
                return Err(Box::new(validation::ValidationError::InvalidNumericInput("Invalid amount format".to_string())) as Box<dyn Error>);
            }
        };

        // Validate and set gas limit
        let gas_limit_value = if gas_limit_eth != "empty" {
            match validation::validate_gas_limit(gas_limit_eth) {
                Ok(limit) => limit,
                Err(e) => {
                    eprintln!("❌ Gas Limit Validation Error: {}", e);
                    return Err(Box::new(e) as Box<dyn Error>);
                }
            }
        } else {
            21_000u64 // Default gas limit for ETH transfer
        };

        // Validate and set gas price
        let gas_price_value = if gas_price_eth != "empty" {
            match validation::validate_gas_price(gas_price_eth) {
                Ok(price) => price,
                Err(e) => {
                    eprintln!("❌ Gas Price Validation Error: {}", e);
                    return Err(Box::new(e) as Box<dyn Error>);
                }
            }
        } else {
            20_000_000_000u64 // Default 20 gwei in wei
        };

        // Validate deadline if provided
        if deadline_eth != "empty" {
            match validation::validate_deadline(deadline_eth, "timestamp") {
                Ok(_) => {
                    println!("✅ Deadline validated: {}", deadline_eth);
                }
                Err(e) => {
                    eprintln!("❌ Deadline Validation Error: {}", e);
                    return Err(Box::new(e) as Box<dyn Error>);
                }
            }
        }

        // Validate nonce if provided
        let nonce_value = if nonce_eth != "empty" {
            match validation::validate_positive_integer(nonce_eth, Some(0)) {
                Ok(nonce) => Some(nonce),
                Err(e) => {
                    eprintln!("❌ Nonce Validation Error: {}", e);
                    return Err(Box::new(e) as Box<dyn Error>);
                }
            }
        } else {
            None
        };

        let mut tx = TransactionRequest::default()
            .with_to(validated_recipient.parse()?)
            .with_value(amount_in_wei)
            .with_gas_price(gas_price_value as u128)
            .with_gas_limit(gas_limit_value);

        // Set nonce if provided
        if let Some(nonce) = nonce_value {
            tx = tx.with_nonce(nonce);
        }

        let pending_tx = provider.send_transaction(tx).await?;

        println!("⏳ Pending transaction hash: {}", pending_tx.tx_hash());

        let reciept = pending_tx.get_receipt().await?;

        println!(
            "✅ Transaction successful! Block number: {}",
            reciept
                .block_number
                .expect("Failed to get the block number...")
        );
        println!("💰 Sent {} ETH to {}", validated_amount, validated_recipient);
    }

    // ERC20 TRANSACTION OPERATION

    // checking token balance
    if let Some(("erc20-token", erc20_matches)) = match_result.subcommand() {
        let token_address = erc20_matches.get_one::<String>("token-address").unwrap();
        
        // Validate token contract address
        let validated_token_address = match validation::validate_wallet_address(token_address) {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("❌ Validation Error for token address: {}", e);
                return Err(Box::new(e) as Box<dyn Error>);
            }
        };

        let token_contract_address = Address::from_str(&validated_token_address).unwrap();
        let erc20 = ERC20::new(token_contract_address, provider.clone());

        if let Some(("token-balance", balance_matches)) = erc20_matches.subcommand() {
            let token_holder = balance_matches.get_one::<String>("token-holder").unwrap();
            
            // Validate token holder address
            let validated_holder_address = match validation::validate_wallet_address(token_holder) {
                Ok(addr) => addr,
                Err(e) => {
                    eprintln!("❌ Validation Error for token holder address: {}", e);
                    return Err(Box::new(e) as Box<dyn Error>);
                }
            };

            let token_holder_address = Address::from_str(&validated_holder_address).unwrap();
            let token_balance = erc20.balanceOf(token_holder_address).call().await?;

            println!("🪙 Token balance for {} is: {}", validated_holder_address, token_balance);
        }
    }

    // Checking token allowance
    if let Some(("erc20-token", erc20_matches)) = match_result.subcommand() {
        let token_address = erc20_matches.get_one::<String>("token-address").unwrap();
        
        // Validate token contract address
        let validated_token_address = match validation::validate_wallet_address(token_address) {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("❌ Validation Error for token address: {}", e);
                return Err(Box::new(e) as Box<dyn Error>);
            }
        };

        let token_contract_address = Address::from_str(&validated_token_address).unwrap();
        let erc20 = ERC20::new(token_contract_address, provider.clone());

        if let Some(("token-allowance", balance_matches)) = erc20_matches.subcommand() {
            let token_owner = balance_matches.get_one::<String>("token-owner").unwrap();
            let token_spender = balance_matches.get_one::<String>("token-spender").unwrap();

            // Validate token owner address
            let validated_owner_address = match validation::validate_wallet_address(token_owner) {
                Ok(addr) => addr,
                Err(e) => {
                    eprintln!("❌ Validation Error for token owner address: {}", e);
                    return Err(Box::new(e) as Box<dyn Error>);
                }
            };

            // Validate token spender address
            let validated_spender_address = match validation::validate_wallet_address(token_spender) {
                Ok(addr) => addr,
                Err(e) => {
                    eprintln!("❌ Validation Error for token spender address: {}", e);
                    return Err(Box::new(e) as Box<dyn Error>);
                }
            };

            let token_owner_address = Address::from_str(&validated_owner_address).unwrap();
            let token_spender_address = Address::from_str(&validated_spender_address).unwrap();

            let token_allowance = erc20
                .allowance(token_owner_address, token_spender_address)
                .call()
                .await?;

            println!("🔐 Token allowance for spender {} from owner {} is: {}", 
                     validated_spender_address, validated_owner_address, token_allowance);
        }
    }

    // Integrating erc20 token contract write ops
    if let Some(("erc20-token", erc20_matches)) = match_result.subcommand() {
        let token_address = erc20_matches.get_one::<String>("token-address").unwrap();
        
        // Validate token contract address
        let validated_token_address = match validation::validate_wallet_address(token_address) {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("❌ Validation Error for token address: {}", e);
                return Err(Box::new(e) as Box<dyn Error>);
            }
        };

        let token_contract_address = Address::from_str(&validated_token_address).unwrap();
        let erc20 = ERC20::new(token_contract_address, provider_signer.clone());

        if let Some(("token-transfer", balance_matches)) = erc20_matches.subcommand() {
            let token_recipient = balance_matches
                .get_one::<String>("token-recipient")
                .unwrap();
            let transfer_amount = balance_matches
                .get_one::<String>("transfer-amount")
                .unwrap();
            
            let gas_limit_token = balance_matches
                .get_one::<String>("gas-limit")
                .unwrap_or(&empty);
            let gas_price_token = balance_matches
                .get_one::<String>("gas-price")
                .unwrap_or(&empty);
            let slippage_token = balance_matches
                .get_one::<String>("slippage")
                .unwrap_or(&empty);

            // Validate token recipient address
            let validated_recipient_address = match validation::validate_wallet_address(token_recipient) {
                Ok(addr) => addr,
                Err(e) => {
                    eprintln!("❌ Validation Error for token recipient address: {}", e);
                    return Err(Box::new(e) as Box<dyn Error>);
                }
            };

            // Validate transfer amount using specialized amount validator
            let validated_transfer_amount = match validation::validate_amount(transfer_amount, Some(0.000001), Some(1_000_000.0)) {
                Ok(amt) => amt,
                Err(e) => {
                    eprintln!("❌ Validation Error for transfer amount: {}", e);
                    return Err(Box::new(e) as Box<dyn Error>);
                }
            };

            // Validate gas limit for token transfer
            let _token_gas_limit = if gas_limit_token != "empty" {
                match validation::validate_gas_limit(gas_limit_token) {
                    Ok(limit) => limit,
                    Err(e) => {
                        eprintln!("❌ Token Gas Limit Validation Error: {}", e);
                        return Err(Box::new(e) as Box<dyn Error>);
                    }
                }
            } else {
                100_000u64 // Default gas limit for token transfer
            };

            // Validate gas price for token transfer
            let _token_gas_price = if gas_price_token != "empty" {
                match validation::validate_gas_price(gas_price_token) {
                    Ok(price) => price,
                    Err(e) => {
                        eprintln!("❌ Token Gas Price Validation Error: {}", e);
                        return Err(Box::new(e) as Box<dyn Error>);
                    }
                }
            } else {
                20_000_000_000u64 // Default 20 gwei in wei
            };

            // Validate slippage tolerance if provided
            let _slippage_percent = if slippage_token != "empty" {
                match validation::validate_percentage(slippage_token) {
                    Ok(percent) => {
                        println!("✅ Slippage tolerance set to: {}%", percent);
                        percent
                    }
                    Err(e) => {
                        eprintln!("❌ Slippage Validation Error: {}", e);
                        return Err(Box::new(e) as Box<dyn Error>);
                    }
                }
            } else {
                0.5f64 // Default 0.5% slippage
            };

            // Convert amount to proper format (assuming 18 decimals for ERC20)
            let transfer_amount_transform = match validated_transfer_amount.parse::<f64>() {
                Ok(amount) => {
                    let amount_with_decimals = (amount * 1e18) as u64;
                    U256::from(amount_with_decimals)
                }
                            Err(_) => {
                eprintln!("❌ Error: Invalid transfer amount format");
                return Err(Box::new(validation::ValidationError::InvalidNumericInput("Invalid transfer amount format".to_string())) as Box<dyn Error>);
            }
            };

            let token_recipient_transform = Address::from_str(&validated_recipient_address).unwrap();

            println!("🔄 Initiating token transfer...");
            println!("📤 From: Your wallet");
            println!("📥 To: {}", validated_recipient_address);
            println!("🪙 Amount: {} tokens", validated_transfer_amount);
            println!("🏷️ Token Contract: {}", validated_token_address);

            let transfer_tx = erc20
                .transfer(token_recipient_transform, transfer_amount_transform)
                .send()
                .await?;
            
            println!("⏳ Transaction submitted. Hash: {}", transfer_tx.tx_hash());
            
            let reciept_tx = transfer_tx.get_receipt().await?;

            println!(
                "✅ Transfer transaction completed successfully!"
            );
            println!("🧾 Transaction hash: {}", reciept_tx.transaction_hash);
            println!("🔗 Block number: {}", reciept_tx.block_number.unwrap_or_default());
            println!("💰 Successfully transferred {} tokens to {}", validated_transfer_amount, validated_recipient_address);
        }
    }

    // BLOCK QUERY OPERATION
    if let Some(("block-query", query_matches)) = match_result.subcommand() {
        let block_number_input = query_matches.get_one::<String>("block-number").unwrap_or(&empty);
        let show_tx_count = query_matches.get_flag("transaction-count");
        let show_gas_used = query_matches.get_flag("gas-used");

        // Validate block number if provided
        let block_number = if block_number_input != "empty" {
            match validation::validate_block_number(block_number_input) {
                Ok(block_num) => Some(block_num),
                Err(e) => {
                    eprintln!("❌ Block Number Validation Error: {}", e);
                    return Err(Box::new(e) as Box<dyn Error>);
                }
            }
        } else {
            None
        };

        // Query block information
        let _block_info = if let Some(block_num) = block_number {
            match provider.get_block_by_number(block_num.into()).await {
                Ok(Some(block)) => {
                    println!("📦 Block Information for Block #{}", block_num);
                    println!("🔗 Block Hash: {}", block.header.hash);
                    println!("👤 Beneficiary: {}", block.header.beneficiary);
                    println!("⏰ Timestamp: {}", block.header.timestamp);
                    
                    if show_tx_count {
                        println!("📊 Transaction Count: {}", block.transactions.len());
                    }
                    
                    if show_gas_used {
                        println!("⛽ Gas Used: {}", block.header.gas_used);
                        println!("🚀 Gas Limit: {}", block.header.gas_limit);
                    }
                    
                    block
                }
                Ok(None) => {
                    eprintln!("❌ Block #{} not found", block_num);
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("❌ Error fetching block: {}", e);
                    return Err(Box::new(e) as Box<dyn Error>);
                }
            }
        } else {
            // Query latest block
            match provider.get_block_by_number(alloy::rpc::types::BlockNumberOrTag::Latest).await {
                Ok(Some(block)) => {
                    println!("📦 Latest Block Information");
                    println!("🔢 Block Number: {}", block.header.number);
                    println!("🔗 Block Hash: {}", block.header.hash);
                    println!("👤 Beneficiary: {}", block.header.beneficiary);
                    println!("⏰ Timestamp: {}", block.header.timestamp);
                    
                    if show_tx_count {
                        println!("📊 Transaction Count: {}", block.transactions.len());
                    }
                    
                    if show_gas_used {
                        println!("⛽ Gas Used: {}", block.header.gas_used);
                        println!("🚀 Gas Limit: {}", block.header.gas_limit);
                    }
                    
                    block
                }
                Ok(None) => {
                    eprintln!("❌ Latest block not found");
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("❌ Error fetching latest block: {}", e);
                    return Err(Box::new(e) as Box<dyn Error>);
                }
            }
        };

        println!("✅ Block query completed successfully!");
    }

    Ok(())
}
