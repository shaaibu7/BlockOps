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