use alloy::{
    providers::Provider,
    rpc::types::BlockNumberOrTag,
};
use std::error::Error;

use crate::validation;

pub struct BlockQueryConfig {
    pub block_number: Option<String>,
    pub show_tx_count: bool,
    pub show_gas_used: bool,
}

/// Query block information
pub async fn query_block(
    provider: &impl Provider,
    config: BlockQueryConfig,
) -> Result<(), Box<dyn Error>> {
    // Validate block number if provided
    let block_number = if let Some(block_number_input) = &config.block_number {
        Some(validation::validate_block_number(block_number_input)?)
    } else {
        None
    };

    // Query block information
    let block_info = if let Some(block_num) = block_number {
        // Query specific block
        match provider.get_block_by_number(block_num.into()).await {
            Ok(Some(block)) => {
                println!("📦 Block Information for Block #{}", block_num);
                println!("🔗 Block Hash: {}", block.header.hash);
                println!("👤 Beneficiary: {}", block.header.beneficiary);
                println!("⏰ Timestamp: {}", block.header.timestamp);
                
                if config.show_tx_count {
                    println!("📊 Transaction Count: {}", block.transactions.len());
                }
                
                if config.show_gas_used {
                    println!("⛽ Gas Used: {}", block.header.gas_used);
                    println!("🚀 Gas Limit: {}", block.header.gas_limit);
                }
                
                Some(block)
            }
            Ok(None) => {
                eprintln!("❌ Block #{} not found", block_num);
                return Ok(());
            }
            Err(e) => {
                eprintln!("❌ Error fetching block: {}", e);
                return Err(Box::new(e));
            }
        }
    } else {
        // Query latest block
        match provider.get_block_by_number(BlockNumberOrTag::Latest).await {
            Ok(Some(block)) => {
                println!("📦 Latest Block Information");
                println!("🔢 Block Number: {}", block.header.number);
                println!("🔗 Block Hash: {}", block.header.hash);
                println!("👤 Beneficiary: {}", block.header.beneficiary);
                println!("⏰ Timestamp: {}", block.header.timestamp);
                
                if config.show_tx_count {
                    println!("📊 Transaction Count: {}", block.transactions.len());
                }
                
                if config.show_gas_used {
                    println!("⛽ Gas Used: {}", block.header.gas_used);
                    println!("🚀 Gas Limit: {}", block.header.gas_limit);
                }
                
                Some(block)
            }
            Ok(None) => {
                eprintln!("❌ Latest block not found");
                return Ok(());
            }
            Err(e) => {
                eprintln!("❌ Error fetching latest block: {}", e);
                return Err(Box::new(e));
            }
        }
    };

    if block_info.is_some() {
        println!("✅ Block query completed successfully!");
    }

    Ok(())
} 