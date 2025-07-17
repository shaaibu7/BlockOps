use clap::{Arg, Command, command, ArgMatches};

use crate::ether::EthereumConfig;
use crate::erc20::TokenTransferConfig;
use crate::blockchain::BlockQueryConfig;

pub fn build_cli() -> Command {
    command!()
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
                                .short('S')
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
        .about("web3 all in one comprehensive cli tool for interacting with the ethereum blockchain")
        .subcommand(
        Command::new("chat")
        .arg(
        Arg::new("cmd_arg")
        .long("message")
        .short('m')
        .required(true)
        .help("Command line arguments from the terminal")
        ))
        .subcommand(
                    Command::new("swap")
                    .arg(
                    Arg::new("token-in")
                    .long("from")
                    .short('f')
                    .required(true)
                    .help(" Token A")
                    )
                    .arg(
                        Arg::new("token-out")
                        .long("to")
                        .short('t')
                        .required(true)
                        .help("Token to recieve")
                    )
                    .arg(
                        Arg::new("amount-in")
                        .long("amount")
                        .short('a')
                        .required(true)
                    ).arg(
                    Arg::new("fee-tier")
                        .long("fee-tier")
                        .value_name("FEE")
                        .help("Fee tier (500, 3000, 10000)")
                        .default_value("3000")
                )
                .arg(
                    Arg::new("slippage-bps")
                        .long("slippage-bps")
                        .value_name("BPS")
                        .help("Slippage tolerance in basis points (100 = 1%)")
                        .default_value("50")
                ).arg(
                    Arg::new("deadline")
                        .long("deadline")
                        .value_name("SECONDS")
                        .help("Transaction deadline in seconds")
                        .default_value("1800")
                )
                .arg(
                    Arg::new("private-key")
                        .long("private-key")
                        .value_name("PRIVATE-KEY")
                        .help("User private key")
                        .required(true)
                )
                )

}


pub fn parse_ethereum_config(matches: &ArgMatches) -> Option<(Option<String>, Option<(String, EthereumConfig)>)> {
    if let Some(eth_matches) = matches.subcommand_matches("ether-transaction") {
        let wallet_address = eth_matches.get_one::<String>("wallet-address").map(|s| s.clone());
        let private_key = eth_matches.get_one::<String>("private-key").map(|s| s.clone());
        let recipient = eth_matches.get_one::<String>("address-to-send-ether").map(|s| s.clone());
        let amount = eth_matches.get_one::<String>("amount-to-send").map(|s| s.clone());
        
        // Check if this is a balance check
        if let Some(addr) = wallet_address {
            return Some((Some(addr), None));
        }
        
        // Check if this is a transaction
        if let (Some(pk), Some(to), Some(amt)) = (private_key, recipient, amount) {
            let config = EthereumConfig {
                recipient: to,
                amount: amt,
                gas_limit: eth_matches.get_one::<String>("gas-limit").map(|s| s.clone()),
                gas_price: eth_matches.get_one::<String>("gas-price").map(|s| s.clone()),
                deadline: eth_matches.get_one::<String>("deadline").map(|s| s.clone()),
                nonce: eth_matches.get_one::<String>("nonce").map(|s| s.clone()),
            };
            return Some((None, Some((pk, config))));
        }
    }
    None
}

pub fn parse_erc20_config(matches: &ArgMatches) -> Option<(String, ERC20Operation)> {
    if let Some(("erc20-token", erc20_matches)) = matches.subcommand() {
        let token_address = erc20_matches.get_one::<String>("token-address").unwrap().clone();
        
        if let Some(("token-balance", balance_matches)) = erc20_matches.subcommand() {
            let token_holder = balance_matches.get_one::<String>("token-holder").unwrap().clone();
            return Some((token_address, ERC20Operation::CheckBalance(token_holder)));
        }
        
        if let Some(("token-allowance", allowance_matches)) = erc20_matches.subcommand() {
            let token_owner = allowance_matches.get_one::<String>("token-owner").unwrap().clone();
            let token_spender = allowance_matches.get_one::<String>("token-spender").unwrap().clone();
            return Some((token_address, ERC20Operation::CheckAllowance(token_owner, token_spender)));
        }
        
        if let Some(("token-transfer", transfer_matches)) = erc20_matches.subcommand() {
            let config = TokenTransferConfig {
                recipient: transfer_matches.get_one::<String>("token-recipient").unwrap().clone(),
                amount: transfer_matches.get_one::<String>("transfer-amount").unwrap().clone(),
                gas_limit: transfer_matches.get_one::<String>("gas-limit").map(|s| s.clone()),
                gas_price: transfer_matches.get_one::<String>("gas-price").map(|s| s.clone()),
                slippage: transfer_matches.get_one::<String>("slippage").map(|s| s.clone()),
            };
            return Some((token_address, ERC20Operation::Transfer(config)));
        }
    }
    None
}

pub fn parse_block_query_config(matches: &ArgMatches) -> Option<BlockQueryConfig> {
    if let Some(("block-query", query_matches)) = matches.subcommand() {
        let config = BlockQueryConfig {
            block_number: query_matches.get_one::<String>("block-number").map(|s| s.clone()),
            show_tx_count: query_matches.get_flag("transaction-count"),
            show_gas_used: query_matches.get_flag("gas-used"),
        };
        return Some(config);
    }
    None
}

pub enum ERC20Operation {
    CheckBalance(String),
    CheckAllowance(String, String),
    Transfer(TokenTransferConfig),
} 
