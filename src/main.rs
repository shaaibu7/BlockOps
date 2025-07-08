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
    let private_key = env::var("PRIVATE_KEY").unwrap_or_else(|_| panic!("Private key not found"));
    let rpc_url: Url = rpc_endpoint.parse()?;

    let private_key: PrivateKeySigner = private_key.parse()?;

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
                                .help("address of token recipient in transfer operation"),
                        ),
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

    let provider = ProviderBuilder::new().connect_http(rpc_url.clone());

    // checking eth balance for a wallet address
    if wallet_address != "empty" {
        let eth_balance = provider.get_balance(wallet_address.parse()?).await?;

        let eth_balance_res = f64::from(eth_balance) / f64::from(10e17);
        println!("{:?}", eth_balance_res);
    }

    if private_key != "empty"
        && wallet_address_to_send_ether != "empty"
        && amount_of_ether != "empty"
    {
        let private_key: PrivateKeySigner = private_key.parse()?;

        let provider = ProviderBuilder::new()
            .wallet(private_key)
            .connect_http(rpc_url.clone());

        let tx = TransactionRequest::default()
            .with_to(wallet_address_to_send_ether.parse()?)
            .with_value(U256::from(
                "10000000000000000"
                    .parse::<U256>()
                    .expect("Invalid U256 string"),
            ))
            .with_gas_price(20_000_000_000)
            .with_gas_limit(21_000);

        let pending_tx = provider.send_transaction(tx).await?;

        println!("Pending transaction hash.... {}", pending_tx.tx_hash());

        let reciept = pending_tx.get_receipt().await?;

        println!(
            "Transaction successfull and included in block number {}",
            reciept
                .block_number
                .expect("Failed to get the block number...")
        )
    }

    // ERC20 TRANSACTION OPERATION
    let token_transaction = match_result.subcommand_matches("erc20-token");

    let token_address = match token_transaction {
        Some(x) => x.get_one::<String>("token-address").unwrap_or(&empty),
        _ => "empty",
    };

    // checking token balance
    if let Some(("erc20-token", erc20_matches)) = match_result.subcommand() {
        let token_address = erc20_matches.get_one::<String>("token-address").unwrap();
        let token_contract_address = Address::from_str(token_address).unwrap();
        let erc20 = ERC20::new(token_contract_address, provider.clone());

        if let Some(("token-balance", balance_matches)) = erc20_matches.subcommand() {
            let token_holder = balance_matches.get_one::<String>("token-holder").unwrap();
            let token_holder_address = Address::from_str(token_holder).unwrap();
            let token_balance = erc20.balanceOf(token_holder_address).call().await?;

            println!("Token balance for user is: {}", token_balance);
        }
    }

    // Checking token allowance

    if let Some(("erc20-token", erc20_matches)) = match_result.subcommand() {
        let token_address = erc20_matches.get_one::<String>("token-address").unwrap();
        let token_contract_address = Address::from_str(token_address).unwrap();
        let erc20 = ERC20::new(token_contract_address, provider.clone());

        if let Some(("token-allowance", balance_matches)) = erc20_matches.subcommand() {
            let token_owner = balance_matches.get_one::<String>("token-owner").unwrap();
            let token_spender = balance_matches.get_one::<String>("token-spender").unwrap();

            let token_owner_address = Address::from_str(token_owner).unwrap();
            let token_spender_address = Address::from_str(token_spender).unwrap();

            let token_balance = erc20
                .allowance(token_owner_address, token_spender_address)
                .call()
                .await?;

            println!("Token allowance for spender is: {}", token_balance);
        }
    }

    // Integrating erc20 token contract write ops

    if let Some(("erc20-token", erc20_matches)) = match_result.subcommand() {
        let token_address = erc20_matches.get_one::<String>("token-address").unwrap();
        let token_contract_address = Address::from_str(token_address).unwrap();
        let erc20 = ERC20::new(token_contract_address, provider_signer.clone());

        if let Some(("token-transfer", balance_matches)) = erc20_matches.subcommand() {
            let token_recipient = balance_matches
                .get_one::<String>("token-recipient")
                .unwrap();
            let transfer_amount = balance_matches
                .get_one::<String>("transfer-amount")
                .unwrap();

            let transfer_amount_transform = U256::from_str_radix(transfer_amount, 10).unwrap();
            let transfer_data = transfer_amount_transform.wrapping_mul(U256::from(10e5));
            let token_recipient_transform = Address::from_str(token_recipient).unwrap();

            let transfer_tx = erc20
                .transfer(token_recipient_transform, transfer_data)
                .send()
                .await?;
            let reciept_tx = transfer_tx.get_receipt().await?;

            println!(
                "Transfer transaction completed successfully and tx hash is {}",
                reciept_tx.transaction_hash
            );

            println!("{} {}", token_recipient, transfer_amount);
        }
    }

    Ok(())
}
