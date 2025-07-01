use alloy::{
    network::TransactionBuilder,
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    rpc::{types::TransactionRequest},
    signers::local::PrivateKeySigner,
    transports::http::reqwest::Url,
};
use clap::{Arg, Command, command};
use core::panic;
use std::error::Error;
use dotenv::dotenv;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();

    let rpc_endpoint = env::var("RPC_URL").unwrap_or_else(|_| panic!("RPC url not found"));

    let match_result = command!()
        .subcommand(
            Command::new("ether-transaction")
                .arg(
                    Arg::new("wallet-address")
                        .long("wallet-address")
                        .short('w')
                        .required(true)
                        .conflicts_with_all(["private-key", "address-to-send-ether", "amount-to-send"])
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
        .get_matches();

    let ether_transaction = match_result.subcommand_matches("ether-transaction");

    let wallet_address = match ether_transaction
        .unwrap_or_else(|| panic!("No wallet address found"))
        .get_one::<String>("wallet-address")
    {
        Some(x) => x,
        _ => "empty",
    };
    let private_key = match ether_transaction.unwrap_or_else(|| panic!("No private key found")) .get_one::<String>("private-key") {
        Some(x) => x,
        _ => "empty",
    };

    let wallet_address_to_send_ether = match ether_transaction
        .unwrap()
        .get_one::<String>("address-to-send-ether")
    {
        Some(x) => x,
        _ => "empty",
    };

    let amount_of_ether = match ether_transaction
        .unwrap()
        .get_one::<String>("amount-to-send")
    {
        Some(x) => x,
        _ => "empty",
    };

    let rpc_url: Url =
        rpc_endpoint.parse()?;

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
        // println!(
        //     "{:?} {:?} {:?}",
        //     private_key, wallet_address_to_send_ether, amount_of_ether
        // );
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

        println!("Transaction successfull and included in block number {}", reciept.block_number.expect("Failed to get the block number..."))
    }

    Ok(())
}
