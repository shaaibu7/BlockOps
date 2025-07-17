use alloy::{  providers::ProviderBuilder, signers::local::PrivateKeySigner};
use alloy::transports::http::reqwest::Url;
 use blockops::{
    erc20,
    ether
};
use inquire::{Select};
use inquire::error::InquireResult;
#[tokio::main]
async fn main() -> InquireResult<()> {
    dotenv::dotenv().ok();

    let rpc_url = std::env::var("RPC_URL").expect("RPC_URL not set in .env");
    let url: Url = rpc_url.parse().expect("Invalid RPC URL");
    let env_private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY not set in .env");
    let private_key: PrivateKeySigner = env_private_key.parse().expect("Invalid private key format");
    let signer_provider = ProviderBuilder::new()
            .wallet(private_key.clone())
            .connect_http(url);

    loop {
        let commands = vec![
            "Ether Transaction",
            "ERC20 Token",
            "DeFI (Swap)",
            "Chat with AI",
            "Exit"
        ];
        let command = Select::new(" Welcome to BlockOps! What would you like to do?", commands.clone())
            .with_help_message("BlockOps is A clo tool for Ethereum and tokens. Use arrow keys to navigate.")
            .prompt()?;

        match command.as_ref() {
            "Ether Transaction" => ether::run(&signer_provider).await?,
            "ERC20 Token" => erc20::run(&signer_provider).await?,
            "DeFi (Swap) " => println!("Defi Transaction"),
            "Chat With AI" => println!(" Chat with AI"),
            "Exit" => {
                println!("👋 Goodbye!");
                break;
            }
            _ => unreachable!(),
        }
    }
    Ok(())
}