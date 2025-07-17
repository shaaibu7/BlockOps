use alloy::{  providers::ProviderBuilder, signers::local::PrivateKeySigner};
use alloy::transports::http::reqwest::Url;
 use blockops::{
    erc20,
    ether,
    chat 
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

    let api_key = std::env::var("OPEN_AI_API_KEY").unwrap_or_else(|_| {
        println!("OPEN_AI_API_KEY not found in environment variables");
        String::new()
    });
    let open_ai_url = std::env::var("OPEN_AI_URL").unwrap_or_else(|_| {
        "https://api.openai.com/v1/chat/completions".to_string()
    });


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
            "DeFI (Swap)" => println!("DeFI Transaction - Coming Soon!"),
            "Chat with AI" => { 
                if api_key.is_empty() {
                    println!("OpenAI API key is not configured. Please set OPEN_AI_API_KEY in your .env file");
                } else {
                    match chat::interactive_chat(&api_key, &open_ai_url).await {
                        Ok(_) => println!("Chat session completed"),
                        Err(e) => println!("Chat error: {}", e),
                    }
                }
            }
            "Exit" => {
                println!("👋 Goodbye!");
                break;
            }
            _ => unreachable!(),
        }
    }
    Ok(())
}