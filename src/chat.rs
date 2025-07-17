use inquire::Text;
use reqwest::Client;
use std::error::Error;
use termimad::MadSkin;

use crate::types::{MessageResponse, OPenAiRequest};

/// Interactive chat function using inquire for user input
pub async fn interactive_chat(api_key: &str, open_ai_url: &str) -> Result<(), Box<dyn Error>> {
    let skin = MadSkin::default();
    let client = Client::new();

    println!("\n{}", "=".repeat(60));
    println!("🤖 Welcome to Interactive ChatGPT!");
    println!("💡 Type your message and press Enter. Type 'quit' or 'exit' to stop.");
    println!("{}", "=".repeat(60));

    loop {
        // Prompt user for input using inquire
        let user_message = Text::new("💭 Your message:")
            .with_placeholder("Ask me anything...")
            .with_help_message("Type 'quit' or 'exit' to end the conversation")
            .prompt();

        match user_message {
            Ok(message) => {
                // Check for exit commands
                let trimmed_message = message.trim().to_lowercase();
                if trimmed_message == "quit" || trimmed_message == "exit" {
                    println!("\n👋 Goodbye! Thanks for chatting!");
                    break;
                }

                // Skip empty messages
                if message.trim().is_empty() {
                    println!("⚠️  Please enter a message or type 'quit' to exit.");
                    continue;
                }

                // Create OpenAI request
                let body = OPenAiRequest {
                    model: "gpt-4o-mini".to_string(),
                    messages: vec![MessageResponse {
                        role: "user".to_string(),
                        content: message.clone(),
                    }],
                };

                println!("🔄 Sending message to ChatGPT...");

                // Make API request
                match client
                    .post(open_ai_url)
                    .bearer_auth(api_key)
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(response) => {
                        match response.json::<serde_json::Value>().await {
                            Ok(json_response) => {
                                if let Some(content) = json_response["choices"][0]["message"]["content"].as_str() {
                                    println!("\n🤖 ChatGPT Response:");
                                    println!("{}", "-".repeat(50));
                                    
                                    // Use termimad skin for formatting the response
                                    skin.print_text(content);
                                    
                                    println!("{}", "-".repeat(50));
                                    println!(); // Add spacing
                                } else {
                                    println!("❌ No response content received from OpenAI");
                                    
                                    // Debug: Print the full response structure
                                    if let Some(error) = json_response.get("error") {
                                        println!("🐛 Error from OpenAI: {}", error);
                                    } else {
                                        println!("🐛 Full response: {}", json_response);
                                    }
                                }
                            }
                            Err(e) => {
                                println!("❌ Failed to parse response: {}", e);
                                println!("💡 The API might have returned an unexpected format");
                            }
                        }
                    }
                    Err(e) => {
                        println!("❌ Failed to send request: {}", e);
                        println!("💡 Please check your internet connection and API key");
                        
                        // Check if it's an authentication error
                        if e.to_string().contains("401") {
                            println!("🔑 This looks like an authentication error. Please check your OPEN_AI_API_KEY");
                        }
                    }
                }
            }
            Err(inquire::InquireError::OperationCanceled) => {
                println!("\n👋 Chat cancelled. Goodbye!");
                break;
            }
            Err(inquire::InquireError::OperationInterrupted) => {
                println!("\n👋 Chat interrupted. Goodbye!");
                break;
            }
            Err(e) => {
                println!("❌ Error reading input: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Alternative chat function that maintains conversation history
pub async fn interactive_chat_with_history(api_key: &str, open_ai_url: &str) -> Result<(), Box<dyn Error>> {
    let skin = MadSkin::default();
    let client = Client::new();
    let mut conversation_history: Vec<MessageResponse> = Vec::new();

    println!("\n{}", "=".repeat(60));
    println!("🤖 Welcome to Interactive ChatGPT with History!");
    println!("💡 This version maintains conversation context.");
    println!("💡 Type your message and press Enter. Type 'quit' or 'exit' to stop.");
    println!("{}", "=".repeat(60));

    loop {
        // Prompt user for input using inquire
        let user_message = Text::new("💭 Your message:")
            .with_placeholder("Ask me anything...")
            .with_help_message("Type 'quit', 'exit', or 'clear' to manage conversation")
            .prompt();

        match user_message {
            Ok(message) => {
                // Check for exit commands
                let trimmed_message = message.trim().to_lowercase();
                if trimmed_message == "quit" || trimmed_message == "exit" {
                    println!("\n👋 Goodbye! Thanks for chatting!");
                    break;
                }

                // Check for clear command
                if trimmed_message == "clear" {
                    conversation_history.clear();
                    println!("🧹 Conversation history cleared!");
                    continue;
                }

                // Skip empty messages
                if message.trim().is_empty() {
                    println!("⚠️  Please enter a message or type 'quit' to exit.");
                    continue;
                }

                // Add user message to history
                conversation_history.push(MessageResponse {
                    role: "user".to_string(),
                    content: message.clone(),
                });

                // Create OpenAI request with full conversation history
                let body = OPenAiRequest {
                    model: "gpt-4o-mini".to_string(),
                    messages: conversation_history.clone(),
                };

                println!("🔄 Sending message to ChatGPT...");

                // Make API request
                match client
                    .post(open_ai_url)
                    .bearer_auth(api_key)
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(response) => {
                        match response.json::<serde_json::Value>().await {
                            Ok(json_response) => {
                                if let Some(content) = json_response["choices"][0]["message"]["content"].as_str() {
                                    println!("\n🤖 ChatGPT Response:");
                                    println!("{}", "-".repeat(50));
                                    
                                    // Use termimad skin for formatting the response
                                    skin.print_text(content);
                                    
                                    println!("{}", "-".repeat(50));
                                    println!(); // Add spacing

                                    // Add assistant response to history
                                    conversation_history.push(MessageResponse {
                                        role: "assistant".to_string(),
                                        content: content.to_string(),
                                    });
                                } else {
                                    println!("❌ No response content received from OpenAI");
                                    
                                    // Debug: Print the full response structure
                                    if let Some(error) = json_response.get("error") {
                                        println!("🐛 Error from OpenAI: {}", error);
                                    }
                                }
                            }
                            Err(e) => {
                                println!("❌ Failed to parse response: {}", e);
                                println!("💡 The API might have returned an unexpected format");
                            }
                        }
                    }
                    Err(e) => {
                        println!("❌ Failed to send request: {}", e);
                        println!("💡 Please check your internet connection and API key");
                        
                        // Check if it's an authentication error
                        if e.to_string().contains("401") {
                            println!("🔑 This looks like an authentication error. Please check your OPEN_AI_API_KEY");
                        }
                    }
                }
            }
            Err(inquire::InquireError::OperationCanceled) => {
                println!("\n👋 Chat cancelled. Goodbye!");
                break;
            }
            Err(inquire::InquireError::OperationInterrupted) => {
                println!("\n👋 Chat interrupted. Goodbye!");
                break;
            }
            Err(e) => {
                println!("❌ Error reading input: {}", e);
                break;
            }
        }
    }

    Ok(())
}