# 🚀 BlockOps

**BlockOps** is a powerful and extensible Rust-based CLI tool for interacting with the Ethereum blockchain. It allows users to perform core on-chain operations directly from the terminal, such as checking Ether balances and sending Ether securely between accounts.

This tool is designed to grow into a comprehensive Web3 command-line assistant, with planned support for smart contract interaction, DeFi protocols, and more.

---

## ✨ Features (Current)

- 🔍 **Check Ether Balance**  
  Retrieve the ETH balance of any address on the Ethereum blockchain.

- 💸 **Send Ether**  
  Transfer ETH from one address to another with secure private key signing.

---

## 🛠 Usage

### ✅ Prerequisites

- Rust & Cargo: [Install Rust](https://www.rust-lang.org/tools/install)
- Ethereum Node Access: You’ll need an Ethereum RPC URL (e.g., from [Infura](https://infura.io), [Alchemy](https://www.alchemy.com).

```bash
git clone https://github.com/shaaibu7/BlockOps.git
cd blockops
cargo build --release

```

## 🔐 Using a `.env` File for Environment Variables

To avoid exposing sensitive data such as your Ethereum RPC URL or private keys directly on the command line, you can use a `.env` file to securely manage environment variables.

### 1. Create a `.env` file

In your project root directory, create a file named `.env` with the following content:

```env
RPC_URL=https://mainnet.infura.io/v3/YOUR_PROJECT_ID
```


## 📖 Command Usage

The `BlockOps` CLI uses subcommands to interact with the Ethereum blockchain. Currently, the main supported operations include:

- Sending Ether from one wallet to another
- Checking the Ether balance of any Ethereum address

All commands are accessible via the `ether-transaction` subcommand.

---

### 🚀 Send Ether

Send Ether from your wallet to another Ethereum address.

```bash
cargo run -- ether-transaction \
  --private-key $PRIVATE_KEY \
  --user-address 0xeCf1A521C97A7A0eA663161E17FE7B9476fE0495 \
  --amount 100
```
### 🚀 Check Ether Balance for wallet address

```
cargo run -- ether-transaction \
  --wallet-address 0xb725e575b82b57c73f81E51808Af1b2e8c4387bB

```
## Roadmap

Planned features for future versions of BlockOps:

### Smart Contract Interaction

- Read contract state using view functions
- Write to contracts (state-changing transactions)
- Load contract ABI and call any method
- Deploy smart contracts from CLI

### DeFi Integration

- Swap tokens using Uniswap, Curve, etc.
- Interact with lending protocols like Aave and Compound
- View DeFi positions and balances

### Developer Tools

- Encode/decode contract inputs and outputs (ABI utilities)
- Estimate gas usage
- Simulate transactions


## Contributing

Contributions are welcome! Please feel free to open an issue or submit a pull request if you find a bug or have a feature suggestion.

## License

MIT License © 2025 Shaaibu Suleiman

