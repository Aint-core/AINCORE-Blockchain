# Bridge Multi-Signature Deployment Guide

## Overview
This guide explains how to deploy and configure the multi-signature bridge contract.

## Prerequisites
- Node.js & npm installed
- Hardhat or Foundry
- 5 independent signers with private keys
- Access to EVM testnet (Sepolia, Goerli, etc.)

## Step 1: Install Dependencies

```bash
cd phase21-depin/bridge-rust/contracts
npm init -y
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
npx hardhat init
```

## Step 2: Configure Hardhat

Create `hardhat.config.js`:

```javascript
require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  solidity: "0.8.20",
  networks: {
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL,
      accounts: [process.env.DEPLOYER_PRIVATE_KEY]
    }
  }
};
```

## Step 3: Generate Signer Keys

```bash
# Generate 5 signer keypairs
for i in {1..5}; do
  openssl ecparam -name secp256k1 -genkey -noout -out signer_$i.pem
  openssl ec -in signer_$i.pem -pubout -out signer_$i_pub.pem
done
```

## Step 4: Deploy Contract

Create `scripts/deploy.js`:

```javascript
async function main() {
  const signers = [
    "0x1234...", // Signer 1 address
    "0x5678...", // Signer 2 address
    "0x9abc...", // Signer 3 address
    "0xdef0...", // Signer 4 address
    "0x1111...", // Signer 5 address
  ];

  const WrappedAIN = await ethers.getContractFactory("WrappedAIN");
  const wAIN = await WrappedAIN.deploy(signers);
  await wAIN.deployed();

  console.log("WrappedAIN deployed to:", wAIN.address);
}

main();
```

Deploy:
```bash
npx hardhat run scripts/deploy.js --network sepolia
```

## Step 5: Update Bridge Client

Update `bridge-rust/src/main.rs` to use multi-sig:

```rust
// Store contract address
const WRAPPED_AIN_ADDRESS: &str = "0x..."; // From deployment

// Load 3 signer keys (for 3-of-5 threshold)
let signer1 = load_keystore("signer_1.json", password)?;
let signer2 = load_keystore("signer_2.json", password)?;
let signer3 = load_keystore("signer_3.json", password)?;
```

## Step 6: Test Multi-Sig

```bash
# Test minting with 3 signatures
cargo test test_multisig_mint

# Test with insufficient signatures (should fail)
cargo test test_insufficient_signatures
```

## Security Checklist

- [ ] 5 signers are independent entities
- [ ] Private keys stored in hardware wallets
- [ ] Contract verified on Etherscan
- [ ] Timelock added for signer changes
- [ ] Emergency pause mechanism
- [ ] Audit by external firm

## Signer Distribution Recommendation

1. **Signer 1**: AINCORE Foundation
2. **Signer 2**: Independent Validator 1
3. **Signer 3**: Independent Validator 2
4. **Signer 4**: Community DAO
5. **Signer 5**: Security Partner

**Threshold**: Any 3 of 5 must sign to mint tokens.
