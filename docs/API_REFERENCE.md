# AINCORE API Reference

> **Complete JSON-RPC API documentation**

---

## Overview

AINCORE node menyediakan JSON-RPC API untuk interaksi dengan blockchain.

**Default Endpoint:** `http://localhost:8001/rpc`

**Request Format:**
```json
{
    "method": "method_name",
    "params": [param1, param2, ...]
}
```

**Response Format:**
```json
{
    "result": { ... },
    "error": null
}
```

---

## Node Methods

### get_status

Get current node status.

**Request:**
```json
{
    "method": "get_status",
    "params": []
}
```

**Response:**
```json
{
    "node_id": "8f7d00f56518177823e32849fa9e5f83",
    "height": 12345,
    "round": 5678,
    "peers": 8,
    "synced": true,
    "version": "1.0.0"
}
```

---

### get_node_info

Get detailed node information.

**Request:**
```json
{
    "method": "get_node_info",
    "params": []
}
```

**Response:**
```json
{
    "node_id": "8f7d00f56518177823e32849fa9e5f83",
    "public_key": "a1b2c3...",
    "p2p_address": "/ip4/192.168.1.100/tcp/9000",
    "api_port": 8001,
    "chain_id": "AINCORE-MAINNET-1",
    "uptime_seconds": 86400
}
```

---

### get_peers

Get connected peers.

**Request:**
```json
{
    "method": "get_peers",
    "params": []
}
```

**Response:**
```json
{
    "peers": [
        {
            "peer_id": "12D3KooW...",
            "address": "/ip4/1.2.3.4/tcp/9000",
            "latency_ms": 50
        }
    ],
    "count": 1
}
```

---

## Account Methods

### get_balance

Get account balance.

**Request:**
```json
{
    "method": "get_balance",
    "params": ["8f7d00f56518177823e32849fa9e5f83"]
}
```

**Response:**
```json
{
    "address": "8f7d00f56518177823e32849fa9e5f83",
    "balance": "1000000000000000000",
    "nonce": 5
}
```

---

### get_account

Get full account data.

**Request:**
```json
{
    "method": "get_account",
    "params": ["8f7d00f56518177823e32849fa9e5f83"]
}
```

**Response:**
```json
{
    "address": "8f7d00f56518177823e32849fa9e5f83",
    "balance": "1000000000000000000",
    "nonce": 5,
    "public_key": "a1b2c3...",
    "staked": "500000000000000000",
    "delegated": "0"
}
```

---

### get_resources

Get Move resources for an account.

**Request:**
```json
{
    "method": "get_resources",
    "params": ["8f7d00f56518177823e32849fa9e5f83"]
}
```

**Response:**
```json
{
    "resources": [
        {
            "type": "0x1::coin::Balance<0x1::AIN>",
            "data": {
                "value": "1000000000000000000"
            }
        }
    ]
}
```

---

## Transaction Methods

### submit_transaction

Submit a signed transaction.

**Request:**
```json
{
    "method": "submit_transaction",
    "params": [{
        "sender": "8f7d00f56518177823e32849fa9e5f83",
        "action": "transfer",
        "payload": {
            "to": "a1b2c3d4e5f6...",
            "amount": "1000000000000000000"
        },
        "gas_limit": 100000,
        "gas_price": 1000,
        "nonce": 6,
        "chain_id": "AINCORE-MAINNET-1",
        "signature": "base64_encoded_signature"
    }]
}
```

**Response:**
```json
{
    "tx_hash": "0x123abc...",
    "status": "pending"
}
```

---

### get_transaction

Get transaction by hash.

**Request:**
```json
{
    "method": "get_transaction",
    "params": ["0x123abc..."]
}
```

**Response:**
```json
{
    "hash": "0x123abc...",
    "sender": "8f7d00f56518177823e32849fa9e5f83",
    "action": "transfer",
    "payload": {
        "to": "a1b2c3d4e5f6...",
        "amount": "1000000000000000000"
    },
    "status": "confirmed",
    "block_height": 12345,
    "gas_used": 21000,
    "timestamp": 1706900000
}
```

---

### get_pending_transactions

Get pending transactions from mempool.

**Request:**
```json
{
    "method": "get_pending_transactions",
    "params": []
}
```

**Response:**
```json
{
    "transactions": [...],
    "count": 42
}
```

---

## Block Methods

### get_block

Get block by height.

**Request:**
```json
{
    "method": "get_block",
    "params": [12345]
}
```

**Response:**
```json
{
    "height": 12345,
    "hash": "0xabc123...",
    "prev_hash": "0xdef456...",
    "proposer": "8f7d00f56518177823e32849fa9e5f83",
    "timestamp": 1706900000,
    "tx_count": 100,
    "transactions": ["0x111...", "0x222..."]
}
```

---

### get_latest_block

Get latest block.

**Request:**
```json
{
    "method": "get_latest_block",
    "params": []
}
```

---

### get_blocks

Get range of blocks.

**Request:**
```json
{
    "method": "get_blocks",
    "params": [12340, 12345]
}
```

---

## Validator Methods

### get_validators

Get active validator set.

**Request:**
```json
{
    "method": "get_validators",
    "params": []
}
```

**Response:**
```json
{
    "validators": [
        {
            "address": "8f7d00f56518177823e32849fa9e5f83",
            "stake": "100000000000000000000000",
            "commission": 5,
            "uptime": 99.9
        }
    ],
    "count": 10
}
```

---

### get_staking_info

Get staking information for an address.

**Request:**
```json
{
    "method": "get_staking_info",
    "params": ["8f7d00f56518177823e32849fa9e5f83"]
}
```

**Response:**
```json
{
    "staked": "100000000000000000000000",
    "delegated": "50000000000000000000000",
    "rewards_pending": "1000000000000000000",
    "delegators": 5
}
```

---

## Move Methods

### call_view_function

Call a Move view function (read-only).

**Request:**
```json
{
    "method": "call_view_function",
    "params": {
        "module": "0x1::coin",
        "function": "balance",
        "type_args": ["0x1::AIN"],
        "args": ["8f7d00f56518177823e32849fa9e5f83"]
    }
}
```

**Response:**
```json
{
    "result": ["1000000000000000000"]
}
```

---

### get_module

Get published Move module.

**Request:**
```json
{
    "method": "get_module",
    "params": ["0x1", "coin"]
}
```

---

## Transaction Actions

| Action | Description | Payload |
|--------|-------------|---------|
| `transfer` | Native token transfer | `{to, amount}` |
| `stake` | Stake tokens | `{amount}` |
| `unstake` | Unstake tokens | `{amount}` |
| `delegate` | Delegate stake | `{validator, amount}` |
| `publish_module` | Deploy Move module | `{bytecode}` |
| `call_function` | Call Move function | `{module, function, args}` |

---

## Error Codes

| Code | Message |
|------|---------|
| -32600 | Invalid request |
| -32601 | Method not found |
| -32602 | Invalid params |
| -32603 | Internal error |
| 1001 | Account not found |
| 1002 | Insufficient balance |
| 1003 | Invalid signature |
| 1004 | Invalid nonce |
| 1005 | Block not found |
| 1006 | Transaction not found |

---

## Rate Limits

| Endpoint Type | Limit |
|--------------|-------|
| Read (get_*) | 100/second |
| Write (submit_*) | 10/second |
| Heavy (get_blocks) | 10/second |

---

## WebSocket (Coming Soon)

Subscribe to real-time events:

```javascript
const ws = new WebSocket('ws://localhost:8001/ws');

ws.send(JSON.stringify({
    method: 'subscribe',
    params: ['new_blocks', 'new_transactions']
}));

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('Event:', data);
};
```

---

## SDK Examples

### JavaScript

```javascript
const response = await fetch('http://localhost:8001/rpc', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        method: 'get_balance',
        params: ['8f7d00f56518177823e32849fa9e5f83']
    })
});
const result = await response.json();
console.log('Balance:', result.balance);
```

### Python

```python
import requests

response = requests.post('http://localhost:8001/rpc', json={
    'method': 'get_balance',
    'params': ['8f7d00f56518177823e32849fa9e5f83']
})
result = response.json()
print(f"Balance: {result['balance']}")
```

### Rust

```rust
use reqwest;
use serde_json::json;

let client = reqwest::Client::new();
let response = client.post("http://localhost:8001/rpc")
    .json(&json!({
        "method": "get_balance",
        "params": ["8f7d00f56518177823e32849fa9e5f83"]
    }))
    .send()
    .await?;
```
