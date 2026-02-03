
import socket
import json
import time

TARGET_IP = "127.0.0.1"
TARGET_PORT = 9001

def send_tx(tx_json):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET_IP, TARGET_PORT))
        msg = f"TX:{tx_json}"
        s.sendall(msg.encode())
        s.close()
        print(f"Sent: {tx_json[:50]}...")
    except Exception as e:
        print(f"Error: {e}")

def test_chain_id():
    print("--- Testing Chain ID Enforcement ---")
    
    # 1. Valid Chain ID
    tx_valid = json.dumps({
        "chain_id": "AINCORE-MAINNET-1",
        "sender": "c4b14ae227ec4e1f661dbb0d15039f1c",
        "input_objects": [],
        "payload": "transfer:c4b14ae227ec4e1f661dbb0d15039f1c:1", # Self transfer 1 unit
        "gas_limit": 10000,
        "gas_price": 1,
        "sequence_number": 0, # Assuming 0 for test
        "public_key": "c4b14ae227ec4e1f661dbb0d15039f1c00000000000000000000000000000000", # Fake PK matching sender
        "signature": "00"*64 # Fake Sig (Will fail signature check but PASS chain_id check)
    })
    
    # 2. Invalid Chain ID
    tx_invalid = json.dumps({
        "chain_id": "AINCORE-TESTNET",
        "sender": "c4b14ae227ec4e1f661dbb0d15039f1c",
        "input_objects": [],
        "payload": "transfer:...",
        "gas_limit": 10000,
        "gas_price": 1,
        "sequence_number": 0,
        "public_key": "c4b14ae227ec4e1f661dbb0d15039f1c00000000000000000000000000000000",
        "signature": "00"*64
    })

    # 3. Missing Chain ID
    tx_missing = json.dumps({
        "sender": "c4b14ae227ec4e1f661dbb0d15039f1c",
        "input_objects": [],
        "payload": "transfer:...",
        "gas_limit": 10000,
        "gas_price": 1,
        "sequence_number": 0,
        "public_key": "c4b14ae227ec4e1f661dbb0d15039f1c00000000000000000000000000000000",
        "signature": "00"*64
    })

    print("Sending Valid ChainID Tx...")
    send_tx(tx_valid)
    time.sleep(1)
    
    print("Sending Invalid ChainID Tx...")
    send_tx(tx_invalid)
    time.sleep(1)
    
    print("Sending Missing ChainID Tx...")
    send_tx(tx_missing)
    print("Done. Check node logs for 'Invalid Chain ID' vs 'Invalid Signature'.")

if __name__ == "__main__":
    test_chain_id()
