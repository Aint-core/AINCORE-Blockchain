import json
import time
import math
import random
import hashlib

# --- Configuration ---
AINCORE_RPC = "http://localhost:8002/rpc"
ORACLE_PRIVATE_KEY = "..." # In real app, load from secure env

# --- BQI Calculation Logic ---
def calculate_bqi(heart_rate_data, breath_data, spo2):
    """
    Calculates Breath Quality Index (0-100)
    """
    # 1. RSA (Respiratory Sinus Arrhythmia) Simulation
    # Real RSA requires cross-correlation of HR and Breath.
    # Here we simulate it: if HR varies in sync with Breath, score is high.
    # For prototype, we assume data is already processed or we use simple variance.
    
    # High variance in HR (good for RSA) but within healthy range.
    hr_variance = calculate_variance(heart_rate_data)
    rsa_score = min(100, hr_variance * 5) 

    # 2. HRV (Heart Rate Variability) - RMSSD
    # RMSSD = sqrt(mean(diff(RR_intervals)^2))
    # We simulate RR intervals from HR data
    rr_intervals = [60000/hr for hr in heart_rate_data]
    diffs = [abs(rr_intervals[i+1] - rr_intervals[i]) for i in range(len(rr_intervals)-1)]
    sq_diffs = [d*d for d in diffs]
    rmssd = math.sqrt(sum(sq_diffs) / len(sq_diffs)) if sq_diffs else 0
    
    # Normalize RMSSD (Healthy range 20-100ms)
    hrv_score = min(100, max(0, (rmssd - 20) * 1.25))

    # 3. SpO2 Factor
    spo2_factor = 1.0
    if spo2 < 95:
        spo2_factor = max(0, 1.0 - (95 - spo2) * 0.1) # -10% per point below 95
    
    # 4. Stability (Variance of breath rate)
    # Lower variance is better.
    breath_variance = calculate_variance(breath_data)
    stability_score = max(0, 100 - breath_variance * 10)

    # Weights
    w1, w2, w3, w4 = 0.4, 0.3, 0.2, 0.1
    
    final_bqi = (w1 * rsa_score) + (w2 * hrv_score) + (w3 * (spo2_factor * 100)) + (w4 * stability_score)
    return int(final_bqi)

def calculate_variance(data):
    if not data: return 0
    mean = sum(data) / len(data)
    return sum((x - mean) ** 2 for x in data) / len(data)

# --- Oracle Service ---
def process_device_data(payload):
    """
    Process incoming JSON payload from IoT Device
    """
    try:
        data = json.loads(payload)
        device_id = data.get("device_id")
        signature = data.get("signature")
        
        # 1. Verify Signature (Mock)
        # verify_signature(device_id, signature, data['payload'])
        print(f"🔐 Verifying signature for device {device_id}...")
        
        # 2. Extract Sensor Data
        sensors = data.get("sensors", {})
        hr_data = sensors.get("heart_rate", []) # List of HR values
        breath_data = sensors.get("breath_rate", []) # List of Breath rates
    except Exception as e:
        print(f"❌ Error processing data: {e}")

import subprocess
import os
import paho.mqtt.client as mqtt
import hmac

# Configuration
BROKER = "broker.hivemq.com"
PORT = 1883
TOPIC = "aincore/devices/+/data"
DEVICE_SECRET = "aincore_secret_key" # Shared secret for HMAC

def calculate_bqi(hr, br, spo2):
    """
    Calculate Breath Quality Index (BQI)
    Real logic: Weighted average of vitals.
    """
    # Normalize inputs (simplified for prototype)
    # HR: 60-100 is good (1.0), else lower
    hr_score = 1.0 if 60 <= hr <= 100 else 0.8
    
    # SpO2: >95 is good (1.0), else lower
    spo2_score = 1.0 if spo2 >= 95 else 0.5
    
    # BR: 12-20 is good (1.0)
    br_score = 1.0 if 12 <= br <= 20 else 0.7

    bqi = (hr_score * 0.4) + (spo2_score * 0.4) + (br_score * 0.2)
    return round(bqi * 100, 2)

import nacl.signing
import nacl.exceptions

def verify_signature(payload_str, signature_hex, public_key_hex):
    """
    Verify Ed25519 signature.
    """
    try:
        # Create VerifyKey from hex
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(public_key_hex))
        
        # Verify
        verify_key.verify(payload_str.encode('utf-8'), bytes.fromhex(signature_hex))
        return True
    except nacl.exceptions.BadSignatureError:
        return False
    except Exception as e:
        print(f"⚠️ Verification Error: {e}")
        return False

# --- Key Management ---
private_key_hex = None

def load_key_from_keystore(path):
    import eth_keyfile
    import getpass
    import binascii
    
    print(f"🔐 Loading key from keystore: {path}")
    password = getpass.getpass("🔑 Enter keystore password: ")
    
    try:
        keydata = eth_keyfile.load_keyfile(path)
        private_key_bytes = eth_keyfile.decode_keyfile_json(keydata, password.encode())
        return binascii.hexlify(private_key_bytes).decode()
    except Exception as e:
        print(f"❌ Failed to decrypt key: {e}")
        exit(1)

def submit_mining_proof(device_id, bqi):
    """
    Submit proof to AINCORE blockchain via helper script.
    """
    global private_key_hex
    print(f"🔗 Submitting Proof for {device_id} (BQI: {bqi})...")
    
    if not private_key_hex:
        print("⚠️  No private key loaded! Cannot submit proof.")
        return

    try:
        # Call the TypeScript helper to sign and send
        # We pass the private key via STDIN
        cmd = ["npx", "ts-node", "../../aincore-js/submit_proof.ts", device_id, str(bqi)]
        
        process = subprocess.Popen(
            cmd, 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        
        stdout, stderr = process.communicate(input=private_key_hex)
        
        if process.returncode == 0:
            print(stdout)
        else:
            print(f"❌ Submission Failed: {stderr}")
            print(f"Stdout: {stdout}")
            
    except Exception as e:
        print(f"❌ Error calling submit script: {e}")

def on_connect(client, userdata, flags, rc):
    print(f"✅ Connected to MQTT Broker (RC: {rc})")
    client.subscribe(TOPIC)
    print(f"📡 Subscribed to {TOPIC}")

def on_message(client, userdata, msg):
    try:
        payload_str = msg.payload.decode()
        data = json.loads(payload_str)
        
        device_id = data.get("device_id")
        signature = data.get("signature")
        
        # 1. Verify Signature (Ed25519)
        # In a real system, we fetch the device's public key from the Blockchain (Registry).
        # For this prototype, we assume the device_id IS the public key (or we have a mapping).
        # Let's assume device_id is the hex public key.
        device_pubkey = device_id 
        
        vitals = data.get("vitals")
        vitals_str = json.dumps(vitals, separators=(',', ':')) # Canonical JSON
        
        if not verify_signature(vitals_str, signature, device_pubkey):
            print(f"⚠️ Invalid Ed25519 Signature from {device_id}. Dropping.")
            return

        print(f"📩 Received Data from {device_id}: HR={vitals['hr']}, SpO2={vitals['spo2']}")

        # 2. Calculate BQI
        bqi = calculate_bqi(vitals['hr'], vitals['br'], vitals['spo2'])
        print(f"🧮 Calculated BQI: {bqi}")

        # 3. Submit Proof
        submit_mining_proof(device_id, bqi)

    except Exception as e:
        print(f"❌ Error processing message: {e}")

# --- Main Execution ---
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--keystore", help="Path to keystore file")
    args = parser.parse_args()

    if args.keystore:
        private_key_hex = load_key_from_keystore(args.keystore)

    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    
    print("🔮 AINCORE Bio-Oracle Starting (REAL MQTT MODE)...")
    try:
        client.connect(BROKER, PORT, 60)
        client.loop_forever()
    except Exception as e:
        print(f"❌ MQTT Connection Failed: {e}")