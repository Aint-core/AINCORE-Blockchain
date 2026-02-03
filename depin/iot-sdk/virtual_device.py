import json
import time
import random
import paho.mqtt.client as mqtt
import nacl.signing
import nacl.encoding

# Configuration
BROKER = "broker.hivemq.com"
PORT = 1883
TOPIC = "aincore/devices/watch_01/data"

# Generate a new Identity for this session
signing_key = nacl.signing.SigningKey.generate()
verify_key = signing_key.verify_key
public_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()

print(f"⌚ Virtual Device Started.")
print(f"🔑 Public Key (Device ID): {public_key_hex}")

client = mqtt.Client()
client.connect(BROKER, PORT, 60)

while True:
    # 1. Simulate Sensors
    hr = 60 + random.randint(0, 40)
    spo2 = 95 + random.randint(0, 5)
    br = 12 + random.randint(0, 8)
    
    vitals = {
        "hr": hr,
        "spo2": spo2,
        "br": br
    }
    
    # 2. Create Payload (Canonical JSON)
    vitals_str = json.dumps(vitals, separators=(',', ':'))
    
    # 3. Sign Data (Ed25519)
    signature_bytes = signing_key.sign(vitals_str.encode('utf-8')).signature
    signature_hex = signature_bytes.hex()
    
    payload = {
        "device_id": public_key_hex,
        "vitals": vitals,
        "signature": signature_hex
    }
    
    # 4. Publish
    client.publish(TOPIC, json.dumps(payload))
    print(f"📤 Sent Data: HR={hr} SpO2={spo2} (Sig: {signature_hex[:8]}...)")
    
    time.sleep(5)
