import paho.mqtt.client as mqtt
import json
import time
import random

# --- Configuration ---
MQTT_BROKER = "broker.hivemq.com"
MQTT_PORT = 1883
import hmac
import hashlib

# Configuration
BROKER = "broker.hivemq.com"
PORT = 1883
TOPIC = "aincore/devices/dev_001/data"
DEVICE_SECRET = "aincore_secret_key"

def generate_signature(vitals):
    """
    Generate HMAC-SHA256 signature for the vitals.
    """
    vitals_str = json.dumps(vitals, separators=(',', ':')) # Canonical JSON
    signature = hmac.new(
        DEVICE_SECRET.encode('utf-8'),
        vitals_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return signature

def on_connect(client, userdata, flags, rc):
    print(f"📡 Device Connected to Broker with result code {rc}")

client = mqtt.Client()
client.on_connect = on_connect

print(f"🔌 Connecting to {BROKER}...")
client.connect(BROKER, PORT, 60)

client.loop_start()

try:
    while True:
        # 1. Generate Sensor Data
        vitals = {
            "hr": random.randint(60, 100),
            "br": random.randint(12, 20),
            "spo2": random.randint(95, 100)
        }
        
        # 2. Sign Data
        signature = generate_signature(vitals)
        
        payload = {
            "device_id": "dev_001",
            "timestamp": time.time(),
            "vitals": vitals,
            "signature": signature
        }
        
        # 3. Publish
        json_payload = json.dumps(payload)
        print(f"📤 Publishing data to {TOPIC}: HR={vitals['hr']}, SpO2={vitals['spo2']}")
        client.publish(TOPIC, json_payload)
        
        time.sleep(5)

except KeyboardInterrupt:
    print("🛑 Device Simulator Stopped.")
    client.loop_stop()
    client.disconnect()
