
import serial
import time
import requests
import json
import logging
from typing import Optional

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("Apex7600Driver")

class Apex7600Driver:
    """
    Driver for Apex 7600 Bill Acceptor via Serial (Pulse/RS232).
    """

    def __init__(self, port: str = '/dev/ttyUSB0', baud_rate: int = 9600):
        self.port_name = port
        self.baud_rate = baud_rate
        self.serial_conn: Optional[serial.Serial] = None
        self.is_running = False
        
        # AINCORE Configuration
        self.rpc_url = "http://localhost:8545"
        self.machine_private_key = "0x..." # Setup during deployment
        self.machine_address = "0x..." 
        
        # Bill Mapping (Pulse Count -> USD Value)
        # 1 Pulse = $1
        self.bill_map = {
            1: 100,  # $1.00
            5: 500,  # $5.00
            10: 1000, # $10.00
            20: 2000, # $20.00
            50: 5000, # $50.00
            100: 10000 # $100.00
        }

    def connect(self):
        """Connect to the serial port."""
        try:
            self.serial_conn = serial.Serial(
                self.port_name,
                self.baud_rate,
                timeout=1
            )
            logger.info(f"✅ Connected to Bill Acceptor on {self.port_name}")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to connect to serial port: {e}")
            return False

    def listen_loop(self):
        """Main loop to listen for bill events."""
        if not self.serial_conn:
            if not self.connect():
                return

        self.is_running = True
        logger.info("👀 Listening for bills...")

        # Buffer for pulse counting logic (if simple pulse mode)
        # Real Apex 7600 RS232 protocol is more complex bytes.
        # This is a simplified Pulse/Serial reader.
        
        while self.is_running:
            try:
                if self.serial_conn.in_waiting > 0:
                    data = self.serial_conn.read()
                    # Logic to identify bill value from pulse/byte
                    bill_value_cents = self.parse_bill_data(data)
                    
                    if bill_value_cents > 0:
                        logger.info(f"💵 Bill Inserted: ${bill_value_cents/100:.2f}")
                        self.process_sale(bill_value_cents)
                        
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in loop: {e}")
                time.sleep(1)
                self.connect() # Reconnect attempt

    def parse_bill_data(self, data: bytes) -> int:
        """
        Convert raw serial data to USD cents.
        """
        # Placeholder for specific Apex 7600 protocol byte parsing.
        # For prototype, we assume 1 byte integer = $ value.
        try:
            val = int.from_bytes(data, byteorder='big')
            if val in self.bill_map:
                return self.bill_map[val]
            # Map raw byte directly to dollars if simple protocol
            return val * 100 
        except:
            return 0

    def process_sale(self, amount_usd_cents: int):
        """
        Execute call to AINCORE Treasury to send AIN to user.
        """
        # User Interaction:
        # In a real machine, we need the USER'S ADDRESS.
        # Typically via QR Code Scanner on the machine.
        user_address = self.scan_qr_code() 
        
        if not user_address:
            logger.warning("Refund or Cancel: No User Address Scanned")
            return

        logger.info(f"🚀 Sending {amount_usd_cents} cents worth of AIN to {user_address}")
        
        try:
            tx_hash = self.call_treasury_contract(user_address, amount_usd_cents)
            logger.info(f"✅ Transaction Successful: {tx_hash}")
            self.display_message("AIN Sent! Check Wallet.")
        except Exception as e:
            logger.error(f"❌ Transaction Failed: {e}")
            self.display_message("Error! Contact Support.")

    def scan_qr_code(self) -> str:
        """
        Simulate getting user address (e.g. from camera/scanner input).
        For prototype, we read from a temporary file or input.
        """
        # return "0x123..." 
        logger.info("Waiting for QR Scan...")
        # In real kiosk logic, wait for camera input
        return "0xUserAddressFromQR"

    def call_treasury_contract(self, user: str, amount: int) -> str:
        """
        RPC Call to AINCORE Node to execute `treasury::sell_ain`.
        """
        payload = {
            "jsonrpc": "2.0",
            "method": "submit_entry_function",
            "params": {
                "function": "0x1::treasury::sell_ain",
                "arguments": [
                     user,
                     str(amount)
                ],
                "sender_key": self.machine_private_key # Local signing in production
            },
            "id": 1
        }
        
        resp = requests.post(self.rpc_url, json=payload)
        resp_data = resp.json()
        
        if "error" in resp_data:
            raise Exception(resp_data["error"])
            
        return resp_data["result"]["hash"]

    def display_message(self, msg: str):
        logger.info(f"[DISPLAY]: {msg}")

if __name__ == "__main__":
    driver = Apex7600Driver()
    driver.listen_loop()
