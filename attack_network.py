import socket
import time
import threading
import sys

TARGET_IP = "127.0.0.1"
TARGET_PORT = 9001 # Default P2P Port
ATTACK_DURATION = 10

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

def slowloris_attack(thread_id):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((TARGET_IP, TARGET_PORT))
        log(f"Thread {thread_id}: Connected via TCP")
        
        # Send partial header/handshake
        s.send(b"HELL") # Incomplete "HELLO"
        log(f"Thread {thread_id}: Sent partial data 'HELL'. Waiting...")
        
        # Wait longer than the 5s timeout
        time.sleep(7) 
        
        # Try to send more
        try:
            s.send(b"O:WORLD")
            log(f"Thread {thread_id}: ❌ SCANDAL! Still connected after 7s! Verification FAILED.")
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            log(f"Thread {thread_id}: ✅ SUCCESS! Connection dropped by server (Timeout worked).")
            
        s.close()
    except Exception as e:
        log(f"Thread {thread_id}: Error: {e}")

def buffer_overflow_attack():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET_IP, TARGET_PORT))
        log("BufferOverflow: Connected. Sending 70KB of data...")
        
        # Create 70KB payload (Limit is 64KB)
        payload = b"A" * 70000
        s.sendall(payload)
        
        # Check if server processes it or disconnects
        # If server uses read_exact or buffered read with limit, it might just read 64kb
        # But if we rely on `read(&buffer)`, it will read up to 64KB and ignore the rest or process it in next loop.
        # The key is: DOES IT CRASH?
        
        log("BufferOverflow: Data sent. Checking for server crash...")
        time.sleep(2)
        s.close()
        log("BufferOverflow: Done.")
    except Exception as e:
        log(f"BufferOverflow Error: {e}")

if __name__ == "__main__":
    log("🚀 Starting Stress Test / Audit Verification")
    
    # 1. Slowloris Test (Timeout Verification)
    log("--- Phase A: Slowloris (Timeout) Test ---")
    threads = []
    for i in range(5):
        t = threading.Thread(target=slowloris_attack, args=(i,))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
        
    # 2. Buffer Test
    log("\n--- Phase B: Large Payload Test ---")
    buffer_overflow_attack()
    
    log("\n✅ Stress Test Sequence Complete. Verify Node logs for 'Connection Timed Out' and NO Panic.")
