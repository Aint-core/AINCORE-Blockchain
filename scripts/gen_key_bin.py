import secrets
# Generate 32 bytes raw binary
key = secrets.token_bytes(32)
import sys
sys.stdout.buffer.write(key)
