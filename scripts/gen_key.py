import secrets
# Generate 32 bytes (64 hex chars)
key = secrets.token_hex(32)
print(key, end="")
