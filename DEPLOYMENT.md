# AINCORE Deployment Guide 🚀

Yes, you can run AINCORE on any computer (Linux, Mac, Windows) that supports Docker!

## Prerequisites
- **Docker** & **Docker Compose** installed.
- Internet connection (for pulling base images).

## Option 1: The Easy Way (Docker)

This is the recommended method. You don't need to install Rust or any dependencies.

### 1. Copy Files
Transfer the entire `aincore` project folder to the new computer.
Or, if you have it on GitHub, just clone it:
```bash
git clone https://github.com/your-repo/aincore.git
cd aincore
```

### 2. Run the Node
Run the following command to build and start the node:
```bash
docker compose -f docker-compose.mainnet.yml up --build -d
```

### 3. Verify
Check if it's running:
```bash
docker ps
```
You should see `aincore-validator-1`, `aincore-indexer`, etc.

## Option 2: Multi-Node Setup (Connecting Computers) 🌐

If you want Computer A and Computer B to talk to each other (form a network):

1.  **Network**: Both computers must be able to ping each other (Same Wi-Fi/LAN is easiest).
2.  **Config**:
    *   **Computer A (Seed Node)**: Run as usual. Note its IP (e.g., `192.168.1.10`).
    *   **Computer B (Peer)**:
        Edit `docker-compose.mainnet.yml` on Computer B.
        Change the `AINCORE_PEERS` environment variable:
        ```yaml
        environment:
          - AINCORE_PEERS=192.168.1.10:9002  # IP of Computer A
        ```
3.  **Start**: Run `docker compose up` on both. They will connect and sync blocks!

## Hardware Requirements (Minimum)
- **CPU**: 2 Cores
- **RAM**: 4GB (8GB recommended for compilation)
- **Storage**: 20GB SSD
