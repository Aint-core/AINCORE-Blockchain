# AINCORE — Modular Blockchain 🌐

AINCORE is a high-performance, modular Layer 1 blockchain built with Rust and Move. It features a DAG-based consensus (Narwhal/Bullshark), parallel execution, and native Account Abstraction.

## 🚀 Quick Start (Run Anywhere)

You can run a AINCORE node on any computer (Mac, Windows, Linux) using Docker.

### Prerequisites
- **Docker** & **Docker Compose** installed.

### Run Command
Simply run this in your terminal:

```bash
docker compose -f docker-compose.mainnet.yml up --build -d
```

This will start:
- **Validator Node** (Port 9002/8002)
- **Indexer** (Port 3001)
- **Prometheus** (Port 9090)

### Check Status
```bash
docker ps
```

## 📚 Documentation

- **[Deployment Guide](DEPLOYMENT.md)**: Detailed instructions for multi-node setup and networking.
- **[API Documentation](http://localhost:8002/docs)**: (Available when node is running)

## 🛠️ Development

To build from source (requires Rust):
```bash
cargo build --release
```

## 🤝 Contributing
Pull requests are welcome! Please read `CONTRIBUTING.md` (coming soon).
