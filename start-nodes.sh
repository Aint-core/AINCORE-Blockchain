for i in {1..4}
do
  PORT=$((9000 + i))
  LOG_FILE="logs/node_${PORT}.log"

  echo "🚀 Starting node on port ${PORT}..."
  cargo run --release --bin node -- --port ${PORT} > "$LOG_FILE" 2>&1 &

  sleep 2
done

echo "✅ All nodes started successfully!"
