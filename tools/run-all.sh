#!/usr/bin/env bash
# tools/run-all.sh
# ------------------------------------------------------------
# Starts all NestJS services in watch mode (in parallel)
# ------------------------------------------------------------

set -e  # Exit on first error

# List of Nest projects (as created by `nest g app ...`)
SERVICES=(
  api-gateway
  auth-service
  tenant-service
  product-service
  user-service
)

# Start each service in the background using Nest CLI directly
for SERVICE in "${SERVICES[@]}"; do
  echo "▶︎ Starting $SERVICE..."
  npx nest start "$SERVICE" --watch &
done

# Trap Ctrl+C and stop all background jobs
trap 'echo; echo "🛑 Stopping all services..."; kill 0' SIGINT

# Wait for all background jobs
wait

