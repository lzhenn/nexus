#!/bin/bash
cd "$(dirname "$0")"

# Kill existing instance
./stop.sh 2>/dev/null

# Source SMTP config if available
if [ -f .env ]; then
    set -a; source .env; set +a
fi

nohup python3 app.py > nexus.log 2>&1 &
echo $! > nexus.pid
echo "Nexus started with PID $(cat nexus.pid)"
