#!/bin/bash
cd "$(dirname "$0")"
if [ -f nexus.pid ]; then
    kill "$(cat nexus.pid)" 2>/dev/null
    rm -f nexus.pid
    echo "Nexus stopped"
else
    echo "No PID file found"
fi
