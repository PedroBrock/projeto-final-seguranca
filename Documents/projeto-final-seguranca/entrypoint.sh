#!/bin/bash
# entrypoint.sh — sobe o honeypot em background e o dashboard em foreground.
# Uso: troque o CMD do Dockerfile para ["./entrypoint.sh"]
# e adicione COPY entrypoint.sh . + RUN chmod +x entrypoint.sh antes do USER honeypot.

set -e

python honeypot.py &
HONEYPOT_PID=$!

streamlit run dashboard.py --server.address=0.0.0.0 --server.port=8501 &
DASHBOARD_PID=$!

trap "kill $HONEYPOT_PID $DASHBOARD_PID" SIGINT SIGTERM
wait