#!/usr/bin/env bash
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"
echo "🛡️  TriageOne v1.3"
[ ! -f .env ] && cp .env.example .env && echo "Created .env from template — add your API keys"
pip install -r requirements.txt --quiet 2>/dev/null || pip install -r requirements.txt
echo "Starting backend on :8000 and frontend on :8501..."
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload &
sleep 3
streamlit run frontend/app.py --server.port 8501 --server.address 127.0.0.1 &
echo "Ready! Frontend: http://127.0.0.1:8501 | API: http://127.0.0.1:8000/docs"
trap "kill %1 %2 2>/dev/null; exit 0" SIGINT SIGTERM
wait
