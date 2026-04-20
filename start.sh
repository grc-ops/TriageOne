#!/bin/bash
export PYTHONPATH=/app
uvicorn backend.main:app --host 0.0.0.0 --port 8000 &
sleep 3
streamlit run frontend/app.py --server.port 10000 --server.address 0.0.0.0 --server.headless true