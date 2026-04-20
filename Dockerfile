FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN [ ! -f .env ] && cp .env.example .env || true
EXPOSE 8000 8501
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost:8000/health || exit 1
CMD ["bash", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port 8000 & sleep 3 && streamlit run frontend/app.py --server.port 8501 --server.address 0.0.0.0 & wait"]
