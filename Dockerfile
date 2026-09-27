FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 tcpdump && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt scikit-learn pandas joblib
COPY backend/ ./backend/
COPY ml/rf_v1.joblib ml/metrics.json ./ml/
COPY samples/ ./samples/
ENV HOME=/root
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "/app/backend"]
