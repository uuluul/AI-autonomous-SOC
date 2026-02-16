# 使用輕量級 Python 3.9
FROM python:3.9-slim

# 設定工作目錄
WORKDIR /app

# 1. 先複製 requirements.txt 並安裝所有套件 (包含 dotenv, stix2, opensearch-py 等)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. 修正複製路徑：把本地的 src 複製到容器的 /app/src
# 這樣容器裡的路徑結構就會是 /app/src/run_pipeline.py
COPY src/ /app/src/

# 3. 設定 Python 路徑，確保程式能 import src 模組
ENV PYTHONPATH=/app

# [Security] Create a non-root user
RUN useradd -m -u 1000 socuser && \
    chown -R socuser:socuser /app

# Switch to non-root user
USER socuser

# 預設指令
CMD ["python", "/app/src/app_ui.py"]