FROM python:3.12-slim

# Playwright 의존성 (Chromium headless)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl ca-certificates \
    libnss3 libatk-bridge2.0-0 libdrm2 libxkbcommon0 libgbm1 \
    libgtk-3-0 libasound2 libxcomposite1 libxdamage1 libxrandr2 \
    libpangocairo-1.0-0 libcairo2 libcups2 libx11-xcb1 libxcb-dri3-0 \
    fonts-liberation xvfb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwright Chromium 브라우저 설치 (deps는 위에서 수동 설치)
RUN playwright install chromium

COPY . .

EXPOSE 8090
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8090"]
