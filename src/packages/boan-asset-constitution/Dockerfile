FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN addgroup --system boan && adduser --system --ingroup boan boan
USER boan
EXPOSE 8083
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8083"]
