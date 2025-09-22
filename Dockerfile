FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install fastapi uvicorn

ENTRYPOINT ["python", "-m", "stackhawk_mcp.server"]