FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install fastapi uvicorn
EXPOSE 8080
# Default: run HTTP server
ENTRYPOINT ["uvicorn", "stackhawk_mcp.http_server:app", "--host", "0.0.0.0", "--port", "8080"]
# To run stdio: override entrypoint with
# docker run --entrypoint python ... -m stackhawk_mcp.server 