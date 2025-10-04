# DNS-over-HTTPS Proxy Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY dohproxy.py ./
COPY config.yaml ./

EXPOSE 5353/udp
EXPOSE 5353/tcp

CMD ["python", "dohproxy.py"]
