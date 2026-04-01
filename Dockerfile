
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    file libmagic1 binutils ca-certificates iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/samples /app/artifacts /app/rules

EXPOSE 8000

CMD ["python", "run.py"]
