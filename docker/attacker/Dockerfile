FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y \
    nmap \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    scapy \
    paramiko \
    requests \
    rich

COPY attacks/ /attacks/

WORKDIR /attacks
