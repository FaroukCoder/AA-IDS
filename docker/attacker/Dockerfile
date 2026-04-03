FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-scapy \
    python3-paramiko \
    python3-requests \
    nmap \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages rich

COPY attacks/ /attacks/

WORKDIR /attacks
