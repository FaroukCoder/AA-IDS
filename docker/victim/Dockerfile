FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nginx \
    openssh-server \
    python3 \
    python3-pip \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install scapy

# SSH setup — strong password ensures brute-force attempts always fail
RUN mkdir /var/run/sshd \
    && echo 'root:Xk9#mQ2!vL' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config

COPY nginx.conf /etc/nginx/nginx.conf
COPY capture/capture.py /capture/capture.py

EXPOSE 80 22
