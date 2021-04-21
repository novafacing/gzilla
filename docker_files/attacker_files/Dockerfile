# Dockerfile for attacker
FROM ubuntu:18.04

# No interactive installation
ENV DEBIAN_FRONTEND noninteractive

# Update & install packages
RUN apt-get -y update && \
    apt-get install -y \
    build-essential \
    bind9 \
    bind9utils \
    python3 \
    python3-pip \
    bash \
    vim \
    dnsutils \
    iputils-ping \
    wireshark

# Install python packages
COPY requirements.txt ./
RUN pip3 install -r requirements.txt
RUN rm -f requirements.txt

# Set up bind9 config files
COPY ./attacker_files/example.edu.db /etc/bind/example.edu.db
COPY ./attacker_files/named.conf.local /etc/bind/named.conf.local
COPY ./attacker_files/resolv.conf /etc/resolv.conf

COPY ./init.sh /init.sh

RUN mkdir -p /attacker_files
WORKDIR /attacker_files

ENTRYPOINT ["/init.sh"]
