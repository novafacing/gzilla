#Dockerfile for attacker
FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update && \
    apt-get install -y \
    build-essential \
    bind9 \
    python3 \
    python3-pip \
    bash \
    wireshark

COPY requirements.txt ./
RUN pip3 install -r requirements.txt
RUN rm -f requirements.txt

COPY ./attacker_files/example.edu.db /etc/bind/example.edu.db
COPY ./attacker_files/named.conf.local /etc/bind/named.conf.local

RUN mkdir -p /attacker_files
WORKDIR /attacker_files

ENTRYPOINT ["bash"]
