#Dockerfile for apollo
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

COPY ./named.conf.default-zones /etc/bind/named.conf.default-zones
COPY ./db.attacker /etc/bind/db.attacker

RUN mkdir -p /apollo_files
WORKDIR /apollo_files

ENTRYPOINT ["bash"]
