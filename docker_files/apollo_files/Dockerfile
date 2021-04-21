#Dockerfile for apollo
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
COPY ./apollo_files/named.conf.default-zones /etc/bind/named.conf.default-zones
COPY ./apollo_files/db.attacker /etc/bind/db.attacker

COPY ./init.sh .

RUN mkdir -p /apollo_files
WORKDIR /apollo_files

ENTRYPOINT ["/init.sh"]
