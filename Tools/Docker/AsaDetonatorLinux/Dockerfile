FROM mcr.microsoft.com/mirror/docker/library/ubuntu:22.04

COPY Detonate.sh /Detonate.sh

COPY publish /asa

RUN chmod +x /Asa/Asa

RUN apt-get update && apt-get install -y \
    coreutils \
    iproute2

ENTRYPOINT ["sh", "/Detonate.sh"]