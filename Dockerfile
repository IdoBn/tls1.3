FROM ubuntu:18.04

RUN yes | apt update
RUN yes | apt install python3.7 python3-pip python3-dev
RUN yes | apt install wget ipython3
RUN yes | wget https://github.com/dlitz/pycrypto/archive/v2.7a1.tar.gz
RUN pip3 install v2.7a1.tar.gz
RUN pip3 install cryptography pytest dataclasses
RUN pip3 install -U cryptography>=2.7

RUN mkdir workspace

WORKDIR /workspace

COPY ./*.py ./