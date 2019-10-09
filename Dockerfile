FROM debian:stable-slim

RUN apt-get update

RUN apt-get -y install automake
RUN apt-get -y install libtool
RUN apt-get -y install pkg-config
RUN apt-get -y install libglib2.0-dev
RUN apt-get -y install make

ENTRYPOINT /bin/bash
