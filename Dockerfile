FROM debian:buster

RUN apt-get update
RUN apt-get install -y build-essential
RUN apt-get install -y cmake
RUN apt-get install -y libgtest-dev
RUN apt-get install -y emacs-nox
RUN apt-get install -y man

RUN apt-get install -y softhsm2-common libsofthsm2-dev
