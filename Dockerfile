FROM debian:buster

RUN apt-get update 
RUN apt-get upgrade -y
RUN apt-get install -y build-essential libc6 gcc make bash valgrind traceroute

RUN mkdir -p /ft_traceroute

COPY Makefile /ft_traceroute/Makefile
COPY srcs /ft_traceroute/srcs
COPY includes /ft_traceroute/includes
COPY entrypoint.sh /ft_traceroute/entrypoint.sh
COPY srcs.mk /ft_traceroute/srcs.mk

RUN chmod +xw /ft_traceroute/entrypoint.sh

WORKDIR /ft_traceroute

ENTRYPOINT [ "/bin/sh", "entrypoint.sh" ]