
#! /bin/sh

CONTAINER_NAME="ft_ping-container-debian:7"

chmod +x gensources.sh
./gensources.sh

docker build -t ${CONTAINER_NAME} .
docker run -d ${CONTAINER_NAME}
