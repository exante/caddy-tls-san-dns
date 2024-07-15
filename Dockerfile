FROM docker.io/library/golang:1.22.5-bullseye
WORKDIR /opt/caddy
COPY . .
RUN apt update && apt install -y debian-keyring debian-archive-keyring apt-transport-https
RUN curl -1sLf 'https://dl.cloudsmith.io/public/caddy/xcaddy/debian.deb.txt' > /etc/apt/sources.list.d/caddy-xcaddy.list && apt-get --allow-insecure-repositories update && apt-get --allow-unauthenticated install xcaddy
CMD xcaddy run
