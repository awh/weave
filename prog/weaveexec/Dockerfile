FROM alpine

MAINTAINER Weaveworks Inc <help@weave.works>
LABEL works.weave.role=system

WORKDIR /home/weave
VOLUME /w
VOLUME /w-noop
ENTRYPOINT ["/home/weave/sigproxy", "/home/weave/weave"]

RUN apk add --update \
    curl \
    ethtool \
    iptables \
    iproute2 \
    util-linux \
    conntrack-tools \
    bind-tools \
  && rm -rf /var/cache/apk/*

ADD ./weave ./sigproxy ./weaveproxy /home/weave/
ADD ./netcheck ./docker_tls_args /usr/bin/
ADD ./weavewait /w/w
ADD ./weavewait_noop /w-noop/w
ADD ./docker.tgz /
