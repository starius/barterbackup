FROM scratch
ARG BBD_BIN
COPY integration/docker/container-etc/ /etc/
COPY ${BBD_BIN} /bbd
ENTRYPOINT ["/bbd"]
