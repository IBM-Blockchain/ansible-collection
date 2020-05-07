#
# SPDX-License-Identifier: Apache-2.0
#

# In the first stage, install all the development packages, so we can build the native Python modules.
FROM alpine:3.11 AS builder
RUN apk add --no-cache build-base curl libffi-dev openssl-dev python3 python3-dev
RUN pip3 install --user ansible fabric-sdk-py openshift
ENV PATH=/root/.local/bin:$PATH
RUN ansible-galaxy collection install ibm.blockchain_platform
RUN mkdir /opt/fabric \
    && curl -sSL https://github.com/hyperledger/fabric/releases/download/v1.4.6/hyperledger-fabric-linux-amd64-1.4.6.tar.gz | tar xvzf - -C /opt/fabric \
    && curl -sSL https://github.com/hyperledger/fabric-ca/releases/download/v1.4.6/hyperledger-fabric-ca-linux-amd64-1.4.6.tar.gz | tar xvzf - -C /opt/fabric

# In the second stage, copy all the installed Python modules across from the first stage.
FROM alpine:3.11
RUN apk add --no-cache bash python3 \
    && mkdir /lib64 \
    && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
COPY --from=builder /root/.local /root/.local
COPY --from=builder /root/.ansible /root/.ansible
COPY --from=builder /opt/fabric /opt/fabric
ENV FABRIC_CFG_PATH=/opt/fabric/config
ENV PATH=/opt/fabric/bin:/root/.local/bin:$PATH