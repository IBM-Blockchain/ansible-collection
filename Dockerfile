#
# SPDX-License-Identifier: Apache-2.0
#

# In the first stage, install the common dependencies, and then set up the standard user.
FROM registry.access.redhat.com/ubi8/ubi-minimal AS base
RUN microdnf install python38 shadow-utils \
    && groupadd -g 7051 ibp-user \
    && useradd -u 7051 -g ibp-user -G root -s /bin/bash ibp-user \
    && chgrp -R root /home/ibp-user /etc/passwd \
    && chmod -R g=u /home/ibp-user /etc/passwd \
    && microdnf remove shadow-utils \
    && microdnf clean all

# In the second stage, install all the development packages, install the Python dependencies,
# and then install the Ansible collection.
FROM base AS builder
RUN microdnf install gcc gzip python38-devel tar \
    && microdnf clean all
USER ibp-user
ENV PATH=/home/ibp-user/.local/bin:$PATH
RUN pip3.8 install --user -U 'ansible>=2.9,<2.10' fabric-sdk-py python-pkcs11 'openshift==0.11.2' semantic_version \
    && chgrp -R root /home/ibp-user/.local \
    && chmod -R g=u /home/ibp-user/.local
ADD . /tmp/collection
RUN cd /tmp/collection \
    && ansible-galaxy collection build --output-path /tmp \
    && ansible-galaxy collection install /tmp/ibm-blockchain_platform-*.tar.gz \
    && chgrp -R root /home/ibp-user/.ansible \
    && chmod -R g=u /home/ibp-user/.ansible

# In the third stage, build the Hyperledger Fabric binaries with HSM enabled (this is not the default).
FROM base AS fabric
RUN microdnf install git make tar gzip which findutils gcc \
    && microdnf clean all
RUN ARCH=$(uname -m) \
    && if [ "${ARCH}" = "x86_64" ]; then ARCH=amd64; fi \
    && if [ "${ARCH}" = "aarch64" ]; then ARCH=arm64; fi \
    && curl -sSL https://dl.google.com/go/go1.14.15.linux-${ARCH}.tar.gz | tar xzf - -C /usr/local
ENV GOPATH=/go
ENV PATH=/usr/local/go/bin:$PATH
RUN mkdir -p /go/src/github.com/hyperledger \
    && cd /go/src/github.com/hyperledger \
    && git clone -n https://github.com/hyperledger/fabric.git \
    && cd fabric \
    && git checkout v2.2.1 \
    # FAB-18175 - ignore expired signer certificates when submitting transactions.
    && git remote add jyellick https://github.com/jyellick/fabric.git \
    && git fetch jyellick \
    && git format-patch --stdout -1 459fca8f6a62198b63e6705c83897b98d64ae478 msp/mspimplsetup.go | git apply -
RUN cd /go/src/github.com/hyperledger/fabric \
    && make configtxlator peer GO_TAGS=pkcs11 EXECUTABLES=

# In the final stage, copy all the installed Python modules across from the second stage and the Hyperledger
# Fabric binaries from the third stage.
FROM base
COPY --from=builder /home/ibp-user/.local /home/ibp-user/.local
COPY --from=builder /home/ibp-user/.ansible /home/ibp-user/.ansible
COPY --from=fabric /go/src/github.com/hyperledger/fabric/build/bin /opt/fabric/bin
COPY --from=fabric /go/src/github.com/hyperledger/fabric/sampleconfig /opt/fabric/config
COPY docker/docker-entrypoint.sh /
ENV FABRIC_CFG_PATH=/opt/fabric/config
ENV PATH=/opt/fabric/bin:/home/ibp-user/.local/bin:$PATH
USER 7051
ENTRYPOINT [ "/docker-entrypoint.sh" ]
