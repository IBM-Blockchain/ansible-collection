#
# SPDX-License-Identifier: Apache-2.0
#

# In the first stage, install all the development packages, so we can build the native Python modules.
FROM registry.access.redhat.com/ubi8/ubi-minimal AS builder
RUN microdnf install gcc gzip python38 python38-devel tar
RUN pip3.8 install --user ansible fabric-sdk-py python-pkcs11 openshift
ENV PATH=/root/.local/bin:$PATH
RUN ansible-galaxy collection install ibm.blockchain_platform
RUN mkdir /opt/fabric \
    && curl -sSL https://github.com/hyperledger/fabric/releases/download/v1.4.7/hyperledger-fabric-linux-amd64-1.4.7.tar.gz | tar xvzf - -C /opt/fabric \
    && curl -sSL https://github.com/hyperledger/fabric-ca/releases/download/v1.4.7/hyperledger-fabric-ca-linux-amd64-1.4.7.tar.gz | tar xvzf - -C /opt/fabric

# In the second stage, copy all the installed Python modules across from the first stage.
FROM registry.access.redhat.com/ubi8/ubi-minimal
RUN microdnf install python38
COPY --from=builder /root/.local /root/.local
COPY --from=builder /root/.ansible /root/.ansible
COPY --from=builder /opt/fabric /opt/fabric
ENV FABRIC_CFG_PATH=/opt/fabric/config
ENV PATH=/opt/fabric/bin:/root/.local/bin:$PATH