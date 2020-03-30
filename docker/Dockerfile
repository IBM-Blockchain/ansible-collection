#
# SPDX-License-Identifier: Apache-2.0
#

# In the first stage, install all the development packages, so we can build the native Python modules.
FROM alpine:3.11 AS builder
RUN apk add --no-cache build-base libffi-dev openssl-dev python3 python3-dev
RUN pip3 install --user ansible fabric-sdk-py
ENV PATH=/root/.local/bin:$PATH
RUN ansible-galaxy collection install ibm.blockchain_platform

# In the second stage, copy all the installed Python modules across from the first stage.
FROM alpine:3.11
RUN apk add --no-cache python3
COPY --from=builder /root/.local /root/.local
COPY --from=builder /root/.ansible /root/.ansible
ENV PATH=/root/.local/bin:$PATH