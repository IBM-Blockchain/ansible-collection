..
.. SPDX-License-Identifier: Apache-2.0
..

Migrating from v1.2 to version 2
================================

Consistent with a major version upgrade, the following are important changes between v1.2 and v2

- For the latest ansible(current is 2.13.1), Your python3 version should at least be 3.8.
    python3.9 is used for the docker image. And we do not test against python3.11.
- All the dependencies in requirent.txt should be the latest version.