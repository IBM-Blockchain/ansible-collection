# Tutorial

This tutorial will demonstrate how to use the IBM Blockchain Platform collection for Ansible to automate the building of a two organization Hyperledger Fabric network.

## Overview

During this tutorial, you will execute several Ansible Playbooks. The Ansible Playbooks are named `<task number>-<task>.yml` and will be executed in order. Depending on your IBM Blockchain Platform configuration, you may not need to execute all of the Ansible Playbooks to complete this tutorial.

The Ansible Playbooks require variables that specify the IBM Blockchain Platform connection details, as well as the name, enrollment IDs and secrets for that organiation. These variables are stored in files named `<organization>.yml` and must be passed on the command line when executing an Ansible Playbook.

## Before you start

Edit the files [ordering-org-vars.yml](ordering-org-vars.yml) (Ordering Org), [org1-vars.yml](org1-vars.yml) (Org1), and [org2-vars.yml](org2-vars.yml) (Org2) with the IBM Blockchain Platform connection details for each organization.

Note that if all of the organizations use the same IBM Blockchain Platform console, you will need to skip certain steps. This is because all of the information is already present in the IBM Blockchain Platform console, and does not need to be imported.

## Steps

1. Create the components for the ordering organization Ordering Org

    - Organization: Ordering Org
    - Playbook: [01-create-ordering-organization-components.yml](01-create-ordering-organization-components.yml)
    - Command: `ansible-playbook 01-create-ordering-organization-components.yml --extra-vars "@ordering-org-vars.yml"`

    This playbook uses the Ansible Role `ibm.blockchain_platform.ordering_organization` to set up the certificate authority, organization (MSP), and ordering service components for the ordering organization Ordering Org.

2. Create the components for the endorsing organization Org1

    - Organization: Org1
    - Playbook: [02-create-endorsing-organization-components.yml](02-create-endorsing-organization-components.yml)
    - Command: `ansible-playbook 02-create-endorsing-organization-components.yml --extra-vars "@org1-vars.yml"`

    This playbook uses the Ansible Role `ibm.blockchain_platform.endorsing_organization` to set up the certificate authority, organization (MSP), and peer components for the endorsing organization Org1.

3. Export the organization for Org1

    Note: skip this step if all organizations are using the same IBM Blockchain Platform console.

    - Organization: Org1
    - Playbook: [03-export-organization.yml](03-export-organization.yml)
    - Command: `ansible-playbook 03-export-organization.yml --extra-vars "@org1-vars.yml"`

    This playbook uses the Ansible Module `ibm.blockchain_platform.organization_info` module to export the organization Org1 to a file.

    In a real deployment, this file must then be passed to the organization Ordering Org out of band, so they could import the organization Org1 into their IBM Blockchain Plaform console.

4. Import the organization for Org1

    Note: skip this step if all organizations are using the same IBM Blockchain Platform console.

    - Organization: Org1
    - Playbook: [04-import-organization.yml](04-import-organization.yml)
    - Command: `ansible-playbook 04-import-organization.yml --extra-vars "@ordering-org-vars.yml"`

    This playbook uses the Ansible Module `ibm.blockchain_platform.external_organization` module to import the organization Org1 from a file.

5. Add Org1 to the consortium

    - Organization: Ordering Org
    - Playbook: [05-add-organization-to-consortium.yml](05-add-organization-to-consortium.yml)
    - Command: `ansible-playbook 05-add-organization-to-consortium.yml --extra-vars "@ordering-org-vars.yml"`

    This playbook updates the ordering service system channel configuration to add Org1 as a member of the consortium.

6. Export the ordering service

    Note: skip this step if all organizations are using the same IBM Blockchain Platform console.

    - Organization: Ordering Org
    - Playbook: [06-export-ordering-service.yml](06-export-ordering-service.yml)
    - Command: `ansible-playbook 06-export-ordering-service.yml --extra-vars "@ordering-org-vars.yml"`

    This playbook uses the Ansible Module `ibm.blockchain_platform.ordering_service_info` module to export the ordering service to a file.

    In a real deployment, this file must then be passed to the organization Org1 out of band, so they could import the ordering service into their IBM Blockchain Plaform console.

7. Import the ordering service

    Note: skip this step if all organizations are using the same IBM Blockchain Platform console.

    - Organization: Org1
    - Playbook: [07-import-ordering-service.yml](07-import-ordering-service.yml)
    - Command: `ansible-playbook 07-import-ordering-service.yml --extra-vars "@org1-vars.yml"`

    This playbook uses the Ansible Module `ibm.blockchain_platform.external_ordering_service` module to import the ordering service from a file.

8. Create the channel mychannel

    - Organization: Org1
    - Playbook: [08-create-channel.yml](08-create-channel.yml)
    - Command: `ansible-playbook 08-create-channel.yml --extra-vars "@org1-vars.yml"`

    This playbook creates a new channel named mychannel, with Org1 as the only member.

9. Join the peer to the channel

    - Organization: Org1
    - Playbook: [09-join-peer-to-channel.yml](09-join-peer-to-channel.yml)
    - Command: `ansible-playbook 09-join-peer-to-channel.yml --extra-vars "@org1-vars.yml"`

    This playbook joins Org1's peer to the channel mychannel.

10. Add anchor peer to the channel

    - Organization: Org1
    - Playbook: [10-add-anchor-peer-to-channel.yml](10-add-anchor-peer-to-channel.yml)
    - Command: `ansible-playbook 10-add-anchor-peer-to-channel.yml --extra-vars "@org1-vars.yml"`

    This playbook adds Org1's peer as an anchor peer for the channel mychannel.

11. Create the components for the endorsing organization Org2

    - Organization: Org2
    - Playbook: [11-create-endorsing-organization-components.yml](02-create-endorsing-organization-components.yml)
    - Command: `ansible-playbook 11-create-endorsing-organization-components.yml --extra-vars "@org2-vars.yml"`

    This playbook uses the Ansible Role `ibm.blockchain_platform.endorsing_organization` to set up the certificate authority, organization (MSP), and peer components for the endorsing organization Org2.

12. Export the organization for Org2

    Note: skip this step if all organizations are using the same IBM Blockchain Platform console.

    - Organization: Org2
    - Playbook: [12-export-organization.yml](12-export-organization.yml)
    - Command: `ansible-playbook 12-export-organization.yml --extra-vars "@org2-vars.yml"`

    This playbook uses the Ansible Module `ibm.blockchain_platform.organization_info` module to export the organization Org2 to a file.

    In a real deployment, this file must then be passed to the organization Org1 out of band, so they could import the organization Org2 into their IBM Blockchain Plaform console.

13. Import the organization for Org2

    Note: skip this step if all organizations are using the same IBM Blockchain Platform console.

    - Organization: Org1
    - Playbook: [13-import-organization.yml](13-import-organization.yml)
    - Command: `ansible-playbook 13-import-organization.yml --extra-vars "@org1-vars.yml"`

    This playbook uses the Ansible Module `ibm.blockchain_platform.external_organization` module to import the organization Org2 from a file.

14. Add Org2 to the channel mychannel

    - Organization: Org1
    - Playbook: [14-add-organization-to-channel.yml](14-add-organization-to-channel.yml)
    - Command: `ansible-playbook 14-add-organization-to-channel.yml --extra-vars "@org1-vars.yml"`

    This playbook adds Org2 to the channel mychannel, and updates the channel policies such that Org2 can read from and write to the channel, and both Org1 and Org2 must sign any future configuration updates.

15. Import the ordering service

    Note: skip this step if all organizations are using the same IBM Blockchain Platform console.

    - Organization: Org2
    - Playbook: [15-import-ordering-service.yml](15-import-ordering-service.yml)
    - Command: `ansible-playbook 15-import-ordering-service.yml --extra-vars "@org2-vars.yml"`

    This playbook uses the Ansible Module `ibm.blockchain_platform.external_ordering_service` module to import the ordering service from a file.

16. Join the peer to the channel

    - Organization: Org2
    - Playbook: [16-join-peer-to-channel.yml](16-join-peer-to-channel.yml)
    - Command: `ansible-playbook 16-join-peer-to-channel.yml --extra-vars "@org2-vars.yml"`

    This playbook joins Org2's peer to the channel mychannel.

17. Add anchor peer to the channel

    - Organization: Org2
    - Playbook: [17-add-anchor-peer-to-channel.yml](17-add-anchor-peer-to-channel.yml)
    - Command: `ansible-playbook 17-add-anchor-peer-to-channel.yml --extra-vars "@org2-vars.yml"`

    This playbook adds Org2's peer as an anchor peer for the channel mychannel.

18. Install the FabCar chaincode on the peer

    - Organization: Org1
    - Playbook: [18-install-chaincode.yml](18-install-chaincode.yml)
    - Command: `ansible-playbook 18-install-chaincode.yml --extra-vars "@org1-vars.yml"`

    This playbook installs the FabCar chaincode onto Org1's peer.

19. Install the FabCar chaincode on the peer

    - Organization: Org2
    - Playbook: [19-install-chaincode.yml](19-install-chaincode.yml)
    - Command: `ansible-playbook 19-install-chaincode.yml --extra-vars "@org2-vars.yml"`

    This playbook installs the FabCar chaincode onto Org2's peer.

20. Instantiate the FabCar chaincode on the channel

    - Organization: Org1
    - Playbook: [20-instantiate-chaincode.yml](20-instantiate-chaincode.yml)
    - Command: `ansible-playbook 20-instantiate-chaincode.yml --extra-vars "@org1-vars.yml"`

    This playbook installs the FabCar chaincode onto Org2's peer.

21. Register application identity and create connection profile

    - Organiation: Org1
    - Playbook: [21-register-application.yml](21-register-application.yml)
    - Command: `ansible-playbook 21-register-application.yml --extra-vars "@org1-vars.yml"`

    This playbook registers a new identity and creates a new connection profile, that the FabCar application can use to connect to the network.

    The enrollment ID (`org1app`), enrollment secret (`org1apppw` by default), and connection profile (`Org1 Gateway.json`) should be passed to the application developer.

22. Register application identity and create connection profile

    - Organiation: Org2
    - Playbook: [22-register-application.yml](22-register-application.yml)
    - Command: `ansible-playbook 22-register-application.yml --extra-vars "@org2-vars.yml"`

    This playbook registers a new identity and creates a new connection profile, that the FabCar application can use to connect to the network.

    The enrollment ID (`org2app`), enrollment secret (`org2apppw` by default), and connection profile (`Org2 Gateway.json`) should be passed to the application developer.

## Cleaning up

1. Delete the components for the endorsing organization Org1

    - Organization: Org1
    - Playbook: [97-delete-endorsing-organization-components.yml](97-delete-endorsing-organization-components.yml)
    - Command: `ansible-playbook 97-delete-endorsing-organization-components.yml --extra-vars "@org1-vars.yml"`

    This playbook uses the Ansible Role `ibm.blockchain_platform.endorsing_organization` to delete the certificate authority, organization (MSP), and peer components for the endorsing organization Org1.

2. Delete the components for the endorsing organization Org2

    - Organization: Org2
    - Playbook: [98-delete-endorsing-organization-components.yml](98-delete-endorsing-organization-components.yml)
    - Command: `ansible-playbook 98-delete-endorsing-organization-components.yml --extra-vars "@org2-vars.yml"`

    This playbook uses the Ansible Role `ibm.blockchain_platform.endorsing_organization` to delete the certificate authority, organization (MSP), and peer components for the endorsing organization Org2.

3. Delete the components for the ordering organization Ordering Org

    - Organization: Ordering Org
    - Playbook: [99-delete-ordering-organization-components.yml](99-delete-ordering-organization-components.yml)
    - Command: `ansible-playbook 99-delete-ordering-organization-components.yml --extra-vars "@ordering-org-vars.yml"`

    This playbook uses the Ansible Role `ibm.blockchain_platform.ordering_organization` to delete the certificate authority, organization (MSP), and ordering service components for the ordering organization Ordering Org.

