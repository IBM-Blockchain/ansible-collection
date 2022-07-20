# ansible-collection

The IBM Blockchain Platform provides advanced tooling that allows you to quickly build, operate & govern and grow blockchain networks. It uses Hyperledger Fabric, the open source, industry standard for enterprise blockchain. It also helps you to deploy Hyperledger Fabric networks anywhere, either to cloud or on-premises, using Kubernetes.

This Ansible collection, provided as part of the IBM Blockchain Platform, enables you to automate the building of Hyperledger Fabric networks.

*Please Note* the main branch is now set to `2.0.0-beta`, the `release-1.2` branch is available. If you build a local copy of Ansible for production, please work from the `release-1.2` branch.

## Beta support for Fabric Operator and Fabric Operations Console

With the Open Source version of the [Fabric Operations Console](https://github.com/hyperledger-labs/fabric-operations-console) and the [Fabric Operator](https://github.com/hyperledger-labs/fabric-operator), it is possible now to use the Ansible Playbooks previously targetted towards The IBM Blockchain Platform in a complete open source stack.

This should be considered beta functionality at present, please do try it out, but would not advise production use cases at present. Both the Operator AND the Console must be installed.

Currently the installation of the Operator and Console are available via Playbooks. Once installed Fabric resources can be managed with the existing Ansible modules.

Please see the [README](./examples/opensource-stack/README.md) in the `opensource-stack` example for more information.

## Documentation

Documentation for this Ansible collection is available here: https://ibm-blockchain.github.io/ansible-collection/

The documentation includes installation instructions, tutorials, and reference material for all modules and roles in this collection.

## License

Apache-2.0

## Author Information

This Ansible collection is maintained by the IBM Blockchain Platform development team. For more information on the IBM Blockchain Platform, visit the following website: https://www.ibm.com/cloud/blockchain-platform