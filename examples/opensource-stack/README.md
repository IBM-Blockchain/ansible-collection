# Open-source Fabric Stack

The two playbooks in this example install the [Fabric Operations Console](https://github.com/hyperledger-labs/fabric-operations-console) and the [Fabric Operator](https://github.com/hyperledger-labs/fabric-operator)

## Usage

As this function should be considered beta, it has not been published to Ansible Galaxy, or an image to DockerHub. Therefore please follow the installation instructions on installing from source.

In brief,

- Clone this repository
- Use `poetry` to create a development shell `poetry shell`
- Run these commands to build locally
```
    ansible-galaxy collection build -f
    ansible-galaxy collection install $(ls -1 | grep ibm-blockchain_platform) -f
```

You can then run the playbooks as needed

### Pre-requistie tools

In addition you will need the `kubectl` and `git` installed.
## Kubernetes Connection

The playbooks assume that the kubectl context in the current shell is set to the cluster you wish to install to. NOTE that this has been initially tested using a KIND cluster (see the `sample-network` example in the [Fabric Operator](https://github.com/hyperledger-labs/fabric-operator) for creating a KIND instance)

`vars.yml` contains the essential configuration for naming and initial identities.

## Post-creation actions

Once installed, you've the choice of using the Console to create Fabric resources.
Alternatively you can use the other Ansible modules to create resources.

It helps to create an API key rather than use the username/password.

For example, assuming the naming as used in the example's `vars.yml` and a local KIND cluster.

```
    AUTH=$(curl -X POST https://fabricinfra-hlf-console-console.localho.st:443/ak/api/v2/permissions/keys -u admin:password -k -H 'Content-Type: application/json' -d '{"roles": ["writer", "manager"],"description": "newkey"}')
    KEY=$(echo $AUTH | jq .api_key | tr -d '"')
    SECRET=$(echo $AUTH | jq .api_secret | tr -d '"')

    echo "Writing authentication file for Ansible based IBP (Software) network building"
    cat << EOF > auth-vars.yml
    api_key: $KEY
    api_endpoint: http://fabricinfra-hlf-console-console.localho.st/
    api_authtype: basic
    api_secret: $SECRET
    EOF

```

The `auth-vars.yml` can be included in any other playbooks or added in the `ansible-playbook` cli
