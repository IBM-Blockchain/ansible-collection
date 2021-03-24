# ansible-collection

## Required skills

In order to contribute to this Ansible collection, you will may need skills in:

- Ansible
- Python
- Hyperledger Fabric
- IBM Blockchain Platform
- Docker
- Red Hat OpenShift/Kubernetes
- ReStructed Text
- Jinja2 templates

The skills required depend on the area of the code you are looking to contribute, for example the Ansible modules are written in Python, the Ansible roles are written in YAML, and the documentation is written in ReStructed Text.

## Setting up a development environment

Follow these steps to set up a development environment for this Ansible collection.

1. Install Python v3.x. The Python version manager [pyenv](https://github.com/pyenv/pyenv) works great on Linux and macOS and avoids a lot of difficulties seen when trying to use the system Python, or Python installed using the package manager for your operating system.

2. Clone the GitHub repository. To avoid difficulties later on, it is recommended that you clone the GitHub repository directly into the Ansible collections directory, so you need to delete any installed version first:

   `rm -rf ~/.ansible/collections/ansible_collections/ibm/blockchain_platform`

   Then clone the GitHub repository:

   `git clone git@github.com:IBM-Blockchain/ansible-collection.git ~/.ansible/collections/ansible_collections/ibm/blockchain_platform`

   You can then find the cloned GitHub repository at:

   `~/.ansible/collections/ansible_collections/ibm/blockchain_platform`

   To make it easier to find, you may want to symlink it somewhere else:

   `ln -s ~/.ansible/collections/ansible_collections/ibm/blockchain_platform ~/git/ansible-collection`

3. Open a terminal in the cloned GitHub repository, or change into the directory:

   `cd ~/.ansible/collections/ansible_collections/ibm/blockchain_platform`

4. Install all Python dependencies:

    `pip install -Ur requirements.txt`

    The modules installed include Ansible and tools for building documentation and linting the code.

5. Install the Hyperledger Fabric tools. You can find the latest versions of these tools on the Hyperledger Fabric [releases](https://github.com/hyperledger/fabric/releases) page - find the latest `v2.x` release, look for `Assets`, and download the appropriate file for your operating system.

   Once you have downloaded the appropriate file, it is recommended that you extract it into `/usr/local` so you don't have to set the `PATH` environment variable:

   `tar xf hyperledger-fabric-darwin-amd64-2.3.1.tar.gz -C /usr/local`

6. In order to test any code changes you make to this collection, other than documentation only changes, you will need an IBM Blockchain Platform instance to test against.

   Depending on the change, you may need an instance of IBM Blockchain Platform running on IBM Cloud (SaaS), or the IBM Blockchain Platform software running in a Red Hat OpenShift or Kubernetes cluster, or both.

## What's in the repository?

### Ansible modules

Ansible modules, such as `ibm.blockchain_platform.peer`, are provided as Python modules under `plugins/modules`.

Each Ansible module has a `main()` function that is called by Ansible. At the start of each `main()` function, the arguments for the module are defined in a `argument_spec`, and then passed into Ansible by creating a `BlockchainModule` object, which is an instance of `AnsibleModule`.

Each Ansible module then goes through roughly the same process:

1. Perform any additional input validation
2. Connect to and determine the current state of the system
3. Make any changes required to get the system into the defined state
4. Return any data that may be of interest to the user

Ansible modules must return at the minimum a failure message using `module.fail_json()`, or a changed/not changed flag `module.exit_json(changed=False)`.

Finally, each Ansible module has documentation strings such as `ANSIBLE_METADATA`, `DOCUMENTATION`, etc. These are parsed by the `ansible-doc-extractor` tool to generate the documentation for each module.

### Python utility modules

Code that is used across multiple Ansible modules are provided as Python modules under `plugins/module_utils`.

### Ansible roles

Ansible roles, such as `ibm.blockchain_platform.endorsing_organization`, can be found under `roles`.

Each Ansible role has a set of default parameters in `defaults/main.yml`, metadata in `meta/main.yml`, and the main set of tasks in `tasks/main.yml`. Most of the Ansible roles included in this collection have additional task files under the `tasks` directory that are called from `tasks/main.yml`.

Finally, there is no mechanism for generating documentation from an Ansible role. The documentation for the roles is written as ReStructured Text files under `docs/source/roles`.

### Docker image

There is a `Dockerfile` at the root of the repository that builds a Docker image containing everything needed to use this Ansible collection, including the collection itself.

### Integration tests

There are a few integration tests under `tests/integration/targets`. Integration tests in Ansible closely resemble Ansible roles, where there is a main set of tasks (including assertions) in `tasks/main.yml`.

### Tutorial

The playbooks and configuration used in the build, join, and deploy tutorials is stored under `tutorial`. The legacy Hyperledger Fabric v1.x tutorial is stored under `tutorial/v1.x`, but this is never referenced from the documentation.

### Documentation

The documentation is stored under the `docs/source` directory. There is a Jinja2 template used by `ansible-doc-extractor` under `docs/templates`.

## Building the repository

### Linting

You can lint the Ansible collection by running the following commands:

```
flake8 .
ansible-lint
for ROLE in roles/*; do ansible-lint ${ROLE}; done
for PLAYBOOK in tutorial/??-*.yml; do ansible-lint ${PLAYBOOK}; done
for PLAYBOOK in tutorial/v1.x/??-*.yml; do ansible-lint ${PLAYBOOK}; done
shellcheck tutorial/*.sh
yamllint .
```

### Ansible collection

You can build the Ansible collection into a package by running the following command:

```
ansible-galaxy collection build
```

Other users can then install this package by running:

```
ansible-galaxy collection install ibm-blockchain_platform-1.0.0.tar.gz
```

The package can also be imported into Ansible Galaxy manually using your web browser.

### Documentation

The documentation can be built by running the following commands:

```
cd docs
make clean
make all
```

The built documentation will be available from the `docs/build` directory, open the `index.html` file in a web browser.

## Testing

### Integration tests

In order to run the integration tests, you must edit the file `tests/integration/integration_config.yml` and provide values for your IBM Blockchain Platform instance.

The `test_run_id` and `short_test_run_id` parameters provide namespacing for the tests that allow multiple instances of the tests to run concurrently on the same IBM Blockchain Platform instance. This is mostly useful in the automated CI/CD pipeline, but should not be needed if you are running against an individually owned IBM Blockchain Platform instance.

You can then run the integration tests by running the following command:

```
ansible-test integration
```

### Tutorial tests

Running all of the tutorials is the best way to test the collection. The tutorials exercise most of the Ansible modules and roles in the collection.

## CI

The CI for the collection is managed using GitHub Actions.

There is a main workflow defined in `.github/workflows/main.yml`. This is responsible for building the collection, linting the code, running the tests, and publishing the collection to Ansible Galaxy and Docker Hub when a release is created. This runs on every pull request, every merge into the `main` branch, every release/tag, and is also scheduled to run over night, every night.

There is also a "purge" workflow defined in `.github/workflows/purge.yml`. This is scheduled to run over night, every night, and simply purges all components from the IBM Blockchain Platform instances used by the main workflow. This is unfortunately required as sometimes the cleanup processes in the test do not occur or do not work, and the leftover components can take up valuable CPU, memory and storage on the associated Red Hat OpenShift cluster.

There are a large number of Action secrets defined here: https://github.com/IBM-Blockchain/ansible-collection/settings/secrets/actions

These include:
- Ansible Galaxy API keys
- Docker Hub API keys
- IBM Blockchain Platform API keys
- IBM Cloud API keys
- Kubernetes information

## Publishing/releasing

There are three parts to the publishing process:

- Publishing the collection to Ansible Galaxy (https://galaxy.ansible.com/ibm/blockchain_platform)
- Publishing the documentation to GitHub Pages using the `gh-pages` branch (https://ibm-blockchain.github.io/ansible-collection/)
- Publishing the Docker image to Docker Hub (https://hub.docker.com/r/ibmcom/ibp-ansible)

All of this is automated using GitHub Actions.

To publish a new release, use GitHub by going to the [Releases](https://github.com/IBM-Blockchain/ansible-collection/releases) page.

For the tag version and release title, use the version number in `galaxy.yml` prefixed with `v`, for example `v1.2.3`.

When you publish the release, the GitHub Actions workflow will be triggered and it should automatically publish. You may need to restart the workflow if the tests fail due to intermittent issues such as slow or dropped network connections.

The workflow will automatically bump the version number in `galaxy.yml` after the publishing has completed.

Currently, `sstone1`, `lesleyannjordan`, and `mbwhite` have access to the `ibm` publisher on Ansible Galaxy.