# Open-source Fabric Stack

The two playbooks in this example install the [Fabric Operations Console](https://github.com/hyperledger-labs/fabric-operations-console) and the [Fabric Operator](https://github.com/hyperledger-labs/fabric-operator).

This guide provides comprehensive instructions for setting up the complete open source Hyperledger Fabric stack using Ansible.

> **⚠️ Beta Notice**: This functionality is currently in beta. It has not been published to Ansible Galaxy or DockerHub. Please do not use for production workloads.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Playbooks](#running-the-playbooks)
- [Post-Installation](#post-installation)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

---

## Prerequisites

Before you begin, ensure you have the following software and tools installed:

### Required Software

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.8+ | Runtime environment |
| Poetry | 1.2+ | Dependency management |
| Ansible | 2.12+ | Automation framework |
| kubectl | 1.25+ | Kubernetes CLI |
| git | 2.x | Version control |
| jq | 1.6+ | JSON processing |

### Verify Installation

Check that all required tools are installed:

```bash
python3 --version      # Expected: Python 3.8.0 or higher
poetry --version       # Expected: Poetry 1.2.0 or higher
ansible --version      # Expected: ansible [core 2.12.0] or higher
kubectl version --client  # Expected: Client Version v1.25.0 or higher
git --version          # Expected: git version 2.x
jq --version           # Expected: jq-1.6 or higher
```

### Kubernetes Cluster

You need access to a Kubernetes cluster. This has been tested with:

- **KIND** (Kubernetes IN Docker) - Recommended for development
- **Minikube**
- **OpenShift** 4.x
- **IKS** (IBM Kubernetes Service) 1.25+

#### Creating a KIND Cluster (Recommended for Testing)

```bash
# Install KIND
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-darwin-arm64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Create a cluster
kind create cluster --name fabric-test

# Verify cluster is running
kubectl cluster-info
kubectl get nodes
```

**Expected output:**
```
Kubernetes control plane is running at https://127.0.0.1:6443
CoreDNS is running at https://127.0.0.1:6443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy

NAME                 STATUS   ROLES           AGE   VERSION
fabric-test-control-plane   Ready    control-plane   1m    v1.27.3
```

---

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/IBM-Blockchain/ansible-collection.git
cd ansible-collection
```

### Step 2: Set Up Python Environment

```bash
# Install Poetry if not already installed
curl -sSL https://install.python-poetry.org | python3 -

# Create virtual environment and install dependencies
poetry install
poetry shell
```

**Expected output:**
```
Creating virtualenv ibm-blockchain-platform in /Users/username/.cache/pypoetry/virtualenvs
Installing dependencies from lock file
...
Installing the current project: ibm-blockchain-platform (2.0.0)
```

### Step 3: Build and Install Ansible Collection

```bash
# Build the collection
ansible-galaxy collection build -f

# Install the collection
ansible-galaxy collection install $(ls -1 | grep ibm-blockchain_platform) -f
```

**Expected output:**
```
Created collection for ibm.blockchain_platform at /path/to/ibm-blockchain_platform-2.0.0.tar.gz
Collection 'ibm-blockchain_platform-2.0.0.tar.gz' was installed successfully.
```

### Step 4: Verify Installation

```bash
ansible-galaxy collection list | grep ibm.blockchain
```

**Expected output:**
```
ibm.blockchain_platform    2.0.0
```

---

## Configuration

### Kubernetes Context

Ensure your kubectl context is set to the target cluster:

```bash
# List available contexts
kubectl config get-contexts

# Set the context (replace with your cluster name)
kubectl config use-context kind-fabric-test

# Verify current context
kubectl config current-context
```

### Configure Variables

The `vars.yml` file contains essential configuration for naming and initial identities. Review and customize:

```bash
cat vars.yml
```

**Example `vars.yml`:**
```yaml
# Cluster configuration
k8s_cluster_type: kind
k8s_namespace: fabric-infra

# Console configuration
console_name: fabricinfra
console_ingress_host: fabricinfra-hlf-console-console.localho.st

# Operator configuration
operator_name: fabricinfra
operator_namespace: fabric-infra

# Admin credentials (change in production!)
console_admin_user: admin
console_admin_password: password
```

> **⚠️ Security Warning**: Change default credentials before deploying to any shared or production environment.

---

## Running the Playbooks

### Step 1: Install Fabric Operator

```bash
ansible-playbook 01-operator-install.yml
```

**Expected output:**
```
PLAY [Install Fabric Operator and CRDs] ****************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [fabric-operator-crds : Install CRDs] *************************************
changed: [localhost]

TASK [fabric-operator : Deploy Operator] ***************************************
changed: [localhost]

PLAY RECAP *********************************************************************
localhost                  : ok=15   changed=12   unreachable=0    failed=0
```

### Step 2: Install Fabric Operations Console

```bash
ansible-playbook 02-console-install.yml
```

**Expected output:**
```
PLAY [Install Fabric Operations Console] ***************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [hlfsupport-console : Deploy Console] *************************************
changed: [localhost]

TASK [hlfsupport-console : Wait for Console to be Ready] ***********************
ok: [localhost]

PLAY RECAP *********************************************************************
localhost                  : ok=12   changed=8    unreachable=0    failed=0
```

### Step 3: Verify Installation

```bash
# Check pods are running
kubectl get pods -n fabric-infra

# Check services
kubectl get svc -n fabric-infra

# Access the console (for KIND clusters)
kubectl port-forward svc/fabricinfra-hlf-console-console -n fabric-infra 443:443
```

**Expected output:**
```
NAME                                              READY   STATUS    RESTARTS   AGE
fabricinfra-hlf-console-console-5d8f9c7b9-x2k4m   1/1     Running   0          2m
fabricinfra-hlf-operator-6b7d8f9c5-y3l5n          1/1     Running   0          3m

NAME                                      TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)          AGE
fabricinfra-hlf-console-console           ClusterIP   10.96.123.45    <none>        443/TCP          2m
fabricinfra-hlf-operator                  ClusterIP   10.96.234.56    <none>        8443/TCP         3m
```

Access the console at: `https://localhost:443`

---

## Post-Installation

### Create API Key (Recommended)

Instead of using username/password, create an API key for automation:

```bash
# Generate API key
AUTH=$(curl -X POST https://fabricinfra-hlf-console-console.localho.st:443/ak/api/v2/permissions/keys \
  -u admin:password \
  -k \
  -H 'Content-Type: application/json' \
  -d '{"roles": ["writer", "manager"], "description": "ansible-automation"}')

# Extract credentials
KEY=$(echo $AUTH | jq .api_key | tr -d '"')
SECRET=$(echo $AUTH | jq .api_secret | tr -d '"')

# Create authentication file
cat << EOF > auth-vars.yml
api_key: $KEY
api_endpoint: http://fabricinfra-hlf-console-console.localho.st/
api_authtype: basic
api_secret: $SECRET
EOF

echo "Authentication file created: auth-vars.yml"
```

### Using the Authentication File

Include the `auth-vars.yml` in your playbooks:

```yaml
# In your playbook
- name: Include API credentials
  include_vars: auth-vars.yml

- name: Create Fabric component
  ibm.blockchain_platform.console_component:
    api_key: "{{ api_key }}"
    api_endpoint: "{{ api_endpoint }}"
    api_authtype: "{{ api_authtype }}"
    api_secret: "{{ api_secret }}"
    # ... other parameters
```

Or via command line:

```bash
ansible-playbook my-playbook.yml -e @auth-vars.yml
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Poetry Installation Fails

**Error:** `curl: command not found` or `python3: command not found`

**Solution:**
```bash
# Install curl
# macOS
brew install curl

# Ubuntu/Debian
sudo apt-get install curl

# Install Python 3
# macOS
brew install python@3.8

# Ubuntu/Debian
sudo apt-get install python3 python3-pip
```

#### 2. Ansible Collection Build Fails

**Error:** `ERROR! Invalid collection name`

**Solution:**
```bash
# Ensure you're in the correct directory
cd /path/to/ansible-collection

# Verify galaxy.yml exists
cat galaxy.yml

# Rebuild
ansible-galaxy collection build -f
```

#### 3. Kubernetes Connection Issues

**Error:** `Unable to connect to the server: dial tcp: i/o timeout`

**Solution:**
```bash
# Verify cluster is running
kind get clusters

# Check kubectl context
kubectl config current-context
kubectl cluster-info

# Restart KIND cluster if needed
kind delete cluster --name fabric-test
kind create cluster --name fabric-test
```

#### 4. Pods Not Starting (CrashLoopBackOff)

**Error:** Console or Operator pods showing `CrashLoopBackOff`

**Solution:**
```bash
# Check pod logs
kubectl logs -n fabric-infra -l app=fabricinfra-hlf-console-console

# Check for resource constraints
kubectl describe pod -n fabric-infra <pod-name>

# Common fixes:
# 1. Increase memory limits
# 2. Check storage class availability
# 3. Verify image pull secrets
```

#### 5. Certificate Errors

**Error:** `x509: certificate signed by unknown authority`

**Solution:**
```bash
# For KIND clusters, use -k flag to skip TLS verification
curl -k https://your-console-url

# Or add certificate to trust store
kubectl get secret -n fabric-infra fabricinfra-hlf-console-console-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > console.crt
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain console.crt
```

#### 6. Port Forwarding Issues

**Error:** `error: unable to listen port 443: bind: permission denied`

**Solution:**
```bash
# Use a higher port number
kubectl port-forward svc/fabricinfra-hlf-console-console -n fabric-infra 8443:443

# Then access via https://localhost:8443
```

---

## FAQ

### Q: Can I use this in production?

**A:** No, this is currently beta functionality. Wait for official release or use IBM Blockchain Platform for production workloads.

### Q: Which Kubernetes versions are supported?

**A:** Tested with Kubernetes 1.25+. KIND is recommended for development and testing.

### Q: How do I upgrade the Operator or Console?

**A:** Re-run the installation playbooks with updated collection version:
```bash
ansible-galaxy collection install ibm.blockchain_platform:2.1.0 -f
ansible-playbook 01-operator-install.yml
ansible-playbook 02-console-install.yml
```

### Q: Can I install only the Operator without the Console?

**A:** Yes, run only `01-operator-install.yml`. However, managing Fabric resources will require CLI or custom tooling.

### Q: How do I uninstall everything?

**A:** Run the uninstall playbooks in reverse order:
```bash
ansible-playbook 03-console-uninstall.yml
ansible-playbook 04-operator-uninstall.yml
```

### Q: Where can I get help?

**A:** 
- Open an issue on [GitHub](https://github.com/IBM-Blockchain/ansible-collection/issues)
- Check the [Hyperledger Fabric documentation](https://hyperledger-fabric.readthedocs.io/)
- Join the [Hyperledger Discord](https://discord.com/invite/hyperledger)

---

## Additional Resources

- [Fabric Operator Documentation](https://github.com/hyperledger-labs/fabric-operator)
- [Fabric Operations Console](https://github.com/hyperledger-labs/fabric-operations-console)
- [Hyperledger Fabric Documentation](https://hyperledger-fabric.readthedocs.io/)
- [Ansible Collection Documentation](https://ibm-blockchain.github.io/ansible-collection/)

---

**Last Updated**: April 2026  
**Collection Version**: 2.0.0 (beta)
