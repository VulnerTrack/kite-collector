# Kite Collector fleet deployment with Ansible

This project installs the machine-wide Windows MSI published in a versioned
GitHub Release, enrolls each machine with the VulnerTrack PKI, and verifies the
Windows service. Run it from a Linux Ansible control node joined to, or able to
authenticate against, the company's Active Directory domain.

## 1. Prepare Windows management

Use Group Policy to:

1. Enable **Allow remote server management through WinRM**.
2. Set the **Windows Remote Management (WS-Management)** service to Automatic.
3. Enable the **Windows Remote Management (HTTP-In)** firewall rule for the
   Domain profile, restricted to the Ansible controller's source address.
4. Grant a dedicated domain account (the example uses `svc-ansible`) local
   administrator rights on the managed computers.

Use FQDN inventory names for Kerberos. Do not enable Basic authentication or
WinRM's `AllowUnencrypted` setting.

## 2. Install the controller dependencies

On Ubuntu/Debian:

```bash
cd deploy/ansible
sudo apt update
sudo apt install -y python3-venv python3-dev gcc libkrb5-dev krb5-user
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install ansible 'pywinrm[kerberos]'
ansible-galaxy collection install -r requirements.yml
```

Run the remaining commands in this document from `deploy/ansible`.

Validate all playbooks after installing the collection:

```bash
ansible-playbook --syntax-check playbooks/deploy.yml
ansible-playbook --syntax-check playbooks/verify.yml
ansible-playbook --syntax-check playbooks/uninstall.yml
```

## 3. Publish a release

Create the MSI from the repository root:

```bash
make build
./scripts/build-msi.sh 1.2.3 "$(git rev-parse --short HEAD)"
sha256sum dist/kite-collector_1.2.3_amd64.msi
```

Push tag `v1.2.3`. The release workflow builds the MSI and uploads this exact
filename to its GitHub Release automatically:

```text
kite-collector_1.2.3_amd64.msi
kite-collector_1.2.3_amd64.msi.sha256
```

Do not rename the file to include the tag's leading `v`. The resulting URL is:

```text
https://github.com/VulnerTrack/kite-collector/releases/download/v1.2.3/kite-collector_1.2.3_amd64.msi
```

## 4. Configure inventory and secrets

Edit:

- `inventory/production/hosts.yml`: replace the example FQDNs.
- `inventory/production/group_vars/kite_windows/main.yml`: set the domain,
  version, SHA-256 and PKI endpoint.

Create and immediately encrypt the secret variables:

```bash
cp \
  inventory/production/group_vars/kite_windows/vault.example.yml \
  inventory/production/group_vars/kite_windows/vault.yml
ansible-vault encrypt \
  inventory/production/group_vars/kite_windows/vault.yml
```

Edit the encrypted file with:

```bash
ansible-vault edit \
  inventory/production/group_vars/kite_windows/vault.yml
```

Use a short-lived, client-scoped enrollment token. Its `max_uses` must cover
every not-yet-enrolled machine selected by one playbook run. To rotate the token
per batch, split the inventory into deployment groups, run one group at a time,
and replace the vaulted token between runs. Revoke each token after its run.
Each machine still creates a distinct private key and certificate locally.

## 5. Test and deploy

Test one pilot's WinRM connection:

```bash
ansible kite_windows_pilot -m ansible.windows.win_ping --ask-vault-pass
```

Deploy to the pilot group:

```bash
ansible-playbook playbooks/deploy.yml \
  --limit kite_windows_pilot \
  --ask-vault-pass
```

Verify the pilot in the VulnerTrack platform before expanding the deployment.
Then deploy to the full Windows group; the playbook uses five-host and
twenty-five-host batches:

```bash
ansible-playbook playbooks/deploy.yml --ask-vault-pass
```

Audit the current fleet without changing it:

```bash
ansible-playbook playbooks/verify.yml --ask-vault-pass
```

## Updating

Upload the new MSI to its new release, then change `kite_version` and
`kite_msi_sha256` in `main.yml` and rerun `deploy.yml`. The MSI has a stable
UpgradeCode, so it replaces the previous version while preserving enrollment
data during a normal upgrade.

## Uninstalling

The uninstall playbook requires an explicit confirmation:

```bash
ansible-playbook playbooks/uninstall.yml --ask-vault-pass
```

A full MSI uninstall may remove `C:\ProgramData\kite-collector`. Back up that
directory first when a rollback must retain the existing machine identity.
