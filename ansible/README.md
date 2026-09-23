# RedELK Ansible Deployment

This directory provides roles and playbooks for deploying the RedELK stack: the server and its log-collection connectors on existing C2 servers and redirectors. The original shell scripts remain available for manual installs without Ansible.

The roles provide:
- RedELK server deployment (`redelk-server`)
- RedELK client connector deployment (`redelk-client`)
- Docker installation on hosts that need a local Docker engine (`docker` role)

## Scope

The playbooks automate:
- explicit package generation on the control node via `prepare-packages.yml`, or reuse of prebuilt artifacts
- upload and extraction of `elkserver.tgz`, plus deployment of prepared client CA certificates and sync public keys
- native RedELK server preparation on ELK hosts (`.env`, config, certificates, compose startup)
- native Ansible deployment of Filebeat and public C2 sync helpers on client hosts

These roles deploy RedELK and its connectors. Operators must install and configure C2 software and redirectors separately, including the log sources used by RedELK.

## Relationship To The Shell Scripts

The repository still ships the original installer scripts:
- `initial-setup.sh`
- `elkserver/install-elkserver.sh`
- `c2servers/install-c2server.sh`
- `redirs/install-redir.sh`

Those scripts remain useful for standalone/manual deployments.

The Ansible workflow follows the same component split:
- package preparation on the control node
- ELK server deployment
- C2 connector deployment
- redirector connector deployment

## Repository Layout

- `prepare-packages.yml`: local certificate, SSH key, and package preparation
- `playbook.yml`: deployment using already prepared artifacts
- `inventory.yml`: example inventory
- `group_vars/`: example variable sets
- `roles/redelk-package-prep`: local package preparation role for certs, SSH keys, and archives
- `roles/docker`: local Docker install role
- `roles/redelk-server`: native ELK server role with internal-style task split
- `roles/redelk-client`: native client role for Filebeat, redirector logs, and public C2 sync helpers

Each of those RedELK roles also has its own local `README.md` with role-specific design notes and implementation details.

## Prerequisites

- Ansible available on the control node
- required collections installed from `collections.yml`
- SSH access to all targets
- privilege escalation (`become`) on targets
- Debian/APT-based targets for RedELK installer compatibility
- Ubuntu targets for the local `docker` role
- valid certificate config at `certs/config.cnf` before running `prepare-packages.yml`

Install the shared Ansible collections first:

```bash
cd ansible
ansible-galaxy collection install -r collections.yml -p .ansible/collections
```

## Required Variables

Package preparation runs on localhost, independently of the deployment inventory.
The `redelk-package-prep` role supplies these defaults:
- `redelk_local_repo_path`: `"{{ playbook_dir | dirname }}"` (this repository root)
- `redelk_openssl_config_path`: `certs/config.cnf`, relative to that root

Override preparation variables with `-e` or `-e @file.yml`; target-group variables
such as `group_vars/elkservers.yml` do not apply to localhost. If overriding
`redelk_local_repo_path`, use the same workspace for preparation and deployment.

Set deployment variables in `group_vars` or inventory vars matching your own host groups.

Server-related:
- `redelk_local_repo_path` (usually `"{{ playbook_dir | dirname }}"`)
- `redelk_remote_base_path` (for example `/opt/redelk`)
- `redelk_install_type` (`limited`, `full`, or `dev`)
- optional `redelk_elk_install_command` for backwards compatibility with older examples
- optional `redelk_letsencrypt_enabled`, `redelk_external_domain`, `redelk_letsencrypt_email`

Client-related:
- `redelk_local_repo_path`
- `redelk_attack_scenario`
- `redelk_logstash_endpoint`
- optional `redelk_identifier` (defaults to `inventory_hostname`)
- optional `redelk_sync_public_key_path` for C2 rsync access
- optional `redelk_c2_filebeat_inputs` and `redelk_c2_sync_jobs`

Deployment controls:
- `deploy_redelk` (`true` in the supplied group vars; set `false` to explicitly skip client deployment on selected hosts)

`redelk_generate_packages` is no longer used. Deployment never invokes package preparation.

## Usage

Assign RedELK targets to `elkservers`, `c2servers`, and `redirs`. Other hosts are
ignored, so an existing inventory can be reused.

1. Use your existing inventory or update `inventory.yml` with your hosts and access settings.
2. Set deployment variables for your groups in `group_vars/`.
3. Fill in the repository-root `certs/config.cnf` using `certs/config.cnf.example`.
4. Prepare locally, then deploy only if preparation succeeds:

```bash
cd ansible
ansible-playbook -i localhost, prepare-packages.yml && \
  ansible-playbook -i inventory.yml playbook.yml
```

Preparation needs no SSH access to deployment hosts and runs without privilege
escalation, using the Python interpreter that runs Ansible. If the deployment
artifacts have already been prepared (including client CA and sync-key files),
run only the second command. Existing missing-artifact checks still apply.

## Live System Testing

Use `inventory.yml` as the starting point for reserved real hosts.

Recommended flow:
- create your own private live inventory based on `inventory.yml`
- set real values in `group_vars/elkservers.yml`, `group_vars/c2servers.yml`, and `group_vars/redirs.yml`
- run `ansible-playbook -i localhost, prepare-packages.yml` before deployment, or supply prepared artifacts
- start with a narrow deployment run against one host or group

Examples:

```bash
cd ansible
ansible-playbook -i inventory-live.yml playbook.yml --limit elkservers
ansible-playbook -i inventory-live.yml playbook.yml --limit c2servers
ansible-playbook -i inventory-live.yml playbook.yml --limit redirs
```

Then run the full integration deployment:

```bash
cd ansible
ansible-playbook -i inventory-live.yml playbook.yml
```

Notes for live runs:
- `playbook.yml` is the integrale deployment playbook for RedELK plus the client connectors
- `molecule/redelk` is useful for local role validation, not as the primary entrypoint for real systems
- `redelk-package-prep` replaces the old `initial-setup.sh` flow only for the Ansible path
- `redelk-server` deploys the public ELK package natively for the Ansible path; the standalone script path still exists separately
- `redelk-client` is native Ansible for the Ansible path; the standalone client scripts still exist separately
- Docker installation is intentionally kept in the separate `docker` role for the Ansible path, even though the legacy ELK installer script bootstraps Docker itself

## Molecule Testing

A Molecule split setup is available:
- `molecule/docker`: isolated test of the `docker` role
- `molecule/redelk`: test of `redelk-server` and `redelk-client` with fixture archives generated from the repository contents

Both scenarios use privileged Ubuntu containers.

Run syntax checks without connecting to hosts:

```bash
cd ansible
ansible-playbook -i localhost, prepare-packages.yml --syntax-check
ansible-playbook -i inventory.yml playbook.yml --syntax-check
```

Run Docker-role tests:

```bash
cd ansible
ansible-galaxy collection install -r collections.yml -p .ansible/collections
molecule test -s docker
```

Run RedELK-role tests:

```bash
cd ansible
ansible-galaxy collection install -r collections.yml -p .ansible/collections
molecule test -s redelk
```

Requirements:
- local Docker daemon running
- ability to run privileged containers
- outbound network access for apt repositories used during Molecule prepare/converge

## Playbook Behavior

`prepare-packages.yml` runs only `redelk-package-prep` on localhost, without
facts gathering or privilege escalation. The role needs no delegation or `run_once`.

`playbook.yml` runs these plays:
- `elkservers:c2servers:redirs`: SSH prep and shared pre-tasks
- `elkservers`: `docker` then `redelk-server`
- `c2servers`: `redelk-client`
- `redirs`: `redelk-client`

This Docker split is deliberate:
- `redelk-server` checks for Docker but does not install it or declare a Docker role dependency
- the legacy shell scripts remain authoritative for standalone installs, but not for Ansible role decomposition

## Idempotency and Re-runs

Preparation can be rerun with unchanged inputs; existing keys and certificates
are reused. Keep the generated material instead of deleting it before a rerun.

The ELK server role preserves generated package contents by checking for extracted package content at:
- `/opt/redelk/elkserver/VERSION`

Set `redelk_force_extract_server_package: true` if you want to force re-extraction of `elkserver.tgz`.

## Notes

- If you do not want to use Ansible, use the script-based deployment path documented in the repository root [`README.md`](../README.md).
- The current static parity assessment between the legacy scripts and the Ansible path is documented in [`test-results/legacy-vs-ansible-static-parity.md`](./test-results/legacy-vs-ansible-static-parity.md).
