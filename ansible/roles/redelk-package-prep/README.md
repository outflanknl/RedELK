RedELK Package Prep Role
========================

Prepares the public RedELK deployment artifacts on the control node.

This role replaces `initial-setup.sh` for the Ansible path, while keeping the
legacy script available for standalone/manual installs.

Scope
-----

This role is responsible for:

- validating the configured OpenSSL config file
- rejecting placeholder certificate values
- generating the RedELK CA key and certificate
- generating the ELK server key, CSR, certificate, and PKCS8 key
- generating the RedELK sync SSH keypair
- copying generated certs and SSH material into the packaged subtrees
- copying `VERSION` into `elkserver`, `c2servers`, and `redirs`
- creating `elkserver.tgz`, `c2servers.tgz`, and `redirs.tgz`

Key Variables
-------------

- `redelk_local_repo_path`: packaging workspace; defaults to `"{{ playbook_dir | dirname }}"`
- `redelk_openssl_config_path`: OpenSSL config path relative to that workspace; defaults to `certs/config.cnf`
- `redelk_package_ssh_dir`: local SSH key output directory
- `redelk_package_archives`: archive definitions for packaged outputs

Design Notes
------------

- This role is control-node work only. `prepare-packages.yml` selects localhost,
  a local connection, Ansible's Python interpreter, and no privilege escalation.
- Run from `ansible/` with `ansible-playbook -i localhost, prepare-packages.yml`,
  then deploy with `ansible-playbook -i inventory.yml playbook.yml`.
- Target-group variables do not apply to localhost. Override prep defaults with
  `-e` or `-e @file.yml`; use the same workspace for preparation and deployment.
- It uses `community.crypto` and `community.general.archive` instead of shell
  commands such as `openssl`, `ssh-keygen`, and `tar`.
- It keeps the same practical artifact model as `initial-setup.sh`: generated
  package trees plus `elkserver.tgz`, `c2servers.tgz`, and `redirs.tgz`.

Intentional Differences From `initial-setup.sh`
-----------------------------------------------

- Archive output is functionally equivalent, but not guaranteed to be
  byte-identical to `tar zcvf`.
- Generated PEM formatting may differ because crypto artifacts are produced by
  Ansible modules rather than the exact shell command sequence.
- The role copies missing `*.example` files declaratively across the repository
  before packaging.

Validation
----------

Check the preparation entrypoint with:

```bash
cd ansible
ansible-playbook -i localhost, prepare-packages.yml --syntax-check
```

The `molecule/redelk` scenario exercises this entrypoint before deployment and
repeats it during idempotence testing. The downstream roles consume the generated
fixture artifacts.
