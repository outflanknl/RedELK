RedELK Server Role
==================

Implements the public Ansible deployment path for the ELK-side RedELK server.

This role replaces `elkserver/install-elkserver.sh` for the Ansible path, while
keeping the legacy script available for standalone/manual installs.

Scope
-----

This role is responsible for:

- validating Ubuntu 24.04 or newer, matching the Docker and connector roles
- interpreting the install mode (`limited`, `full`, `dev`)
- deriving memory settings, including `fixedmemory` and `dryrun` compatibility
- extracting `elkserver.tgz` into the remote deployment path
- rendering `.env` and RedELK application config files
- preserving generated secrets across reruns
- preparing self-signed or Let's Encrypt certificate paths
- managing `vm.max_map_count`
- configuring periodic C2 log retrieval for hosts in `c2servers`
- starting the stack through Docker Compose v2

This role is not responsible for installing Docker itself in the Ansible path.
That remains in the separate `docker` role by design, matching the internal
`infra_mgmnt` role boundary.

Key Variables
-------------

- `redelk_local_repo_path`: local repository root used to locate `elkserver.tgz`
- `redelk_remote_base_path`: remote base path, default `/opt/redelk`
- `redelk_install_type`: explicit install type (`limited`, `full`, `dev`)
- `redelk_elk_install_command`: legacy-compatible input used to infer mode flags
- `redelk_fixedmemory`: explicit compatibility switch for legacy `fixedmemory`
- `redelk_dryrun`: explicit compatibility switch for legacy `dryrun`
- `redelk_extract_server_package`: enable archive extraction
- `redelk_force_extract_server_package`: force re-extraction of `elkserver.tgz`
- `redelk_letsencrypt_enabled`: switch between self-signed and Let's Encrypt flow
- `redelk_external_domain`: required when Let's Encrypt is enabled
- `redelk_letsencrypt_email`: required when Let's Encrypt is enabled
- `redelk_sync_user`: remote C2 sync account, default `scponly`
- `redelk_start_containers`: control whether the role starts the stack

Design Notes
------------

- Docker is expected to exist already. The role only performs Docker preflight
  checks.
- `.env`, `config.json`, BloodHound config, and password reference files are
  managed declaratively on reruns.
- Existing generated secrets are read back from current files before rendering,
  so reruns stay stable.
- The role follows the internal Ansible approach rather than the legacy shell
  process where that keeps behavior cleaner and more idempotent.

Intentional Differences From The Legacy Script
----------------------------------------------

- Docker bootstrap stays outside this role.
- Deployment uses an Ansible archive/extract workflow instead of running
  directly inside a manually extracted source tree.
- Certificate and Compose handling use Ansible modules instead of matching the
  exact shell command sequence.

Validation
----------

This role is exercised in the `molecule/redelk` scenario together with
`redelk-client`.
