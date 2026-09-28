RedELK Client Role
==================

Implements the public Ansible deployment path for RedELK connectors on
`c2servers` and `redirs`.

This role replaces `c2servers/install-c2server.sh` and `redirs/install-redir.sh`
for the Ansible path, while keeping the legacy scripts available for
standalone/manual installs.

Scope
-----

This role is responsible for:

- validating Debian/APT-based connector hosts
- installing locale support and generating configured locales before writing defaults
- configuring the Elastic APT repository
- installing and configuring Filebeat
- deploying the RedELK CA certificate
- handling redirector-specific Filebeat and HAProxy logrotate behavior
- handling C2-specific sync user, `rush`, cron jobs, and helper scripts

The role supports two connector types:

- `c2servers`
- `redirs`

It intentionally branches on host group rather than trying to treat both
targets as a single identical connector type.

Key Variables
-------------

- `redelk_attack_scenario`: scenario label required in deployed connector config
- `redelk_logstash_endpoint`: Logstash host and port for Filebeat output
- `redelk_identifier`: host identifier written into connector config
- `redelk_manage_locale`: enable or disable locale generation and defaults management;
  the `locales` package is always installed with the other dependencies
- `redelk_c2_filebeat_inputs`: enabled Filebeat inputs for C2 hosts
- `redelk_c2_sync_jobs`: enabled RedELK sync cron jobs for C2 hosts
- `redelk_sync_public_key_path`: public key copied into the C2 sync account
- `redelk_redir_manage_haproxy_logrotate`: manage redirector HAProxy logrotate

Design Notes
------------

- Redirectors get a monolithic `filebeat.yml`, because that stays functionally
  closer to the public legacy redirector script.
- C2 hosts still keep a more Ansible-style split between `filebeat.yml` and
  `inputs.d`, because that matches the cleaner structure used internally.
- The sync user's `authorized_keys_old` backup is only created when a different
  existing key file is being replaced. This is more conservative and more
  idempotent than the legacy shell flow.
- Filebeat restart behavior is declarative through handlers, not imperative
  stop/edit/start sequencing.

Intentional Differences From The Legacy Scripts
-----------------------------------------------

- Filebeat config is rendered declaratively rather than copied and mutated with
  shell commands.
- C2 main-config layout stays closer to the internal Ansible implementation
  than to the literal legacy example file.
- Key-file replacement behavior favors idempotence over literal shell parity.

Validation
----------

This role is exercised in the `molecule/redelk` scenario together with
`redelk-server`. The scenario verifies locale generation and defaults for both
connector types, including runtime and idempotence checks.
