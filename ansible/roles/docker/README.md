Docker Role
===========

Installs Docker Engine on Ubuntu by following Docker's official apt repository installation flow:
https://docs.docker.com/engine/install/ubuntu/

Features
--------

- Removes conflicting distro Docker packages.
- Installs Docker prerequisites (`ca-certificates`, `curl`).
- Installs Docker's apt signing key to `/etc/apt/keyrings/docker.asc`.
- Configures Docker apt repo using deb822 source file (`/etc/apt/sources.list.d/docker.sources`).
- Installs `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin`, and `docker-compose-plugin`.
- Ensures Docker service is enabled and running.
- Requires Ubuntu 24.04 or newer, matching all RedELK deployment roles.

Requirements
------------

- Ubuntu 24.04 or newer.
- `become: true` for package and service management tasks.
- A working Ubuntu apt configuration.

Configuration
-------------

This role intentionally exposes no user-tunable variables for Docker packages,
repository settings, or service state. Values are hardcoded to keep behavior
consistent across hosts. The role derives apt architecture from system facts
(for example, `x86_64` -> `amd64`, `aarch64` -> `arm64`).

Example Playbook
----------------

```yaml
- hosts: docker_hosts
  become: true
  roles:
    - role: docker
```

Ubuntu Version Logic
--------------------

Docker's current Ubuntu installation steps are the same across supported Ubuntu
versions. The only release-specific input is the apt suite/codename, which this
role sets from `ansible_distribution_release` when configuring
`download.docker.com`.
