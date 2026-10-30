# Pinned RedELK releases

A GitHub release, its source `VERSION`, Compose files and all images built from
that source use the **same exact tag**, including any `v` prefix. Never reuse or
move a published release tag. Branch builds are development artifacts, not a
production default. External images retain their separate upstream versions.

## Prepare a release

Choose the real release tag first; no new version is assigned automatically.
From the repository root, with `RELEASE_TAG` set to that exact tag:

```sh
python3 scripts/pin_release.py "$RELEASE_TAG"
python3 scripts/pin_release.py --check "$RELEASE_TAG"
git diff -- VERSION elkserver/redelk-limited.yml elkserver/redelk-full.yml elkserver/.env.tmpl
```

The dependency-free Python helper preserves Compose comments and only changes
own-image tags, `VERSION` and the environment template's version. It validates
all inputs before writing. It never commits, tags, builds or publishes anything.
The local-build `redelk-dev.yml` is not a release deployment file.

Review and commit the prepared source before creating the matching GitHub tag
and release. Publishing remains a maintainer action. Publishing the GitHub release
(including a prerelease) triggers the five production image builds, also when the
tag already existed. Tag pushes alone do not publish production images.
The production image workflows check the committed release files before logging in/building and
publish exactly the Git tag, without implicit `latest` or stripped `v` aliases.
All five own images share that tag; successful builds of the required core
images remain a prerequisite for a supported deployment. A tag alone does not
prove runtime compatibility or that every image build succeeded.

## Deploy that release

Use the prepared release checkout as `redelk_local_repo_path` and explicitly set
`redelk_version` to its exact GitHub tag. There is no `master` fallback. The role
rejects a mismatching `VERSION`, variable-based/other-tag core images, and rolling
branch tags before changing application files or keys. It only validates the
limited/core stack; legacy-full images do not become Ansible dependencies.

Changing `.env` cannot select another own-image version: the release Compose
contains literal tags. `redelk_docker_environment.REDELKREPO` can select a mirror
that supplies the same release-tagged images, not an independent code version.
No automatic checkout, registry publication, key rotation, image digest policy
or runtime password migration is introduced.

The current development tree may intentionally still have an older `VERSION`
and unstamped Compose. Do not treat it as a new release or retag changed code as
an already published version; select and prepare a real release first.
