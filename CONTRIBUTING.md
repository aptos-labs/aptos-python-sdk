# Contributing Guide

## Publishing

PyPI deployment is automated via [`.github/workflows/publish.yaml`](.github/workflows/publish.yaml). On each published GitHub Release, CI runs unit and BDD tests, builds the distribution with `uv build`, and uploads to PyPI using [OIDC trusted publishing](https://docs.pypi.org/trusted-publishers/) (no long-lived API tokens in GitHub Secrets).

### One-time maintainer setup

Before the first automated publish from this repository, configure a trusted publisher on [pypi.org](https://pypi.org/manage/project/aptos-sdk/settings/publishing/):

| Field | Value |
|---|---|
| PyPI project name | `aptos-sdk` |
| Owner | `aptos-labs` |
| Repository name | `aptos-python-sdk` |
| Workflow name | `publish.yaml` |
| Environment name | `pypi` |

Then create a GitHub **environment** named `pypi` under **Settings → Environments** (no secrets required for OIDC).

### Releasing a new version

1. Bump `version` in [`pyproject.toml`](pyproject.toml) and add a dated section to [`CHANGELOG.md`](CHANGELOG.md).
2. Merge the version bump to `main`.
3. Create a [GitHub Release](https://github.com/aptos-labs/aptos-python-sdk/releases/new) from `main`:
   - Tag: `v<version>` (must match `pyproject.toml`, e.g. `v0.12.0` for version `0.12.0`)
   - Title: `v<version>`
   - Paste the new `CHANGELOG.md` section as release notes
4. Click **Publish release**. The `Publish aptos-sdk to PyPI` workflow runs automatically.

To dry-run the pipeline without publishing, run the workflow manually from the Actions tab with **Dry run** enabled (tests and build only).

### Local build

```
uv build
```
