# Contributing Guide
## Publishing
To publish the SDK, follow these steps.

First, make sure you have updated the changelog and bumped the SDK version if necessary.

Build and publish (via GitHub Actions with OIDC trusted publishing):
```
git tag v<version>
git push origin v<version>
```

Or manually build:
```
uv build
```
