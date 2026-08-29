# Release signing and verification (Sigstore cosign)

Every release of this repository is produced by
[`.github/workflows/release.yml`](../.github/workflows/release.yml) when a `v*` tag is pushed, and
everything it publishes is signed **keylessly** with [Sigstore cosign](https://docs.sigstore.dev/):
the GitHub Actions job authenticates to Sigstore with its OIDC token, Fulcio issues a short-lived
certificate bound to the workflow identity, and the signature is recorded in the Rekor transparency
log. There is no long-lived signing key to leak or rotate — what you verify is *"this artifact was
built by the `release.yml` workflow of `c0de-ch/mcp-auth-demo`"*.

## What a release contains

| Asset | Signature / attestation |
|---|---|
| `mcp-auth-demo-vX.Y.Z.tar.gz` — `git archive` of the tag | `mcp-auth-demo-vX.Y.Z.tar.gz.sigstore.json` (cosign bundle) + SLSA build-provenance attestation |
| `SHA256SUMS` | `SHA256SUMS.sigstore.json` |
| `ghcr.io/c0de-ch/mcp-auth-demo:vX.Y.Z` (also `:X.Y`, `:latest`) | cosign signature stored next to the image in the registry + SLSA provenance attestation pushed to the registry |

## Verify the source archive

```bash
TAG=v0.1.0
gh release download "$TAG" --repo c0de-ch/mcp-auth-demo   # or download the assets from the release page

cosign verify-blob \
  --bundle "mcp-auth-demo-$TAG.tar.gz.sigstore.json" \
  --certificate-identity-regexp '^https://github.com/c0de-ch/mcp-auth-demo/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "mcp-auth-demo-$TAG.tar.gz"

sha256sum -c SHA256SUMS
```

`--certificate-identity-regexp` pins the signer to a workflow of this repository; use the exact
identity `https://github.com/c0de-ch/mcp-auth-demo/.github/workflows/release.yml@refs/tags/$TAG`
with `--certificate-identity` if you want to bind to the tag as well.

## Verify the container image

```bash
cosign verify ghcr.io/c0de-ch/mcp-auth-demo:v0.1.0 \
  --certificate-identity-regexp '^https://github.com/c0de-ch/mcp-auth-demo/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The output lists the certificate's subject (the workflow identity), the OIDC issuer and the Rekor
log index. Pin the digest (`ghcr.io/c0de-ch/mcp-auth-demo@sha256:…`) in anything you deploy.

## Verify the build provenance (SLSA)

```bash
gh attestation verify "mcp-auth-demo-$TAG.tar.gz" --repo c0de-ch/mcp-auth-demo
gh attestation verify oci://ghcr.io/c0de-ch/mcp-auth-demo:v0.1.0 --repo c0de-ch/mcp-auth-demo
```

The attestation states which workflow, commit and runner built the artifact
([`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)).

## Why this matters for an auth demo

The examples in this repository are the kind of code people copy into their own MCP servers.
Signed releases let you check that the archive or image you fetched is what CI built from a tagged
commit — the same "verify the issuer, verify the audience, verify the signature" discipline the
examples apply to tokens, applied to the software itself. Releases are immutable: a tag is never
moved or re-signed; fixes ship as a new patch version.

## Running the image

```bash
docker run --rm -p 4104:4104 -e PUBLIC_HOST=192.168.1.10 \
  ghcr.io/c0de-ch/mcp-auth-demo:v0.1.0 ex:04:server
```

`PUBLIC_HOST` must be the address other machines and Keycloak use to reach the host; the image runs
any `ex:NN:*` script from `package.json`.
