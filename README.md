# Archive verifier

`archive-verify` checks what the Archive service hands out, offline and without the service: a record's export
package, or an export set holding a tenant's whole archive. It needs nothing from us but the files and the timestamp
provider's CA certificate, so a customer, an auditor or a court can check the evidence themselves, even if the service
is gone.

The service itself is not open source. This repository holds the code that checks its evidence, and the formats that
code checks, so that you don't have to trust our build to trust our proof.

## Get it

Download the file for your platform, `SHA256SUMS` and `archive-verify.sigstore.json` from this repository's Releases,
then check that the file was built by this repository's release workflow from the tag you expect:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify archive-verify-linux-x64 --repo Voldhooker/archive-verifier \
  --signer-workflow Voldhooker/archive-verifier/.github/workflows/release.yml \
  --source-ref refs/tags/verifier-v<version> --deny-self-hosted-runners
```

`gh attestation` and its flags need a current GitHub CLI from https://cli.github.com; some Linux distributions package
an older one without it (Ubuntu 24.04 has 2.45).

The attestation ties the file to the tagged source and the workflow run that built it, on GitHub's runners. To check it
later without GitHub's API, keep the release's bundle and a copy of Sigstore's trusted root, taken once with
`gh attestation trusted-root > trusted_root.jsonl`, and add `--bundle archive-verify.sigstore.json
--custom-trusted-root trusted_root.jsonl` to the command above.

On Linux and macOS, make the file executable (`chmod +x`). The macOS file isn't notarised: remove the quarantine mark
with `xattr -d com.apple.quarantine archive-verify-osx-arm64`, and if macOS still refuses it, sign it for this machine
only with `codesign --sign - archive-verify-osx-arm64`.

Or build it yourself from the tag, with the .NET SDK named in `global.json`, as the release does:

```sh
dotnet test Archive.Verifier.slnx
dotnet publish src/Archive.Verifier -c Release --runtime linux-x64 --self-contained \
  -p:ContinuousIntegrationBuild=true -p:EnableCompressionInSingleFile=true -p:Version=<version> -o out
```

A file you build yourself is not promised to match the release byte for byte: the attestation, not a rebuild, is what
ties a release file to its source.

## Use it

```sh
archive-verify <package.zip> --trust <ca.pem>      # one record's export package
archive-verify set <folder> --trust <ca.pem>       # a whole export set
archive-verify export --api <url> --token-url <url> --client-id <id> --out <folder> [--legal-entity <id>]
```

Each `--trust` names a PEM or DER file with the CA certificate a timestamp provider's certificate chains to. Exit codes:
0 valid, 1 invalid (naming every failed check), 2 valid but not yet proven (records not sealed yet, or a log no anchor
holds yet), 3 usage. `export` pulls a set from the service with a client that holds the reader and auditor roles; its
secret comes from the environment variable `ARCHIVE_CLIENT_SECRET`.

A package and a set hold every record's data key: whoever holds them can read the records. Keep them as you keep the
archive.

## What it checks, and what that proves

The formats are in [`docs/formats`](docs/formats):

| Document | What |
|---|---|
| 0001 | One key per record, and erasure by destroying it |
| 0002, 0007 | Seal batches: a Merkle tree over records' hashes, one RFC 3161 timestamp on its root |
| 0006 | The archival package inside the encryption |
| 0008 | The audit log's hashes, and the daily anchor over every tenant's head |
| 0009 | The export package: one record and its proof |
| 0012 | The export set: everything, and the nine checks |

Each says what a valid result proves and what it doesn't. A format is never changed: a new one gets a new number, and
the verifier goes on reading the old ones.

## Contributing

This repository is published from the service's private repository at each release, one commit per release, so each
release's source is exactly what was built. Issues are welcome. A pull request can't be merged here; it is ported by
hand, and credited.

## Licence

Apache-2.0, see `LICENSE` and `NOTICE`.
