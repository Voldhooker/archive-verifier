# Export package, format 1

An export package leaves the archive and is checked later, anywhere, by people who don't trust us: an auditor, a court, the customer. It must carry everything needed to prove that a record existed exactly like this at its sealing time, and nothing that proves more than that record. Packages are handed out and kept for years, so the format is fixed here, as the stored object's is (ADR 0006).

**The package** is a zip named `<record-id>.zip`:

| Entry | What |
|---|---|
| `export.json` | Format 1; the record id; the export time; the stored object's SHA-256; the record's AES-256 data key; and the seal: batch id, leaf index, tree size, the proof's sibling hashes lowest first, and the root. The seal is `null` while the record is unsealed. Hashes and the key are lower-case hex |
| `object.bin` | The stored object exactly as locked (ADR 0006): header, ciphertext, tag |
| `seal/token.tsr` | The seal batch's RFC 3161 token, DER, as the provider sent it; absent while unsealed |
| `originals/<n>-<name>` | Original *n*, as submitted, its name stripped of anything but letters, digits, `.`, `_`, `-` and spaces |
| `manifest.json` | The package's manifest, exactly as `object.bin` holds it |
| `policy.json` | The stored policy decisions, newest first, as `GET /v1/records/{id}/policy` answers them. For reading; the sealed facts are in the manifest |
| `README.txt` | What the package is and how to verify it |

Nothing else may be in it. Only the record's own proof, root and token are included, never the seal batch itself, which lists other tenants' record ids (ADR 0007).

**The checks**, in order; the first that fails is named:
1. `package`: the zip and `export.json` are format 1; a token is present exactly when a seal is named; no entry the format doesn't name.
2. `ciphertext-hash`: the SHA-256 of `object.bin` is the one `export.json` names.
3. `decryption`: `object.bin` decrypts with the data key for the record id; the GCM tag covers the header with the id.
4. `manifest`: the decrypted package checks out (ADR 0006) and names the record, `manifest.json` equals its manifest byte for byte, and each original is there under exactly the entry name its manifest name gives and equals the one it holds.
5. `proof`: the ciphertext hash, as an RFC 9162 leaf, leads through the proof to the root (ADR 0007).
6. `timestamp`: the token covers the root, and its signature checks against the certificate in it.
7. `trust`: that certificate names the time-stamping usage itself, chains to one the verifier was told to trust, and was valid at the token's time. Revocation isn't checked, since the verifier works offline.

A package that can't be read at all, unpacks to more than 512 MiB, or makes the reader throw fails `package`: the verifier never crashes on a crafted package.

All seven pass: the record is **valid**, sealed at the token's time by its signer.

**What valid proves, and what it doesn't.** It proves that the originals and the manifest existed exactly like this at the token's time. It doesn't prove who sealed them: anyone can build a package and have a provider stamp a root of their own, so valid alone doesn't show the archive held or accepted the record. That would take a statement the archive signs, which no part of the MVP makes. Nor does it cover `policy.json` or the export time in `export.json`; they are there to be read. The verifier says so with every valid result. The first four pass and there is no seal: it is **unsealed**, whole but with its time not proven. Otherwise it is **invalid**.

The verifier library (`Archive.Evidence`) and the CLI (`archive-verify`) depend on no server code, enforced by an architecture test (constitution, Evidence isolation).

## Considered Options

- **A second seal over plaintext hashes**, so a package needs no key. Every record would need a second sealed hash, and a hash of personal content would then live outside the encryption and outlive an erasure (decision record, open hash question). Giving out the record's own data key reveals nothing the originals in the package don't already show: the key opens that one record (ADR 0001).
- **Only `object.bin` and the key, no loose files.** Smaller, but a person couldn't open the originals without the verifier. With loose files, the verifier holds them to what `object.bin` decrypts to, so they can't differ unnoticed.
- **The whole seal batch in the package.** It would let the verifier rebuild the tree, but it names every other record in the batch, other tenants' included. The proof is enough to reach the root.
- **A built-in list of trusted providers.** The verifier trusts only the certificates it is given (`--trust`) until a qualified provider is chosen. Its chain then ships with the verifier. An eIDAS trusted list is a project of its own.

## Consequences

Every verifier, now and later, reads format 1 for as long as packages written in it are kept. A change is a new format number, never an edit of format 1. A package carries the data key of its record: whoever holds the package can read the record, as whoever holds its originals can.
