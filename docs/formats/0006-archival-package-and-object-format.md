# Archival package and stored object, format 1

Everything written under object lock stays readable only if every future verifier understands its format, so the format is fixed here before the first record is stored. Format 1 has two layers.

**The package** is an uncompressed POSIX ustar archive. Its first entry is `manifest.json`, then each original, unchanged, as `content/1`, `content/2` and so on. Entries carry mode 0644, no owner and the Unix epoch as their time, so the same record always gives the same bytes. The manifest holds the format number, record id, legal entity, record type, record date and its source, expiry, profile country and version, retention class, and per component its path, the name the submitter gave it, media type, size and lower-case hex SHA-256.

**The stored object** is the package encrypted with the record's own data key (ADR 0001):

| Bytes | Field |
| --- | --- |
| 0–6 | `ARCHIVE` in ASCII |
| 7 | Format version, 1 |
| 8 | Algorithm, 1 = AES-256-GCM |
| 9–20 | Nonce, 12 random bytes |
| 21–36 | Record id, RFC 4122 byte order |
| 37 … n−17 | The package, encrypted |
| n−16 … n−1 | GCM tag |

The whole 37-byte header is associated data. An object copied onto another record's id, or with any header byte changed, fails to decrypt. File names and plaintext hashes exist only inside the encryption, so they are erased with the key, and nothing personal reaches the object's S3 metadata.

## Considered Options

- **Zip instead of tar.** More familiar to people opening a raw package, but it brings compression and zip's format variants into a permanent format. An export package can still be handed out zipped.
- **Chunked encryption** (fixed-size segments, each sealed on its own). It streams large files without holding them in memory, but it is a custom format with its own verifier before anything needs it. Format 1 encrypts in one pass, so a package must fit in memory; the ingest cap (100 MB to start) keeps it there. A chunked format can arrive as version 2, next to version 1.
- **Plaintext hashes outside the encryption**, in the catalogue or object metadata. They would outlive an erasure, and a hash of personal data may itself be personal data (decision record, open question).

## Consequences

Every verifier, now and later, reads format 1 for as long as any record written in it is kept. A change to either layer is a new version number, never an edit of version 1.
