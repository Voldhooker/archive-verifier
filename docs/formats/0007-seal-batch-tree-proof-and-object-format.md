# Seal batch tree, proofs and stored batch, format 1

A seal batch (ADR 0002) is read by every future verifier for as long as any record sealed in it is kept, so its tree, its proofs and its stored form are fixed here before the first batch is written, as the package format is (ADR 0006).

**The tree** is the Merkle tree hash of RFC 9162 §2.1 with SHA-256. Each leaf's data is the 32 raw bytes of one record's ciphertext SHA-256, the hash the catalogue keeps. A leaf hashes as SHA-256(0x00 ‖ data) and a node as SHA-256(0x01 ‖ left ‖ right), so a leaf can never pass as a node. A tree whose size is not a power of two splits at the largest power of two below its size, so no hash is ever duplicated. The leaves are ordered by commit time, then record id, so the same records always make the same tree.

**A proof** is RFC 9162's inclusion proof: the leaf index, the tree size, and the sibling hashes from the leaf up to the root, lowest first. It is checked with the algorithm of §2.1.3.2. The catalogue keeps the index and the hashes per record, and the tree size with the batch.

**The timestamp** is one RFC 3161 TimeStampToken over the root, requested with SHA-256, a nonce and the provider's certificate. It is stored exactly as the provider sent it.

**The stored batch** is UTF-8 JSON under compliance lock, at `seal-batches/<yyyy>/<mm>/<seal-batch-id>` in the archive bucket, locked until the latest retain-until of the records it covers:

| Field | Value |
| --- | --- |
| `format` | 1 |
| `sealBatchId` | The batch's id |
| `tree` | `rfc9162-sha256` |
| `root` | The root, lower-case hex |
| `leaves` | In leaf order, each `{ "recordId", "ciphertextSha256" }`, the hash in lower-case hex |
| `timestampToken` | The token, base64 of its DER bytes |

Its object metadata holds `seal-batch-id` and `object-format` only. A record id and a ciphertext hash are all it says about a record: nothing personal, and nothing an erasure must reach.

## Considered Options

- **A tree of our own** (plain SHA-256 of the two children, an odd node duplicated). Shorter to write, but a leaf could pass as a node, a duplicated last node lets two different leaf lists give the same root, and every verifier would need our description instead of a published standard with test vectors and existing implementations.
- **One batch per tenant.** Each tenant's proof would show only its own records' hashes, but the number of paid tokens would grow with every tenant (Q30). A batch spans tenants; the other leaves a proof reveals are ciphertext hashes, which say nothing about their records.
- **Assigning each record to an open batch at commit.** It needs ingest to know about batches, and a batch left open by a provider outage to be found again. Forming the batch when sealing, from every record without a seal, leaves ingest unchanged and makes a retry after an outage take everything waiting.

## Consequences

An export gives a tenant its own record's proof, the batch root and the token, never the whole stored batch, which lists other tenants' record ids. The proof and the root are enough to check the token; the stored batch is for the operator, to rebuild the tree.

Every verifier, now and later, reads format 1 of the tree, the proof and the stored batch for as long as any record sealed with it is kept. A change to any of them is a new version number, never an edit of version 1.
