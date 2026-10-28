# Daily audit anchor: leaf, tree and stored anchor, format 1

The audit log's hashes are unkeyed. A table owner who rewrites a tenant's chain and recomputes every hash leaves nothing a walk of the chain can find. The daily anchor (Q21) makes such a rewrite detectable: once a day, the head of every tenant's chain is timestamped by an outside provider and stored where nobody can change it. Every check of a chain then holds it to every anchor. A verifier reads anchors for as long as the audit log is kept, so their format is fixed here, as the seal batch's is (ADR 0007).

**The leaf** is one tenant's head, 57 bytes:

| Bytes | Field |
| --- | --- |
| 0 | Format, 1 |
| 1–16 | The tenant id, big-endian (RFC 9562 order, as in the entry content hash) |
| 17–24 | The head's sequence, a big-endian int64 |
| 25–56 | The head's chain hash |

The leaf names its tenant and its place in the chain, so a proof can't be moved to another tenant or another entry.

**The tree** is ADR 0007's: RFC 9162's Merkle tree hash with SHA-256, over the leaves ordered by tenant id. One RFC 3161 token, requested with SHA-256, a nonce and the provider's certificate, covers the root. The token is stored exactly as the provider sent it.

**The stored anchor** is UTF-8 JSON under compliance lock, at `anchors/<yyyy>/<mm>/<anchor-id>` in the archive bucket, locked for 10 years (`Anchoring:RetentionYears`):

| Field | Value |
| --- | --- |
| `format` | 1 |
| `anchorId` | The anchor's id |
| `tree` | `rfc9162-sha256` |
| `leafFormat` | 1 |
| `root` | The root, lower-case hex |
| `heads` | In leaf order, each `{ "tenantId", "sequence", "headHash" }`, the hash in lower-case hex |
| `timestampToken` | The token, base64 of its DER bytes |

Its object metadata holds `anchor-id` and `object-format` only.

**Checking a chain against anchors.** Every version of every object under `anchors/` is read back, delete markers left out. Neither a newer version at an anchor's key nor a delete marker hides a locked version. The database's copy, which a table owner could change, is never read. An anchor holds a tenant's chain only if its heads rebuild its root and its token covers that root. The chain is then broken:
- at the first anchored head whose entry has another hash. Every anchor naming that head must agree, so a second anchor can't stand in for the first;
- at the first anchored head beyond the chain's last entry, when entries were removed;
- at every head an anchor names, when the anchor fails its own checks.

Any anchor that fails its own checks, or can't be read, makes the log not intact, at startup and in `/v1/audit/verification` alike.

**Anchoring never vouches for a rewrite.** Before a tenant's head is anchored, its chain is checked from its last anchored head. That head is taken from the locked anchors, never from the `audit_anchor_heads` rows, and the entry at its sequence must still have the hash every anchor holds for it. A chain that doesn't continue from it is left out. Changing the rows therefore can't make the anchorer lock in a head that doesn't exist.

**Who could still interfere.** Someone who can write the archive bucket, which the archive's own user can, could plant an object under `anchors/` with a token they signed themselves. The check only verifies a token's signature against the certificate inside it; it does not decide whether that certificate is a trusted provider's. A planted anchor can therefore only add claims the true chain contradicts: it raises a false alarm, never hides a rewrite, because every true anchor is still read. Deciding whether a token comes from a trusted provider is the verifier's job (part 3), which knows the trust lists. The prefix is fixed rather than configurable, so no setting can hide older anchors.

## Considered Options

- **One token per tenant.** Each tenant's proof would show nothing of other tenants, but the number of paid tokens would grow with every tenant. One anchor across tenants reveals only other tenants' head hashes and entry counts, and an export hands out the sibling hashes of a proof, not the other leaves.
- **The head hash alone as the leaf.** Shorter, but a head would then not say whose chain or which entry it is, and a proof from one tenant's anchor could be presented for another's.
- **Checking only the newest anchor.** Cheaper, but a rewrite that waits for the next anchor gets its forged head anchored, and only the older anchors still contradict it. Reading 1,000 anchors took 0.8 seconds against RustFS, about 3 seconds for ten years of daily anchors. A version that checked out is kept in memory, since a locked version never changes, so later checks only list.
- **Locking each anchor until the latest retain-until of the records.** It follows the records, but a tenant without records gets no date, and the audit log outlives its records. A fixed period, 10 years, stands until a lawyer says how long the log must be kept.

## Consequences

Every verifier, now and later, reads format 1 of the leaf and the stored anchor for as long as the audit log is kept. A change to either is a new version number, never an edit of version 1. Entries written since the newest anchor are not yet protected: a rewrite of them shows only once the next anchor holds them, a window of up to one day.
