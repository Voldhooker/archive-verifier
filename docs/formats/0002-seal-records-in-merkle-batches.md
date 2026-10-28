# Seal records in Merkle batches, not one timestamp per record

A qualified RFC 3161 timestamp costs a paid token and a provider call each time. Records are therefore sealed in seal batches: a Merkle tree over the ciphertext hashes of up to 10 minutes or 10,000 records, one qualified timestamp on its root, and a proof stored with each record so it can be verified on its own (decision Q30).

## Considered Options

- One timestamp per record: simpler to verify, but cost and provider load grow with every record, and switching to batches later would leave two kinds of proof in the archive forever.

## Consequences

A record is committed some minutes before it is sealed, so submission status and webhooks report both milestones.
