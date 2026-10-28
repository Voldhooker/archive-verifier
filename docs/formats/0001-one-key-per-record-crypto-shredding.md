# One encryption key per record, erased by destroying the key

Records live in write-once storage that cannot delete them before their lock ends, yet GDPR erasure and early erasure after a shortened retention must take effect at once and also cover backups. Each record is therefore encrypted with its own data key, wrapped by the tenant's master key in the key service, and erasure destroys the wrapped key and the catalogue metadata. The encrypted object stays in storage, unreadable, until it can be purged.

## Considered Options

- One key per tenant: erasure would have to rewrite storage, which object lock forbids.
- Storage-level encryption only: cannot make a single record unreadable.

## Consequences

Losing a tenant's master key makes all its records unreadable, so the master key is backed up apart from the data. An erasure is complete only once database backups holding the old wrapped key have expired.
