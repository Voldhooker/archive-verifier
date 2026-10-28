namespace Archive.Evidence.ExportSet;

/// <summary>
/// A set's <c>export-set.json</c>, written last: who and what it covers, when, and every other file with its SHA-256,
/// so nothing can be changed, added or removed unseen.
/// </summary>
/// <param name="LegalEntityId">The one legal entity the records were narrowed to; null for the whole tenant. The audit log is the tenant's either way.</param>
/// <param name="CatalogueHead">The newest audit entry before the catalogue was read: in a set of the whole tenant, every record committed up to it has a catalogue line.</param>
/// <param name="AuditHead">The newest audit entry in the set, read once every package was fetched: the log was read up to it.</param>
/// <param name="Failed">Records whose package couldn't be fetched; a set that names any doesn't verify.</param>
public sealed record ExportSetManifest(
    int Format,
    Guid TenantId,
    Guid? LegalEntityId,
    DateTimeOffset StartedAt,
    DateTimeOffset EndedAt,
    ExportSetCounts Counts,
    long CatalogueHead,
    long AuditHead,
    IReadOnlyList<ExportSetFile> Files,
    IReadOnlyList<ExportSetFailure> Failed);
