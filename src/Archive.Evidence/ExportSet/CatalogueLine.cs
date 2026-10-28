using System.Text.Json.Serialization;

namespace Archive.Evidence.ExportSet;

/// <summary>
/// One record in a set's catalogue, erased and purged ones included: what it is, under which rules it was kept, and what
/// became of it. Ids, codes and dates only, never a name, an address or a subject, so the line can outlive the record:
/// for an erased record it is all there is.
/// </summary>
/// <param name="Type">email or file.</param>
/// <param name="Status">committed, sealed, erased or purged.</param>
/// <param name="Profile">The statutory profile and version its decision used, such as "DK 2026.1"; null under custom rules alone.</param>
/// <param name="CustomProfile">The custom profile and version, such as "ACME-RESEARCH 3"; null under the law alone.</param>
/// <param name="ClassSource">Where its class came from: submission, mailboxRule, entityDefault, reclassification, ….</param>
/// <param name="RecordDateSource">Where its record date came from, such as ownServerReceived or dateHeader.</param>
/// <param name="Held">Whether an open legal hold covered it when the line was read.</param>
/// <param name="ErasureBasis">The legal basis of its erasure, such as "retention ended"; null while kept.</param>
public sealed record CatalogueLine(
    Guid RecordId,
    Guid LegalEntityId,
    string Type,
    string Status,
    string RetentionClass,
    string? ClassSource,
    string? Profile,
    string? CustomProfile,
    DateOnly RecordDate,
    string? RecordDateSource,
    DateTimeOffset CommittedAt,
    DateTimeOffset? SealedAt,
    DateOnly Expiry,
    DateTimeOffset RetainUntil,
    bool Held,
    DateTimeOffset? ErasedAt,
    string? ErasureBasis,
    DateTimeOffset? PurgedAt)
{
    /// <summary>Whether the set holds a package for it: a record that is still kept. Read from the status, never written.</summary>
    [JsonIgnore]
    public bool Kept => Status is "committed" or "sealed";
}
