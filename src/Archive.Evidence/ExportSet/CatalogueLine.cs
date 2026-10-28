using System.Text.Json.Serialization;

namespace Archive.Evidence.ExportSet;

/// <summary>
/// One record in a set's catalogue, erased and purged ones included: what it is, under which rules it was kept, and what
/// became of it. Ids, codes and dates, never a name, an address or a subject, so the line can outlive the record: for an
/// erased record it is all there is. From format 2, a kept record's fields too, the submitting system's facts, which can
/// name someone; an erased record has none left.
/// </summary>
/// <param name="Type">email or file.</param>
/// <param name="Status">committed, sealed, erased or purged.</param>
/// <param name="Profile">The statutory profile and version its decision used, such as "DK 2026.1"; null under custom rules alone.</param>
/// <param name="CustomProfile">The custom profile and version, such as "ACME-RESEARCH 3"; null under the law alone.</param>
/// <param name="ClassSource">Where its class came from: submission, mailboxRule, entityDefault, reclassification, ….</param>
/// <param name="RecordDateSource">Where its record date came from, such as ownServerReceived or dateHeader.</param>
/// <param name="Held">Whether an open legal hold covered it when the line was read.</param>
/// <param name="ErasureBasis">The legal basis of its erasure, such as "retention ended"; null while kept.</param>
/// <param name="Fields">
/// Format 2: the facts the submitting system gave it at ingest, such as invoice-number, by key; empty for none or once
/// erased. Absent from a format-1 line, and never written as null, so a format-1 line reads and writes as it was.
/// </param>
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
    DateTimeOffset? PurgedAt,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyDictionary<string, string>? Fields = null)
{
    /// <summary>Whether the set holds a package for it: a record that is still kept. Read from the status, never written.</summary>
    [JsonIgnore]
    public bool Kept => Status is "committed" or "sealed";
}
