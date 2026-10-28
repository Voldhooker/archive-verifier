using System.Text.Json.Serialization;

namespace Archive.Evidence.Packaging;

/// <summary>
/// <c>manifest.json</c>, the first entry of every archival package (ADR 0006). It lives inside the encryption, so the
/// file names and plaintext hashes it holds are erased with the record's key. The profile fields name the statutory
/// profile, null under custom rules alone; the custom fields came with custom profiles, are absent from older manifests and are
/// written only when set, so a manifest under the law alone reads as it always has.
/// </summary>
public sealed record PackageManifest(
    int Format,
    Guid RecordId,
    Guid LegalEntityId,
    string RecordType,
    DateOnly RecordDate,
    string RecordDateSource,
    DateOnly Expiry,
    string? ProfileCountry,
    string? ProfileVersion,
    string RetentionClass,
    IReadOnlyList<PackageComponent> Components,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? CustomProfile = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? CustomVersion = null)
{
    public const int CurrentFormat = 1;
}
