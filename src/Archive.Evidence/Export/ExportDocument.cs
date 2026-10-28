using System.Text.Json;
using System.Text.Json.Serialization;

namespace Archive.Evidence.Export;

/// <summary>
/// <c>export.json</c>, the heart of an export package, format 1 (ADR 0009): what <c>object.bin</c> is, the key that
/// opens it, and the record's seal. Hashes, keys and proof hashes are lower-case hex.
/// </summary>
/// <param name="ObjectSha256">SHA-256 of <c>object.bin</c>: the leaf its seal batch timestamps.</param>
/// <param name="DataKey">The record's own AES-256 data key, which opens <c>object.bin</c> and nothing else (ADR 0001).</param>
/// <param name="Seal">The record's place in its seal batch; null while it is not sealed.</param>
public sealed record ExportDocument(int Format, Guid RecordId, DateTimeOffset ExportedAt, string ObjectSha256, string DataKey, ExportSeal? Seal)
{
    public const int CurrentFormat = 1;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    public static ExportDocument Read(byte[] utf8) =>
        JsonSerializer.Deserialize<ExportDocument>(utf8, Json) ?? throw new InvalidDataException("export.json is empty.");

    public byte[] ToUtf8() => JsonSerializer.SerializeToUtf8Bytes(this, Json);
}
