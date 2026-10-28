using System.Text.Json;
using System.Text.Json.Serialization;

namespace Archive.Evidence.ExportSet;

/// <summary>
/// The export set, format 1 (ADR 0012): a folder holding everything a tenant's archive holds, verifiable offline. Its
/// files are written and read with these names and these JSON settings, by the server's endpoints, the export tool and
/// the verifier alike.
/// </summary>
public static class ExportSetFormat
{
    public const int Current = 1;

    /// <summary>Written last, naming every other file with its hash: a set without it is unfinished.</summary>
    public const string Manifest = "export-set.json";

    public const string Catalogue = "catalogue.jsonl";

    public const string RecordsFolder = "records";

    public const string AuditEntries = "audit/entries.jsonl";

    public const string AnchorsFolder = "audit/anchors";

    public const string ProfilesFolder = "profiles";

    public const string Readme = "README.txt";

    /// <summary>camelCase, enums as strings, no indentation: one JSON value per line in the .jsonl files.</summary>
    public static JsonSerializerOptions Json { get; } = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    /// <summary>A record's package in the set: <c>records/&lt;id&gt;.zip</c>.</summary>
    public static string PackagePath(Guid recordId) => $"{RecordsFolder}/{recordId}.zip";

    /// <summary>An anchor's proof for the tenant, <c>audit/anchors/&lt;id&gt;.json</c>, beside its token, <c>.tsr</c>.</summary>
    public static string AnchorProofPath(Guid anchorId) => $"{AnchorsFolder}/{anchorId}.json";

    public static string AnchorTokenPath(Guid anchorId) => $"{AnchorsFolder}/{anchorId}.tsr";
}
