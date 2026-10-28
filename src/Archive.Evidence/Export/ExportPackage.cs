using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

using Archive.Evidence.Packaging;

namespace Archive.Evidence.Export;

/// <summary>
/// The export package, format 1 (ADR 0009): a zip a verifier checks offline. <c>export.json</c>, <c>object.bin</c>
/// and <c>seal/token.tsr</c> carry the proof; the originals, <c>manifest.json</c> and <c>policy.json</c> are there to be
/// read, and the verifier holds the originals and the manifest to what <c>object.bin</c> decrypts to.
/// </summary>
public static partial class ExportPackage
{
    public const string DocumentEntry = "export.json";
    public const string ObjectEntry = "object.bin";
    public const string TokenEntry = "seal/token.tsr";
    public const string ManifestEntry = "manifest.json";
    public const string PolicyEntry = "policy.json";
    public const string ReadmeEntry = "README.txt";
    public const string OriginalsFolder = "originals/";

    private const string Readme = """
        Archive export package, format 1 (ADR 0009).

        originals/        the record's files, as submitted
        manifest.json     what the archive recorded about them, with a SHA-256 of each
        policy.json       why the record is kept until its expiry
        object.bin        the record as the archive stores it under lock, encrypted
        export.json       the key that opens object.bin, and the record's seal
        seal/token.tsr    the RFC 3161 timestamp on the root of the record's seal batch

        To check it, offline: archive-verify <this file> --trust <provider CA certificate>
        The verifier decrypts object.bin, checks the originals and the manifest against it, follows the
        proof from object.bin's hash to the root, and checks that a trusted provider signed that root.
        """;

    /// <param name="token">The seal batch's token; null while the record is not sealed.</param>
    public static void Write(
        Stream output,
        ExportDocument document,
        byte[] stored,
        byte[]? token,
        byte[] manifestJson,
        IReadOnlyList<PackageContent> contents,
        byte[] policyJson)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(contents);
        using ZipArchive zip = new(output, ZipArchiveMode.Create, leaveOpen: true);
        Add(zip, ReadmeEntry, Encoding.UTF8.GetBytes(Readme));
        Add(zip, DocumentEntry, document.ToUtf8());
        Add(zip, ObjectEntry, stored);
        if (token is not null)
        {
            Add(zip, TokenEntry, token);
        }

        // The manifest exactly as sealed, never a fresh serialization: the verifier holds the two byte for byte.
        Add(zip, ManifestEntry, manifestJson);
        Add(zip, PolicyEntry, policyJson);
        for (int i = 0; i < contents.Count; i++)
        {
            Add(zip, OriginalEntry(i + 1, contents[i].Name), contents[i].Bytes);
        }
    }

    /// <summary>The entry of original <paramref name="number"/>: <c>originals/&lt;n&gt;-&lt;name&gt;</c>, the name safe to extract.</summary>
    public static string OriginalEntry(int number, string name)
    {
        string safe = UnsafeCharacters().Replace(name, "_").Trim('.', ' ');
        return $"{OriginalsFolder}{number}-{(safe.Length == 0 ? "file" : safe[..Math.Min(safe.Length, 100)])}";
    }

    /// <summary>The number in an original's entry name, or null when the name isn't one.</summary>
    public static int? OriginalNumber(string entry)
    {
        Match match = OriginalName().Match(entry);
        return match.Success && int.TryParse(match.Groups[1].Value, out int number) && number > 0 ? number : null;
    }

    private static void Add(ZipArchive zip, string name, ReadOnlyMemory<byte> bytes)
    {
        ZipArchiveEntry entry = zip.CreateEntry(name, CompressionLevel.Optimal);
        entry.LastWriteTime = new DateTimeOffset(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);
        using Stream stream = entry.Open();
        stream.Write(bytes.Span);
    }

    [GeneratedRegex(@"[^A-Za-z0-9._ -]")]
    private static partial Regex UnsafeCharacters();

    [GeneratedRegex(@"^originals/([1-9][0-9]{0,5})-[A-Za-z0-9._ -]+$")]
    private static partial Regex OriginalName();
}
