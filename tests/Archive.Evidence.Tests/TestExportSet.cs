using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Archive.Evidence.Audit;
using Archive.Evidence.ExportSet;
using Archive.Evidence.Sealing;

namespace Archive.Evidence.Tests;

/// <summary>
/// Writes an export set as format 1 describes it (ADR 0012), without the server or the export tool: two sealed records
/// and one erased, the tenant's audit log, and a daily anchor over it signed by <see cref="TestEvidence"/>'s provider.
/// Written from the format, not by the exporter's code, so the verifier is held to the format itself.
/// </summary>
internal static class TestExportSet
{
    /// <summary>The newest entry the anchor holds: the erasure. The export's own read follows it.</summary>
    public const long AnchoredHead = 5;

    /// <summary>The newest entry before the catalogue was read.</summary>
    public const long CatalogueHead = 5;

    public static readonly Guid TenantId = Guid.Parse("0199e9a0-0000-7000-8000-0000000000b1");
    public static readonly Guid First = Guid.Parse("0199e9a0-0000-7000-8000-00000000e101");
    public static readonly Guid Second = Guid.Parse("0199e9a0-0000-7000-8000-00000000e102");
    public static readonly Guid Erased = Guid.Parse("0199e9a0-0000-7000-8000-00000000e103");

    private static readonly Guid LegalEntity = Guid.Parse("0199e9a0-0000-7000-8000-0000000000c1");
    private static readonly Guid AnchorId = Guid.Parse("0199e9a0-0000-7000-8000-00000000a001");
    private static readonly DateTimeOffset Start = new(2026, 10, 20, 8, 0, 0, TimeSpan.Zero);

    /// <summary>Writes the set into <paramref name="folder"/>, which must be empty.</summary>
    public static void Write(TestEvidence evidence, string folder)
    {
        Directory.CreateDirectory(Path.Combine(folder, ExportSetFormat.RecordsFolder));
        Directory.CreateDirectory(Path.Combine(folder, ExportSetFormat.AnchorsFolder));
        foreach (Guid id in (Guid[])[First, Second])
        {
            File.WriteAllBytes(Path.Combine(folder, ExportSetFormat.PackagePath(id)), evidence.Package(recordId: id));
        }

        WriteLines(folder, ExportSetFormat.Catalogue, [Line(First), Line(Second), Line(Erased) with
        {
            Status = "erased", ErasedAt = Start.AddDays(2), ErasureBasis = "erasure request",
        }]);

        WriteLog(folder, Log());
        List<AuditEntryLine> log = ReadLog(folder);
        WriteAnchor(evidence, folder, Convert.FromHexString(log[(int)AnchoredHead - 1].Hash));
        File.WriteAllText(Path.Combine(folder, ExportSetFormat.Readme), "An export set, format 1, for the verifier's tests.\n");

        ExportSetManifest manifest = new(
            ExportSetFormat.Current,
            TenantId,
            null,
            Start.AddDays(3),
            Start.AddDays(3).AddMinutes(5),
            new ExportSetCounts(3, 0, 2, 1, 0, log.Count, 1),
            CatalogueHead,
            log.Count,
            [],
            []);
        WriteManifest(folder, manifest);
    }

    public static ExportSetManifest Manifest(string folder) =>
        JsonSerializer.Deserialize<ExportSetManifest>(File.ReadAllBytes(Path.Combine(folder, ExportSetFormat.Manifest)), ExportSetFormat.Json)!;

    /// <summary>Writes <paramref name="manifest"/>, naming every file in the folder but itself, each with its hash and size as they are now.</summary>
    public static void WriteManifest(string folder, ExportSetManifest manifest)
    {
        ExportSetFile[] files = [.. Directory.GetFiles(folder, "*", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(folder, f).Replace('\\', '/'))
            .Where(f => f != ExportSetFormat.Manifest)
            .Order(StringComparer.Ordinal)
            .Select(f => Hashed(folder, f))];
        File.WriteAllBytes(Path.Combine(folder, ExportSetFormat.Manifest), JsonSerializer.SerializeToUtf8Bytes(manifest with { Files = files }, ExportSetFormat.Json));
    }

    /// <summary>
    /// The proof for one leaf of the daily anchor over three tenants' heads, this tenant's as leaf 1 at
    /// <paramref name="head"/>; leaves 0 and 2 are other tenants'.
    /// </summary>
    public static AnchorProof ProofOf(byte[] head, int leafIndex)
    {
        (Guid Tenant, long Sequence, byte[] Head)[] heads =
        [
            (Guid.Parse("0199e9a0-0000-7000-8000-0000000000a1"), 17, SHA256.HashData("a"u8)),
            (TenantId, AnchoredHead, head),
            (Guid.Parse("0199e9a0-0000-7000-8000-0000000000a3"), 3, SHA256.HashData("c"u8)),
        ];
        (byte[] root, IReadOnlyList<InclusionProof> proofs) = MerkleTree.Build([.. heads.Select(h => AnchorLeaf.Of(h.Tenant, h.Sequence, h.Head))]);
        (Guid tenant, long sequence, byte[] leafHead) = heads[leafIndex];

        // Now, not on the set's dates: the test provider's certificate is valid from yesterday.
        return new AnchorProof(
            AnchorId,
            DateTimeOffset.UtcNow,
            Convert.ToHexStringLower(root),
            proofs[leafIndex].TreeSize,
            proofs[leafIndex].LeafIndex,
            [.. proofs[leafIndex].Path.Select(Convert.ToHexStringLower)],
            tenant,
            sequence,
            Convert.ToHexStringLower(leafHead));
    }

    public static void WriteProof(string folder, AnchorProof proof) =>
        File.WriteAllBytes(Path.Combine(folder, ExportSetFormat.AnchorProofPath(proof.AnchorId)), JsonSerializer.SerializeToUtf8Bytes(proof, ExportSetFormat.Json));

    /// <summary>The set's log, read back.</summary>
    public static List<AuditEntryLine> ReadLog(string folder) =>
        [.. File.ReadLines(Path.Combine(folder, ExportSetFormat.AuditEntries)).Select(l => JsonSerializer.Deserialize<AuditEntryLine>(l, ExportSetFormat.Json)!)];

    /// <summary>Writes the log with every content and chain hash recomputed from the first entry, as a forger would.</summary>
    public static void WriteLog(string folder, IEnumerable<AuditEntryLine> entries)
    {
        List<AuditEntryLine> lines = [];
        byte[] previous = AuditHashes.Genesis.ToArray();
        foreach (AuditEntryLine entry in entries)
        {
            byte[] content = AuditHashes.ContentHash(TenantId, entry.At, entry.Actor, entry.Action, entry.Target, entry.Outcome, entry.CorrelationId);
            previous = AuditHashes.Link(previous, content);
            lines.Add(entry with { ContentHash = Convert.ToHexStringLower(content), Hash = Convert.ToHexStringLower(previous) });
        }

        WriteLines(folder, ExportSetFormat.AuditEntries, lines);
    }

    /// <summary>The audit log's entries, unhashed: three commits, a refused search, the erasure, and the export's catalogue read.</summary>
    private static List<AuditEntryLine> Log()
    {
        (string Actor, string Action, string? Target, string Outcome)[] entries =
        [
            ("system:ingest", "CommitRecord", $"record/{First}", "succeeded"),
            ("system:ingest", "CommitRecord", $"record/{Second}", "succeeded"),
            ("system:ingest", "CommitRecord", $"record/{Erased}", "succeeded"),
            ("5d1c7a0e-6b2f-4c1a-9e1d-000000000001", "SearchRecords", null, "refused:429"),
            ("5d1c7a0e-6b2f-4c1a-9e1d-000000000001", "EraseRecord", $"record/{Erased}", "succeeded"),
            ("export-client", "ListCatalogue", null, "succeeded"),
        ];

        return [.. entries.Select((e, i) => new AuditEntryLine(i + 1, Start.AddHours(i), e.Actor, e.Action, e.Target, e.Outcome, null, string.Empty, string.Empty))];
    }

    private static void WriteAnchor(TestEvidence evidence, string folder, byte[] head)
    {
        AnchorProof proof = ProofOf(head, 1);
        WriteProof(folder, proof);
        File.WriteAllBytes(
            Path.Combine(folder, ExportSetFormat.AnchorTokenPath(proof.AnchorId)), TestEvidence.Token(Convert.FromHexString(proof.Root), evidence.Signer, proof.StampedAt));
    }

    private static CatalogueLine Line(Guid id) => new(
        id,
        LegalEntity,
        "file",
        "sealed",
        "DK-BOOKKEEPING",
        "submission",
        "DK 2026.1",
        null,
        new DateOnly(2026, 10, 1),
        "submitter",
        Start,
        Start.AddHours(1),
        new DateOnly(2031, 12, 31),
        new DateTimeOffset(2032, 1, 1, 0, 0, 0, TimeSpan.Zero),
        false,
        null,
        null,
        null);

    private static void WriteLines<T>(string folder, string path, IEnumerable<T> lines)
    {
        StringBuilder text = new();
        foreach (T line in lines)
        {
            text.Append(JsonSerializer.Serialize(line, ExportSetFormat.Json)).Append('\n');
        }

        File.WriteAllText(Path.Combine(folder, path), text.ToString());
    }

    private static ExportSetFile Hashed(string folder, string path)
    {
        byte[] bytes = File.ReadAllBytes(Path.Combine(folder, path));
        return new ExportSetFile(path, Convert.ToHexStringLower(SHA256.HashData(bytes)), bytes.Length);
    }
}
