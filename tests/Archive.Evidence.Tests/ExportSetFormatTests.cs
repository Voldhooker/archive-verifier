using System.Text.Json;

using Archive.Evidence.ExportSet;
using Shouldly;

namespace Archive.Evidence.Tests;

/// <summary>
/// Export set formats 1 and 2 (ADR 0012) as sets already written hold them: one line of each kind, as text. The export tool and
/// the verifier share these types, so a renamed property would pass every round trip between them while every set a
/// customer holds stopped reading; these lines are what catches it.
/// </summary>
public sealed class ExportSetFormatTests
{
    private const string Manifest =
        """{"format":1,"tenantId":"0199e9a0-0000-7000-8000-0000000000b1","legalEntityId":null,"startedAt":"2026-10-23T08:00:00+00:00","endedAt":"2026-10-23T08:05:00+00:00","counts":{"records":3,"committed":0,"sealed":2,"erased":1,"purged":0,"auditEntries":6,"anchors":1},"catalogueHead":5,"auditHead":6,"files":[{"path":"catalogue.jsonl","sha256":"00","size":10}],"failed":[{"recordId":"0199e9a0-0000-7000-8000-00000000e101","reason":"damaged"}]}""";

    private const string Catalogue =
        """{"recordId":"0199e9a0-0000-7000-8000-00000000e103","legalEntityId":"0199e9a0-0000-7000-8000-0000000000c1","type":"file","status":"erased","retentionClass":"DK-BOOKKEEPING","classSource":"submission","profile":"DK 2026.1","customProfile":null,"recordDate":"2026-10-01","recordDateSource":"submitter","committedAt":"2026-10-20T08:00:00+00:00","sealedAt":"2026-10-20T09:00:00+00:00","expiry":"2031-12-31","retainUntil":"2032-01-01T00:00:00+00:00","held":false,"erasedAt":"2026-10-22T08:00:00+00:00","erasureBasis":"erasure request","purgedAt":null}""";

    private const string CatalogueWithFields =
        """{"recordId":"0199e9a0-0000-7000-8000-00000000e101","legalEntityId":"0199e9a0-0000-7000-8000-0000000000c1","type":"file","status":"sealed","retentionClass":"DK-BOOKKEEPING","classSource":"submission","profile":"DK 2026.1","customProfile":null,"recordDate":"2026-10-01","recordDateSource":"submitter","committedAt":"2026-10-20T08:00:00+00:00","sealedAt":"2026-10-20T09:00:00+00:00","expiry":"2031-12-31","retainUntil":"2032-01-01T00:00:00+00:00","held":false,"erasedAt":null,"erasureBasis":null,"purgedAt":null,"fields":{"invoice-number":"2026-0042","supplier":"12345678"}}""";

    private const string Entry =
        """{"sequence":5,"at":"2026-10-20T12:00:00+00:00","actor":"subject-1","action":"EraseRecord","target":"record/0199e9a0-0000-7000-8000-00000000e103","outcome":"succeeded","correlationId":null,"contentHash":"aa","hash":"bb"}""";

    private const string Anchor =
        """{"anchorId":"0199e9a0-0000-7000-8000-00000000a001","stampedAt":"2026-10-21T00:00:00+00:00","root":"cc","treeSize":3,"leafIndex":1,"path":["dd","ee"],"tenantId":"0199e9a0-0000-7000-8000-0000000000b1","sequence":5,"headHash":"ff"}""";

    [Fact]
    public void TheManifest_ReadsAndWritesAsFormat1()
    {
        // Act
        ExportSetManifest manifest = RoundTrip<ExportSetManifest>(Manifest);

        // Assert
        (manifest.Format, manifest.CatalogueHead, manifest.AuditHead).ShouldBe((1, 5L, 6L));
        manifest.Counts.ShouldBe(new ExportSetCounts(3, 0, 2, 1, 0, 6, 1));
        manifest.Files.ShouldHaveSingleItem().ShouldBe(new ExportSetFile("catalogue.jsonl", "00", 10));
        manifest.Failed.ShouldHaveSingleItem().Reason.ShouldBe("damaged");
    }

    [Fact]
    public void ACatalogueLine_ReadsAndWritesAsFormat1()
    {
        // Act
        CatalogueLine line = RoundTrip<CatalogueLine>(Catalogue);

        // Assert
        (line.Status, line.Kept, line.RecordDate, line.ErasureBasis).ShouldBe(("erased", false, new DateOnly(2026, 10, 1), "erasure request"));
    }

    [Fact]
    public void ACatalogueLineWithFields_ReadsAndWritesAsFormat2()
    {
        // Act
        CatalogueLine line = RoundTrip<CatalogueLine>(CatalogueWithFields);

        // Assert
        line.Fields.ShouldNotBeNull().ShouldBe(new Dictionary<string, string> { ["invoice-number"] = "2026-0042", ["supplier"] = "12345678" });
    }

    [Fact]
    public void AnAuditEntryLine_ReadsAndWritesAsFormat1()
    {
        // Act
        AuditEntryLine line = RoundTrip<AuditEntryLine>(Entry);

        // Assert
        (line.Sequence, line.Action, line.Target, line.ContentHash, line.Hash).ShouldBe((5L, "EraseRecord", "record/0199e9a0-0000-7000-8000-00000000e103", "aa", "bb"));
    }

    [Fact]
    public void AnAnchorProof_ReadsAndWritesAsFormat1()
    {
        // Act
        AnchorProof proof = RoundTrip<AnchorProof>(Anchor);

        // Assert
        (proof.TreeSize, proof.LeafIndex, proof.Sequence, proof.HeadHash).ShouldBe((3L, 1L, 5L, "ff"));
        proof.Path.ShouldBe(["dd", "ee"]);
    }

    /// <summary>Reads <paramref name="json"/>, and holds the writer to the same text.</summary>
    private static T RoundTrip<T>(string json)
    {
        T value = JsonSerializer.Deserialize<T>(json, ExportSetFormat.Json)!;
        JsonSerializer.Serialize(value, ExportSetFormat.Json).ShouldBe(json);
        return value;
    }
}
