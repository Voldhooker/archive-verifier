using System.Text.Json;

using Archive.Evidence.ExportSet;
using Archive.Verifier;
using Shouldly;

namespace Archive.Evidence.Tests;

/// <summary>
/// The export set's checks (ADR 0012), on a set written from the format: whole, broken in each way a check guards
/// against, and unanchored. Each change is made on a copy, with the manifest rewritten to fit it unless the manifest's
/// own hashes are what should catch it, so the check named is the one that does.
/// </summary>
public sealed class ExportSetVerifierTests : IDisposable
{
    private readonly TestEvidence _evidence = new();
    private readonly List<DirectoryInfo> _folders = [];
    private readonly string _set;

    public ExportSetVerifierTests()
    {
        _set = Folder();
        TestExportSet.Write(_evidence, _set);
    }

    public void Dispose()
    {
        foreach (DirectoryInfo folder in _folders)
        {
            folder.Delete(recursive: true);
        }

        _evidence.Dispose();
    }

    [Fact]
    public void AWholeSet_IsValid_AndNamesTheNewestAnchoredEntry()
    {
        // Act: also with a trailing separator, as a shell completes a folder's name.
        ExportSetVerification result = Verify(_set);
        ExportSetVerification slashed = Verify(_set + Path.DirectorySeparatorChar);

        // Assert
        result.Outcome.ShouldBe(ExportSetVerification.Valid, Describe(result));
        result.Checks.Select(c => c.Name).ShouldBe(
        [
            ExportSetVerifier.ManifestCheck, ExportSetVerifier.FilesCheck, ExportSetVerifier.FetchedCheck, ExportSetVerifier.CatalogueCheck,
            ExportSetVerifier.PackagesCheck, ExportSetVerifier.AnchorsCheck, ExportSetVerifier.AuditCheck, ExportSetVerifier.ReconcileCheck,
            ExportSetVerifier.CountsCheck,
        ]);
        (result.Records, result.Unsealed, result.AuditEntries, result.Anchors).ShouldBe((3, 0, 6, 1));
        result.AnchoredTo.ShouldBe(TestExportSet.AnchoredHead);
        slashed.Outcome.ShouldBe(ExportSetVerification.Valid, Describe(slashed));
    }

    [Theory]
    [InlineData("a manifest of another format", new[] { ExportSetVerifier.ManifestCheck })]
    [InlineData("a catalogue head after the audit head", new[] { ExportSetVerifier.ManifestCheck })]
    [InlineData("a file the manifest doesn't name", new[] { ExportSetVerifier.FilesCheck })]
    [InlineData("a package changed, the manifest not", new[] { ExportSetVerifier.FilesCheck, ExportSetVerifier.PackagesCheck })]
    [InlineData("a link in the set", new[] { ExportSetVerifier.FilesCheck })]
    [InlineData("a package that couldn't be fetched", new[] { ExportSetVerifier.FetchedCheck })]
    [InlineData("a record twice in the catalogue", new[] { ExportSetVerifier.CatalogueCheck })]
    [InlineData("a damaged package", new[] { ExportSetVerifier.PackagesCheck })]
    [InlineData("another record's package under this id", new[] { ExportSetVerifier.PackagesCheck })]
    [InlineData("a package for an erased record", new[] { ExportSetVerifier.PackagesCheck })]
    [InlineData("an anchor's proof moved to another entry", new[] { ExportSetVerifier.AnchorsCheck })]
    [InlineData("an anchor for another tenant", new[] { ExportSetVerifier.AnchorsCheck })]
    [InlineData("an anchor stamped by an untrusted provider", new[] { ExportSetVerifier.AnchorsCheck })]
    [InlineData("an anchor whose token covers another root", new[] { ExportSetVerifier.AnchorsCheck })]
    [InlineData("an entry's field changed", new[] { ExportSetVerifier.AuditCheck })]
    [InlineData("the log rewritten with every hash recomputed", new[] { ExportSetVerifier.AuditCheck })]
    [InlineData("a log ending before the audit head", new[] { ExportSetVerifier.AuditCheck })]
    [InlineData("a record taken out", new[] { ExportSetVerifier.ReconcileCheck })]
    [InlineData("a kept record's package missing", new[] { ExportSetVerifier.ReconcileCheck })]
    [InlineData("a record erased in the catalogue only", new[] { ExportSetVerifier.ReconcileCheck })]
    [InlineData("a record the log never committed", new[] { ExportSetVerifier.ReconcileCheck })]
    [InlineData("counts that differ", new[] { ExportSetVerifier.CountsCheck })]
    public void AChange_FailsTheCheckThatGuardsAgainstIt(string change, string[] failed)
    {
        // Act
        ExportSetVerification result = Verify(Tampered(change));

        // Assert
        result.Outcome.ShouldBe(ExportSetVerification.Invalid);
        result.Checks.Where(c => !c.Passed).Select(c => c.Name).ShouldBe(failed, Describe(result));
    }

    [Fact]
    public void ASet_WithoutItsAnchors_IsNotYetProven()
    {
        // Act: the anchors removed and the manifest fitted, as someone who rewrote the log would.
        ExportSetVerification result = Verify(Unanchored());

        // Assert
        result.Outcome.ShouldBe(ExportSetVerification.NotYetProven, Describe(result));
        result.AnchoredTo.ShouldBeNull();
    }

    [Fact]
    public void TheSetCommand_ExitsWithTheOutcome()
    {
        // Arrange
        string trust = Path.Combine(Folder(), "ca.pem");
        File.WriteAllText(trust, _evidence.Root.ExportCertificatePem());
        string invalid = Tampered("a damaged package");
        string unproven = Unanchored();
        using StringWriter output = new();

        // Act
        int valid = SetCommand.Run([_set, "--trust", trust], output, TextWriter.Null);
        int[] others =
        [
            SetCommand.Run([invalid, "--trust", trust], TextWriter.Null, TextWriter.Null),
            SetCommand.Run([unproven, "--trust", trust], TextWriter.Null, TextWriter.Null),
            SetCommand.Run([_set], TextWriter.Null, TextWriter.Null),
        ];

        // Assert
        valid.ShouldBe(VerifyCommand.Valid, output.ToString());
        output.ToString().ShouldContain("VALID: 3 records");
        others.ShouldBe([VerifyCommand.Invalid, VerifyCommand.Unsealed, VerifyCommand.Usage]);
    }

    /// <summary>A record taken out of the set: its catalogue line and its package.</summary>
    private static void Drop(string folder, Guid recordId)
    {
        DropLine(folder, recordId);
        File.Delete(Path.Combine(folder, ExportSetFormat.PackagePath(recordId)));
    }

    private static void DropLine(string folder, Guid recordId) =>
        Rewrite(folder, ExportSetFormat.Catalogue, t => string.Concat(t.Split('\n').Where(l => l.Length > 0 && !l.Contains(recordId.ToString(), StringComparison.Ordinal)).Select(l => l + "\n")));

    private static void AddLine(string folder, CatalogueLine line) =>
        File.AppendAllText(Path.Combine(folder, ExportSetFormat.Catalogue), JsonSerializer.Serialize(line, ExportSetFormat.Json) + "\n");

    private static CatalogueLine Line(string folder, Guid recordId) =>
        File.ReadLines(Path.Combine(folder, ExportSetFormat.Catalogue)).Select(l => JsonSerializer.Deserialize<CatalogueLine>(l, ExportSetFormat.Json)!).Single(l => l.RecordId == recordId);

    private static string AnchorFile(string folder) => Directory.GetFiles(Path.Combine(folder, ExportSetFormat.AnchorsFolder), "*.json").Single();

    private static AnchorProof Proof(string folder) => JsonSerializer.Deserialize<AnchorProof>(File.ReadAllBytes(AnchorFile(folder)), ExportSetFormat.Json)!;

    private static void Rewrite(string folder, string path, Func<string, string> change)
    {
        string file = Path.Combine(folder, path);
        File.WriteAllText(file, change(File.ReadAllText(file)));
    }

    private static void FlipLastByte(string file)
    {
        byte[] bytes = File.ReadAllBytes(file);
        bytes[^1] ^= 0xff;
        File.WriteAllBytes(file, bytes);
    }

    private static string Describe(ExportSetVerification result) =>
        string.Join("; ", result.Checks.Select(c => $"{c.Name} {(c.Passed ? "ok" : "FAILED")}: {c.Detail}"));

    private ExportSetVerification Verify(string folder) => ExportSetVerifier.Verify(folder, _evidence.Trust);

    /// <summary>A copy of the set, changed as <paramref name="change"/> names.</summary>
    private string Tampered(string change)
    {
        string first = ExportSetFormat.PackagePath(TestExportSet.First);
        return change switch
        {
            "a manifest of another format" => Copy(s => Rewrite(s, ExportSetFormat.Manifest, t => t.Replace("\"format\":1", "\"format\":2", StringComparison.Ordinal)), refit: false),
            "a catalogue head after the audit head" => Copy(_ => { }, m => m with { CatalogueHead = m.AuditHead + 1 }),
            "a file the manifest doesn't name" => Copy(s => File.WriteAllText(Path.Combine(s, "records", "extra.txt"), "x"), refit: false),
            "a package changed, the manifest not" => Copy(s => FlipLastByte(Path.Combine(s, first)), refit: false),
            "a link in the set" => Copy(s => File.CreateSymbolicLink(Path.Combine(s, "records", "link.zip"), Path.Combine(s, first)), refit: false),
            "a package that couldn't be fetched" => Copy(_ => { }, m => m with { Failed = [new ExportSetFailure(TestExportSet.First, "the archive refused it as damaged")] }),
            "a record twice in the catalogue" => Copy(s => Rewrite(s, ExportSetFormat.Catalogue, t => t + t.Split('\n')[0] + "\n")),
            "a damaged package" => Copy(s => FlipLastByte(Path.Combine(s, first))),
            "another record's package under this id" => Copy(s => File.Copy(Path.Combine(s, ExportSetFormat.PackagePath(TestExportSet.Second)), Path.Combine(s, first), overwrite: true)),
            "a package for an erased record" => Copy(s => File.WriteAllBytes(Path.Combine(s, ExportSetFormat.PackagePath(TestExportSet.Erased)), _evidence.Package(recordId: TestExportSet.Erased))),
            "an anchor's proof moved to another entry" => Copy(s => TestExportSet.WriteProof(s, Proof(s) with { Sequence = TestExportSet.AnchoredHead - 1 })),

            // Another tenant's own leaf, with a true proof to the same root: only the tenant tells it apart.
            "an anchor for another tenant" => Copy(s => TestExportSet.WriteProof(s, TestExportSet.ProofOf(Convert.FromHexString(Proof(s).HeadHash), 0))),
            "an anchor stamped by an untrusted provider" => Copy(StampedByAnother),
            "an anchor whose token covers another root" => Copy(s => File.WriteAllBytes(Path.ChangeExtension(AnchorFile(s), ".tsr"), TestEvidence.Token(new byte[32], _evidence.Signer))),
            "an entry's field changed" => Copy(s => Rewrite(s, ExportSetFormat.AuditEntries, t => t.Replace("\"outcome\":\"refused:429\"", "\"outcome\":\"succeeded\"", StringComparison.Ordinal))),

            // Entry 4 changed and every hash after it recomputed: the chain holds, and only the anchor at 5 shows it.
            "the log rewritten with every hash recomputed" => Copy(s => TestExportSet.WriteLog(s, TestExportSet.ReadLog(s).Select(e => e.Sequence == 4 ? e with { Outcome = "succeeded" } : e))),
            "a log ending before the audit head" => Copy(_ => { }, m => m with { AuditHead = m.AuditHead + 1 }),
            "a record taken out" => Copy(s => Drop(s, TestExportSet.Second), m => m with { Counts = m.Counts with { Records = 2, Sealed = 1 } }),
            "a kept record's package missing" => Copy(s => File.Delete(Path.Combine(s, first))),
            "a record erased in the catalogue only" => Copy(
                s =>
                {
                    CatalogueLine line = Line(s, TestExportSet.Second);
                    Drop(s, TestExportSet.Second);
                    AddLine(s, line with { Status = "erased", ErasedAt = line.CommittedAt.AddDays(1), ErasureBasis = "retention ended" });
                },
                m => m with { Counts = m.Counts with { Sealed = 1, Erased = 2 } }),
            "a record the log never committed" => Copy(
                s => AddLine(s, Line(s, TestExportSet.Erased) with { RecordId = Guid.Parse("0199e9a0-0000-7000-8000-00000000e1ff") }),
                m => m with { Counts = m.Counts with { Records = 4, Erased = 2 } }),
            "counts that differ" => Copy(_ => { }, m => m with { Counts = m.Counts with { AuditEntries = 5 } }),
            _ => throw new ArgumentOutOfRangeException(nameof(change), change, "No such change."),
        };
    }

    private void StampedByAnother(string folder)
    {
        using TestEvidence another = new();
        File.WriteAllBytes(Path.ChangeExtension(AnchorFile(folder), ".tsr"), TestEvidence.Token(Convert.FromHexString(Proof(folder).Root), another.Signer));
    }

    private string Unanchored() =>
        Copy(s => Directory.Delete(Path.Combine(s, ExportSetFormat.AnchorsFolder), recursive: true), m => m with { Counts = m.Counts with { Anchors = 0 } });

    /// <summary>
    /// A copy of the set, changed. Unless <paramref name="refit"/> is false, its manifest is then rewritten to name every
    /// file as it now is, after <paramref name="fit"/> changes the rest of it.
    /// </summary>
    private string Copy(Action<string> change, Func<ExportSetManifest, ExportSetManifest>? fit = null, bool refit = true)
    {
        string copy = Folder();
        foreach (string file in Directory.GetFiles(_set, "*", SearchOption.AllDirectories))
        {
            string target = Path.Combine(copy, Path.GetRelativePath(_set, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target);
        }

        change(copy);
        if (refit)
        {
            ExportSetManifest manifest = TestExportSet.Manifest(copy);
            TestExportSet.WriteManifest(copy, fit?.Invoke(manifest) ?? manifest);
        }

        return copy;
    }

    private string Folder()
    {
        DirectoryInfo folder = Directory.CreateTempSubdirectory("archive-set-");
        _folders.Add(folder);
        return folder.FullName;
    }
}
