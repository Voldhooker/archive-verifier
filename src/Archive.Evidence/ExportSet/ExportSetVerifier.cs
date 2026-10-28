using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

using Archive.Evidence.Audit;
using Archive.Evidence.Export;
using Archive.Evidence.Sealing;

namespace Archive.Evidence.ExportSet;

/// <summary>
/// Checks an export set offline (ADR 0012): that it is whole, that every record's package verifies, that the audit
/// log is intact and agrees with every anchor, and that the catalogue and the log tell the same story. One entry and one
/// package at a time, so a set of millions of records is never held in memory.
/// </summary>
public static class ExportSetVerifier
{
    public const string ManifestCheck = "manifest";
    public const string FilesCheck = "files";
    public const string FetchedCheck = "fetched";
    public const string CatalogueCheck = "catalogue";
    public const string PackagesCheck = "packages";
    public const string AnchorsCheck = "anchors";
    public const string AuditCheck = "audit";
    public const string ReconcileCheck = "reconcile";
    public const string CountsCheck = "counts";

    private const int Named = 5;

    public static ExportSetVerification Verify(string folder, X509Certificate2Collection trustAnchors)
    {
        ArgumentNullException.ThrowIfNull(folder);
        ArgumentNullException.ThrowIfNull(trustAnchors);
        List<SetCheck> checks = [];
        ExportSetManifest? manifest = ReadManifest(folder, checks);
        if (manifest is null || !CheckFiles(folder, manifest, checks))
        {
            // Without a manifest there is nothing to hold the set to; with a link or a device in it, reading on isn't safe.
            return new ExportSetVerification(ExportSetVerification.Invalid, checks, 0, 0, 0, 0, null, null);
        }

        checks.Add(manifest.Failed.Count == 0
            ? new SetCheck(FetchedCheck, true, "every kept record's package was fetched")
            : new SetCheck(FetchedCheck, false, $"{manifest.Failed.Count} packages couldn't be fetched: {Listed(manifest.Failed.Select(f => $"{f.RecordId} ({f.Reason})"))}"));

        Dictionary<Guid, CatalogueLine> catalogue = ReadCatalogue(folder, checks);
        (HashSet<Guid> packaged, long unsealed) = CheckPackages(folder, catalogue, trustAnchors, checks);
        AuditLogChain chain = new();
        Anchoring anchoring = CheckAnchors(folder, manifest.TenantId, manifest.AuditHead, chain, trustAnchors, checks);
        AuditFacts log = CheckAudit(folder, manifest, chain, checks);
        Reconcile(manifest, catalogue, packaged, log, checks);
        CheckCounts(manifest, catalogue, log.Entries, anchoring.Files, checks);

        bool proven = unsealed == 0 && (log.Entries == 0 || anchoring.Count > 0);
        string outcome = !checks.TrueForAll(c => c.Passed) ? ExportSetVerification.Invalid
            : proven ? ExportSetVerification.Valid
            : ExportSetVerification.NotYetProven;
        return new ExportSetVerification(outcome, checks, catalogue.Count, unsealed, log.Entries, anchoring.Count, anchoring.NewestSequence, anchoring.NewestAt);
    }

    private static ExportSetManifest? ReadManifest(string folder, List<SetCheck> checks)
    {
        string path = Path.Combine(folder, ExportSetFormat.Manifest);
        if (!File.Exists(path))
        {
            checks.Add(new SetCheck(ManifestCheck, false, $"{ExportSetFormat.Manifest} is missing: the set is unfinished, or not a set"));
            return null;
        }

        try
        {
            ExportSetManifest? manifest = JsonSerializer.Deserialize<ExportSetManifest>(File.ReadAllBytes(path), ExportSetFormat.Json);
            if (manifest is null || manifest.Format != ExportSetFormat.Current || manifest.Counts is null
                || manifest.Files is null || manifest.Files.Any(f => f?.Path is null || f.Sha256 is null)
                || manifest.Failed is null || manifest.Failed.Any(f => f?.Reason is null)
                || manifest.CatalogueHead < 0 || manifest.CatalogueHead > manifest.AuditHead)
            {
                checks.Add(new SetCheck(ManifestCheck, false, $"{ExportSetFormat.Manifest} is not export set format {ExportSetFormat.Current}"));
                return null;
            }

            checks.Add(new SetCheck(ManifestCheck, true, string.Create(
                CultureInfo.InvariantCulture, $"format {manifest.Format}, tenant {manifest.TenantId}, exported {manifest.StartedAt:O} to {manifest.EndedAt:O}")));
            return manifest;
        }
        catch (JsonException exception)
        {
            checks.Add(new SetCheck(ManifestCheck, false, $"{ExportSetFormat.Manifest} can't be read: {exception.Message}"));
            return null;
        }
    }

    /// <summary>Every file the manifest names is there with its size and hash, and no other file is.</summary>
    /// <returns>False when the folder holds a link or anything but files and folders: the set isn't read further.</returns>
    private static bool CheckFiles(string folder, ExportSetManifest manifest, List<SetCheck> checks)
    {
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder));
        List<string> problems = [];
        HashSet<string> present = [];
        foreach (FileSystemInfo entry in Entries(root))
        {
            string relative = Path.GetRelativePath(root, entry.FullName).Replace('\\', '/');
            if (entry.LinkTarget is not null || (entry is FileInfo && (entry.Attributes & (FileAttributes.Device | FileAttributes.ReparsePoint)) != 0))
            {
                problems.Add($"{relative} is a link or a device");
            }
            else if (entry is FileInfo && relative != ExportSetFormat.Manifest)
            {
                present.Add(relative);
            }
        }

        if (problems.Count > 0)
        {
            checks.Add(new SetCheck(FilesCheck, false, $"{problems.Count} entries aren't plain files: {Listed(problems)}"));
            return false;
        }

        foreach (ExportSetFile file in manifest.Files)
        {
            string full = Path.GetFullPath(Path.Combine(root, file.Path));
            if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal) || !present.Remove(file.Path))
            {
                problems.Add($"{file.Path} missing");
                continue;
            }

            using FileStream stream = File.OpenRead(full);
            if (stream.Length != file.Size || !string.Equals(Convert.ToHexStringLower(SHA256.HashData(stream)), file.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                problems.Add($"{file.Path} changed");
            }
        }

        problems.AddRange(present.Order(StringComparer.Ordinal).Select(f => $"{f} not in the manifest"));
        checks.Add(problems.Count == 0
            ? new SetCheck(FilesCheck, true, $"{manifest.Files.Count} files, each with the size and hash the manifest names, and nothing else")
            : new SetCheck(FilesCheck, false, $"{problems.Count} files differ from the manifest: {Listed(problems)}"));
        return true;
    }

    /// <summary>Every file and folder under the root, never following a link.</summary>
    private static IEnumerable<FileSystemInfo> Entries(string root)
    {
        Stack<DirectoryInfo> folders = new([new DirectoryInfo(root)]);
        while (folders.TryPop(out DirectoryInfo? folder))
        {
            foreach (FileSystemInfo entry in folder.EnumerateFileSystemInfos("*", new EnumerationOptions { AttributesToSkip = 0, RecurseSubdirectories = false }))
            {
                yield return entry;
                if (entry is DirectoryInfo inner && entry.LinkTarget is null)
                {
                    folders.Push(inner);
                }
            }
        }
    }

    private static Dictionary<Guid, CatalogueLine> ReadCatalogue(string folder, List<SetCheck> checks)
    {
        Dictionary<Guid, CatalogueLine> lines = [];
        string path = Path.Combine(folder, ExportSetFormat.Catalogue);
        if (!File.Exists(path))
        {
            checks.Add(new SetCheck(CatalogueCheck, false, $"{ExportSetFormat.Catalogue} is missing"));
            return lines;
        }

        int number = 0;
        foreach (string text in File.ReadLines(path))
        {
            number++;
            CatalogueLine? line;
            try
            {
                line = JsonSerializer.Deserialize<CatalogueLine>(text, ExportSetFormat.Json);
            }
            catch (JsonException)
            {
                line = null;
            }

            if (line is null || !lines.TryAdd(line.RecordId, line))
            {
                checks.Add(new SetCheck(CatalogueCheck, false, string.Create(CultureInfo.InvariantCulture, $"line {number} can't be read, or names a record twice")));
                return lines;
            }
        }

        checks.Add(new SetCheck(CatalogueCheck, true, string.Create(
            CultureInfo.InvariantCulture, $"{lines.Count} records: {lines.Values.Count(l => l.Kept)} kept, {lines.Values.Count(l => !l.Kept)} erased or purged")));
        return lines;
    }

    /// <returns>The records packaged, and how many packages are whole but unsealed.</returns>
    private static (HashSet<Guid> Packaged, long Unsealed) CheckPackages(string folder, Dictionary<Guid, CatalogueLine> catalogue, X509Certificate2Collection trust, List<SetCheck> checks)
    {
        string records = Path.Combine(folder, ExportSetFormat.RecordsFolder);
        HashSet<Guid> packaged = [];
        List<string> problems = [];
        long unsealed = 0;
        foreach (string file in Directory.Exists(records) ? Directory.EnumerateFiles(records, "*.zip").Order(StringComparer.Ordinal) : Enumerable.Empty<string>())
        {
            if (!Guid.TryParse(Path.GetFileNameWithoutExtension(file), out Guid id))
            {
                problems.Add($"{Path.GetFileName(file)} is not named by a record id");
                continue;
            }

            packaged.Add(id);
            ExportVerification result;
            using (FileStream stream = File.OpenRead(file))
            {
                result = ExportVerifier.Verify(stream, trust);
            }

            if (result.Outcome == ExportVerification.Invalid)
            {
                problems.Add($"{id}: {result.FailedCheck}, {result.Reason}");
            }
            else if (result.RecordId != id)
            {
                problems.Add($"{id}: the package is record {result.RecordId}'s");
            }
            else if (!catalogue.TryGetValue(id, out CatalogueLine? line) || !line.Kept)
            {
                problems.Add($"{id}: the catalogue names no kept record by that id");
            }
            else if (result.Outcome == ExportVerification.Unsealed)
            {
                unsealed++;
            }
        }

        checks.Add(problems.Count == 0
            ? new SetCheck(PackagesCheck, true, string.Create(
                CultureInfo.InvariantCulture, $"{packaged.Count} packages pass the record checks ({packaged.Count - unsealed} sealed, {unsealed} not yet)"))
            : new SetCheck(PackagesCheck, false, $"{problems.Count} packages fail: {Listed(problems)}"));
        return (packaged, unsealed);
    }

    /// <summary>Each anchor's leaf is the tenant's head, its proof leads to the root, and a trusted token covers the root.</summary>
    /// <returns>The anchors that check out, each holding the chain to its head, and the newest of them.</returns>
    private static Anchoring CheckAnchors(string folder, Guid tenantId, long auditHead, AuditLogChain chain, X509Certificate2Collection trust, List<SetCheck> checks)
    {
        string anchors = Path.Combine(folder, ExportSetFormat.AnchorsFolder);
        List<string> problems = [];
        Anchoring found = new(0, 0, null, null);
        foreach (string file in Directory.Exists(anchors) ? Directory.EnumerateFiles(anchors, "*.json").Order(StringComparer.Ordinal) : Enumerable.Empty<string>())
        {
            found = found with { Files = found.Files + 1 };
            string? problem = CheckAnchor(file, tenantId, auditHead, chain, trust, out long sequence, out DateTimeOffset stampedAt);
            if (problem is not null)
            {
                problems.Add($"{Path.GetFileNameWithoutExtension(file)}: {problem}");
            }
            else
            {
                found = sequence >= found.NewestSequence.GetValueOrDefault(-1)
                    ? new Anchoring(found.Files, found.Count + 1, sequence, stampedAt)
                    : found with { Count = found.Count + 1 };
            }
        }

        checks.Add(
            problems.Count > 0 ? new SetCheck(AnchorsCheck, false, $"{problems.Count} anchors fail: {Listed(problems)}")
            : found.Count == 0 ? new SetCheck(AnchorsCheck, true, "no daily anchor holds the log yet: it rests on its own chain, which anyone can recompute")
            : new SetCheck(AnchorsCheck, true, string.Create(
                CultureInfo.InvariantCulture,
                $"{found.Count} daily anchors: each proof leads to its root, and each root is covered by a trusted timestamp; the newest holds the log to entry {found.NewestSequence} at {found.NewestAt:O}")));
        return found;
    }

    private static string? CheckAnchor(
        string file, Guid tenantId, long auditHead, AuditLogChain chain, X509Certificate2Collection trust, out long sequence, out DateTimeOffset stampedAt)
    {
        sequence = 0;
        stampedAt = default;
        AnchorProof? proof;
        try
        {
            proof = JsonSerializer.Deserialize<AnchorProof>(File.ReadAllBytes(file), ExportSetFormat.Json);
        }
        catch (JsonException)
        {
            proof = null;
        }

        if (proof is null || proof.Path is null)
        {
            return "can't be read";
        }

        if (proof.TenantId != tenantId || proof.Sequence > auditHead)
        {
            return "names another tenant, or an entry beyond the log";
        }

        string token = Path.ChangeExtension(file, ".tsr");
        try
        {
            byte[] head = Convert.FromHexString(proof.HeadHash);
            byte[] root = Convert.FromHexString(proof.Root);
            InclusionProof path = new(proof.LeafIndex, proof.TreeSize, [.. proof.Path.Select(Convert.FromHexString)]);
            if (!MerkleTree.Verify(AnchorLeaf.Of(proof.TenantId, proof.Sequence, head), path, root))
            {
                return "the proof doesn't lead from the tenant's head to the root";
            }

            byte[] stamp = File.Exists(token) ? File.ReadAllBytes(token) : [];
            if (!TimestampTokenCheck.Covers(stamp, root, out stampedAt, out X509Certificate2? signer) || signer is null)
            {
                return "the timestamp token doesn't cover the root, or its signature doesn't check";
            }

            if (!TimestampTokenCheck.Trusts(signer, trust, TimestampTokenCheck.CertificatesIn(stamp), stampedAt))
            {
                return $"the token's signer, {signer.Subject}, doesn't chain to a trusted provider";
            }

            chain.Anchored(proof.Sequence, head);
            sequence = proof.Sequence;
            return null;
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        {
            return "a hash isn't 32 bytes of hex";
        }
    }

    /// <summary>The log rebuilt from the first entry, held to every anchor, up to the head the manifest names.</summary>
    private static AuditFacts CheckAudit(string folder, ExportSetManifest manifest, AuditLogChain chain, List<SetCheck> checks)
    {
        Dictionary<Guid, long> committed = [];
        HashSet<Guid> erased = [];
        string path = Path.Combine(folder, ExportSetFormat.AuditEntries);
        if (!File.Exists(path))
        {
            checks.Add(new SetCheck(AuditCheck, false, $"{ExportSetFormat.AuditEntries} is missing"));
            return new AuditFacts(committed, erased, 0);
        }

        // Read to the end even past a break: the entries are still counted, and the catalogue still held to them.
        long? unreadable = null;
        long number = 0;
        foreach (string text in File.ReadLines(path))
        {
            number++;
            AuditEntryLine? line;
            AuditRecord? record;
            try
            {
                line = JsonSerializer.Deserialize<AuditEntryLine>(text, ExportSetFormat.Json);
                record = line?.ToRecord(manifest.TenantId);
            }
            catch (Exception exception) when (exception is JsonException or FormatException)
            {
                line = null;
                record = null;
            }

            if (line is null || record is null)
            {
                unreadable ??= number;
                continue;
            }

            chain.Add(record);
            if (line.Outcome == "succeeded" && Targeted(line.Target) is { } recordId)
            {
                if (line.Action == "CommitRecord")
                {
                    committed.TryAdd(recordId, line.Sequence);
                }
                else if (line.Action == "EraseRecord")
                {
                    erased.Add(recordId);
                }
            }
        }

        // A break while reading is a changed or missing entry; one found only now, an anchored head beyond the log.
        long? brokenOnEntry = chain.BrokenAt;
        chain.Complete();
        checks.Add(
            unreadable is { } bad ? new SetCheck(AuditCheck, false, string.Create(CultureInfo.InvariantCulture, $"line {bad} of the log can't be read"))
            : brokenOnEntry is { } broken ? new SetCheck(AuditCheck, false, string.Create(CultureInfo.InvariantCulture, $"the chain breaks at entry {broken}"))
            : !chain.Intact ? new SetCheck(AuditCheck, false, string.Create(CultureInfo.InvariantCulture, $"an anchored head beyond the log, at entry {chain.BrokenAt}: entries were removed"))
            : chain.HeadSequence.GetValueOrDefault() != manifest.AuditHead
                ? new SetCheck(AuditCheck, false, string.Create(CultureInfo.InvariantCulture, $"the log ends at entry {chain.HeadSequence.GetValueOrDefault()}, not at {manifest.AuditHead} as the manifest says"))
            : new SetCheck(AuditCheck, true, string.Create(CultureInfo.InvariantCulture, $"{chain.Entries} entries chain from the first, held to {chain.AnchorsChecked} anchored heads")));
        return new AuditFacts(committed, erased, chain.Entries);
    }

    /// <summary>
    /// The catalogue and the log tell one story: every record in it was committed in the log, and every erased one, or
    /// kept one whose package is missing because it was erased during the export, erased there. In a set of the whole
    /// tenant, every record the log committed before the catalogue was read is in the catalogue.
    /// </summary>
    private static void Reconcile(
        ExportSetManifest manifest, Dictionary<Guid, CatalogueLine> catalogue, HashSet<Guid> packaged, AuditFacts log, List<SetCheck> checks)
    {
        List<string> problems = [];
        foreach (CatalogueLine line in catalogue.Values.OrderBy(l => l.RecordId))
        {
            if (!log.Committed.ContainsKey(line.RecordId))
            {
                problems.Add($"{line.RecordId}: no CommitRecord in the log");
            }
            else if (!line.Kept && !log.Erased.Contains(line.RecordId))
            {
                problems.Add($"{line.RecordId}: {line.Status}, but no EraseRecord in the log");
            }
            else if (line.Kept && !packaged.Contains(line.RecordId) && !log.Erased.Contains(line.RecordId))
            {
                problems.Add($"{line.RecordId}: kept, but no package and no EraseRecord in the log");
            }
        }

        if (manifest.LegalEntityId is null)
        {
            problems.AddRange(log.Committed
                .Where(c => c.Value <= manifest.CatalogueHead && !catalogue.ContainsKey(c.Key))
                .OrderBy(c => c.Value)
                .Select(c => string.Create(CultureInfo.InvariantCulture, $"{c.Key}: committed at entry {c.Value}, but not in the catalogue")));
        }

        string scope = manifest.LegalEntityId is null
            ? string.Create(CultureInfo.InvariantCulture, $", and every record the log committed up to entry {manifest.CatalogueHead} is in the catalogue")
            : "; one legal entity's set, so records the log committed for others aren't looked for";
        checks.Add(problems.Count == 0
            ? new SetCheck(ReconcileCheck, true, $"every record in the catalogue was committed in the log, and every erased one erased there{scope}")
            : new SetCheck(ReconcileCheck, false, $"{problems.Count} records don't reconcile with the log: {Listed(problems)}"));
    }

    /// <summary>The counts the manifest gives are the ones the set holds.</summary>
    private static void CheckCounts(ExportSetManifest manifest, Dictionary<Guid, CatalogueLine> catalogue, long entries, int anchors, List<SetCheck> checks)
    {
        ExportSetCounts found = new(
            catalogue.Count,
            catalogue.Values.Count(l => l.Status == "committed"),
            catalogue.Values.Count(l => l.Status == "sealed"),
            catalogue.Values.Count(l => l.Status == "erased"),
            catalogue.Values.Count(l => l.Status == "purged"),
            entries,
            anchors);
        checks.Add(found == manifest.Counts
            ? new SetCheck(CountsCheck, true, "the manifest's counts are the set's")
            : new SetCheck(CountsCheck, false, $"the manifest counts {manifest.Counts}, the set holds {found}"));
    }

    private static Guid? Targeted(string? target) =>
        target is not null && target.StartsWith("record/", StringComparison.Ordinal) && Guid.TryParse(target.AsSpan(7), out Guid id) ? id : null;

    private static string Listed(IEnumerable<string> items)
    {
        List<string> all = [.. items];
        return string.Join("; ", all.Take(Named)) + (all.Count > Named ? string.Create(CultureInfo.InvariantCulture, $"; and {all.Count - Named} more") : string.Empty);
    }

    /// <param name="Files">How many anchor files the set holds, good or not.</param>
    /// <param name="Count">How many of them check out.</param>
    private sealed record Anchoring(int Files, int Count, long? NewestSequence, DateTimeOffset? NewestAt);

    /// <param name="Committed">Each record the log committed, with the entry that did.</param>
    private sealed record AuditFacts(Dictionary<Guid, long> Committed, HashSet<Guid> Erased, long Entries);
}
