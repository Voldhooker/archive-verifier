using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Archive.Evidence.ExportSet;

using static Archive.Verifier.ApiPages;

namespace Archive.Verifier;

/// <summary>
/// Pulls a tenant's export set (ADR 0012) into a folder through the archive's API: the catalogue first, then every kept
/// record's package, then the audit log up to the head it reads first, its anchors, and the profile versions. Resumable:
/// each file is whole once it is there, the .jsonl files continue from their last line, and the manifest, written last,
/// marks the set finished. The catalogue comes before the audit log, so every record it names was committed in the log
/// the set holds.
/// </summary>
public sealed class SetExporter(ArchiveApi api, TextWriter log, TimeProvider time)
{
    /// <summary>The run's own facts, kept while it runs and removed before the manifest is written.</summary>
    public const string StateFile = ".export-state.json";

    public const string Warning =
        "This set will hold every record of the tenant with its data key, so whoever holds the set can read every record. "
        + "Keep it as you keep the archive itself: encrypted at rest, and only where its readers may read the records.";

    /// <returns>The records whose package couldn't be fetched; the set is finished either way, and names them.</returns>
    public async Task<IReadOnlyList<ExportSetFailure>> ExportAsync(string folder, Guid? legalEntityId, CancellationToken cancellation)
    {
        ArgumentNullException.ThrowIfNull(folder);
        if (File.Exists(Path.Combine(folder, ExportSetFormat.Manifest)))
        {
            File.Delete(Path.Combine(folder, StateFile));
            throw new InvalidOperationException($"{folder} holds a finished set already: export into a new folder.");
        }

        Directory.CreateDirectory(Path.Combine(folder, ExportSetFormat.RecordsFolder));
        Directory.CreateDirectory(Path.Combine(folder, ExportSetFormat.AnchorsFolder));
        ExportState state = await StateAsync(folder, legalEntityId, cancellation);

        state = await CatalogueAsync(folder, state, cancellation);
        List<ExportSetFailure> failed = await PackagesAsync(folder, cancellation);
        state = await HeadAsync(folder, state, cancellation);
        await AuditAsync(folder, state, cancellation);
        int anchors = await AnchorsAsync(folder, state, cancellation);
        await ProfilesAsync(folder, cancellation);
        await File.WriteAllTextAsync(Path.Combine(folder, ExportSetFormat.Readme), Readme(state), cancellation);
        await ManifestAsync(folder, state, failed, anchors, cancellation);
        return failed;
    }

    private static IEnumerable<T> ReadLines<T>(string path)
    {
        if (!File.Exists(path))
        {
            yield break;
        }

        foreach (string line in File.ReadLines(path))
        {
            yield return JsonSerializer.Deserialize<T>(line, ExportSetFormat.Json)!;
        }
    }

    /// <summary>Drops a last line a crash cut short, so a resumed run appends to whole lines only.</summary>
    private static void TrimToWholeLines(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        byte[] bytes = File.ReadAllBytes(path);
        int end = Array.LastIndexOf(bytes, (byte)'\n') + 1;
        if (end < bytes.Length)
        {
            using FileStream stream = new(path, FileMode.Open, FileAccess.Write);
            stream.SetLength(end);
        }
    }

    private static async Task AppendAsync<T>(string path, IEnumerable<T> lines, CancellationToken cancellation)
    {
        StringBuilder text = new();
        foreach (T line in lines)
        {
            text.Append(JsonSerializer.Serialize(line, ExportSetFormat.Json)).Append('\n');
        }

        await File.AppendAllTextAsync(path, text.ToString(), cancellation);
    }

    /// <summary>
    /// A name from the archive used as a path segment: letters, digits, dots, hyphens and underscores only, never only
    /// dots, and a changed name keeps a hash of the original so two names never meet in one file.
    /// </summary>
    private static string Safe(string name)
    {
        string safe = new([.. name.Select(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' ? c : '_')]);
        return safe == name && safe.Trim('.').Length > 0
            ? safe
            : $"{safe.Replace('.', '_')}-{Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(name)))[..8]}";
    }

    /// <summary>Written through a temporary file, so a file there is always whole and a resumed run may skip it.</summary>
    private static async Task WriteWholeAsync(string path, byte[] bytes, CancellationToken cancellation)
    {
        string partial = path + ".partial";
        await File.WriteAllBytesAsync(partial, bytes, cancellation);
        File.Move(partial, path, overwrite: true);
    }

    private static Task SaveAsync(string folder, ExportState state, CancellationToken cancellation) =>
        File.WriteAllBytesAsync(Path.Combine(folder, StateFile), JsonSerializer.SerializeToUtf8Bytes(state, ExportSetFormat.Json), cancellation);

    private static string Readme(ExportState state)
    {
        FormattableString text = $"""
        Archive export set, format {ExportSetFormat.Current} (ADR 0012)

        Tenant {state.TenantId}{(state.LegalEntityId is { } entity ? $", legal entity {entity}" : string.Empty)}, exported from {state.StartedAt:O}.

        {Warning}

        export-set.json      every other file with its SHA-256; written last
        catalogue.jsonl      every record, erased and purged ones included: ids, rules, dates and states
        records/<id>.zip     each kept record's export package (ADR 0009), with its originals, data key, proof and timestamp
        audit/entries.jsonl  the tenant's audit log, oldest first, with both hashes of each entry
        audit/anchors/       each daily anchor's proof for this tenant (.json) and its RFC 3161 token (.tsr)
        profiles/            the profile versions the records were decided under

        Verify it offline, with the timestamp providers' CA certificates you trust:

            archive-verify set <this folder> --trust <ca.pem>

        A valid set proves the originals existed exactly like this when each was sealed, and the audit log up to its
        newest anchor existed like this at that anchor's time. Entries after the newest anchor rest on the chain alone.
        It doesn't prove that the content is true.
        """;
        return text.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// A new run reads the log's head first: every record committed up to it is in the catalogue read next, so a set of
    /// the whole tenant can be held to the log in both directions.
    /// </summary>
    private async Task<ExportState> StateAsync(string folder, Guid? legalEntityId, CancellationToken cancellation)
    {
        string path = Path.Combine(folder, StateFile);
        AuditPage first = await api.GetJsonAsync<AuditPage>("v1/audit/entries/export?after=0", cancellation);
        if (File.Exists(path))
        {
            ExportState resumed = JsonSerializer.Deserialize<ExportState>(await File.ReadAllBytesAsync(path, cancellation), ExportSetFormat.Json)
                ?? throw new InvalidDataException($"{StateFile} can't be read.");
            if (resumed.LegalEntityId != legalEntityId || resumed.TenantId != first.TenantId)
            {
                throw new InvalidOperationException($"{folder} holds an unfinished set of another tenant or legal entity: resume it as it was started.");
            }

            log.WriteLine(string.Create(CultureInfo.InvariantCulture, $"Resuming the export started {resumed.StartedAt:O}."));
            return resumed;
        }

        ExportState state = new(first.TenantId, legalEntityId, time.GetUtcNow(), first.Head, CatalogueRead: false, AuditHead: null);
        await SaveAsync(folder, state, cancellation);
        return state;
    }

    /// <summary>The catalogue, paged by record id; once whole, a resumed run doesn't add to it.</summary>
    private async Task<ExportState> CatalogueAsync(string folder, ExportState state, CancellationToken cancellation)
    {
        string path = Path.Combine(folder, ExportSetFormat.Catalogue);
        if (state.CatalogueRead)
        {
            return state;
        }

        TrimToWholeLines(path);
        Guid? after = ReadLines<CatalogueLine>(path).LastOrDefault()?.RecordId;
        long count = ReadLines<CatalogueLine>(path).LongCount();
        do
        {
            string query = (state.LegalEntityId is { } entity ? $"&legalEntity={entity}" : string.Empty) + (after is { } cursor ? $"&after={cursor}" : string.Empty);
            CataloguePage page = await api.GetJsonAsync<CataloguePage>($"v1/records/catalogue?{query.TrimStart('&')}", cancellation);
            await AppendAsync(path, page.Records, cancellation);
            count += page.Records.Count;
            after = page.Next;
        }
        while (after is not null);

        log.WriteLine(string.Create(CultureInfo.InvariantCulture, $"Catalogue: {count} records."));
        ExportState read = state with { CatalogueRead = true };
        await SaveAsync(folder, read, cancellation);
        return read;
    }

    /// <summary>
    /// The head the audit log is exported to, read once every package is fetched: every commit and erasure the catalogue
    /// shows, and every erasure that made a package answer 410, is in the log. The log stops there, since the export's
    /// own reads add entries.
    /// </summary>
    private async Task<ExportState> HeadAsync(string folder, ExportState state, CancellationToken cancellation)
    {
        if (state.AuditHead is not null)
        {
            return state;
        }

        AuditPage head = await api.GetJsonAsync<AuditPage>("v1/audit/entries/export?after=0", cancellation);
        ExportState read = state with { AuditHead = head.Head };
        await SaveAsync(folder, read, cancellation);
        return read;
    }

    private async Task<List<ExportSetFailure>> PackagesAsync(string folder, CancellationToken cancellation)
    {
        List<ExportSetFailure> failed = [];
        long fetched = 0;
        long kept = 0;
        long erasedSince = 0;
        foreach (CatalogueLine line in ReadLines<CatalogueLine>(Path.Combine(folder, ExportSetFormat.Catalogue)).Where(l => l.Kept))
        {
            kept++;
            string file = Path.Combine(folder, ExportSetFormat.PackagePath(line.RecordId));
            if (File.Exists(file))
            {
                continue;
            }

            HttpStatusCode? refused = await api.DownloadAsync($"v1/records/{line.RecordId}/export", file, cancellation);
            if (refused == HttpStatusCode.Gone)
            {
                // Erased since the catalogue was read, by the sweep say: the log, read to a head after this, holds the erasure.
                erasedSince++;
                continue;
            }

            if (refused is { } status)
            {
                failed.Add(new ExportSetFailure(line.RecordId, status == HttpStatusCode.BadGateway ? "damaged: the archive refused to export it" : $"answered {(int)status}"));
                continue;
            }

            if (++fetched % 1000 == 0)
            {
                log.WriteLine(string.Create(CultureInfo.InvariantCulture, $"Packages: {fetched} fetched…"));
            }
        }

        log.WriteLine(string.Create(CultureInfo.InvariantCulture, $"Packages: {kept - failed.Count - erasedSince} of {kept} kept records, {erasedSince} erased since, {failed.Count} failed."));
        return failed;
    }

    private async Task AuditAsync(string folder, ExportState state, CancellationToken cancellation)
    {
        string path = Path.Combine(folder, ExportSetFormat.AuditEntries);
        TrimToWholeLines(path);
        long after = ReadLines<AuditEntryLine>(path).LastOrDefault()?.Sequence ?? 0;
        long head = state.AuditHead!.Value;
        while (after < head)
        {
            AuditPage page = await api.GetJsonAsync<AuditPage>(string.Create(CultureInfo.InvariantCulture, $"v1/audit/entries/export?after={after}"), cancellation);
            List<AuditEntryLine> entries = [.. page.Entries.Where(e => e.Sequence <= head)];
            await AppendAsync(path, entries, cancellation);
            if (entries.Count == 0)
            {
                break;
            }

            after = entries[^1].Sequence;
        }

        log.WriteLine(string.Create(CultureInfo.InvariantCulture, $"Audit log: {after} entries, up to the head the export started at."));
    }

    private async Task<int> AnchorsAsync(string folder, ExportState state, CancellationToken cancellation)
    {
        int written = 0;
        Guid? after = null;
        do
        {
            AnchorsPage page = await api.GetJsonAsync<AnchorsPage>(after is { } cursor ? $"v1/audit/anchors?after={cursor}" : "v1/audit/anchors", cancellation);
            foreach (AnchorSummary anchor in page.Anchors.Where(a => a.Sequence <= state.AuditHead!.Value))
            {
                written++;
                string proofFile = Path.Combine(folder, ExportSetFormat.AnchorProofPath(anchor.Id));
                if (File.Exists(proofFile))
                {
                    continue;
                }

                AnchorProofPage proof = await api.GetJsonAsync<AnchorProofPage>($"v1/audit/anchors/{anchor.Id}/proof", cancellation);
                byte[] token = new byte[proof.Token.Length];
                if (!Convert.TryFromBase64String(proof.Token, token, out int length))
                {
                    throw new InvalidDataException($"Anchor {anchor.Id}'s token isn't base64.");
                }

                // The token first: the proof's file marks the anchor done.
                await WriteWholeAsync(Path.Combine(folder, ExportSetFormat.AnchorTokenPath(anchor.Id)), token[..length], cancellation);
                await WriteWholeAsync(proofFile, JsonSerializer.SerializeToUtf8Bytes(proof.Proof, ExportSetFormat.Json), cancellation);
            }

            after = page.Next;
        }
        while (after is not null);

        log.WriteLine(string.Create(CultureInfo.InvariantCulture, $"Anchors: {written}."));
        return written;
    }

    private async Task ProfilesAsync(string folder, CancellationToken cancellation)
    {
        ProfilesPage profiles = await api.GetJsonAsync<ProfilesPage>("v1/profiles", cancellation);
        foreach (ProfileSummary profile in profiles.Profiles)
        {
            string name = profile.Kind == "statutory" ? profile.Country ?? string.Empty : profile.Name ?? string.Empty;
            string kind = Uri.EscapeDataString(profile.Kind);
            string escaped = Uri.EscapeDataString(name);
            VersionsPage versions = await api.GetJsonAsync<VersionsPage>($"v1/profiles/{kind}/{escaped}/versions", cancellation);
            string target = Path.Combine(folder, ExportSetFormat.ProfilesFolder, Safe(profile.Kind), Safe(name));
            Directory.CreateDirectory(target);
            foreach (VersionSummary version in versions.Versions)
            {
                string file = Path.Combine(target, $"{Safe(version.Version)}.yaml");
                if (!File.Exists(file))
                {
                    VersionFile text = await api.GetJsonAsync<VersionFile>($"v1/profiles/{kind}/{escaped}/versions/{Uri.EscapeDataString(version.Version)}", cancellation);
                    await WriteWholeAsync(file, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(text.Text), cancellation);
                }
            }
        }
    }

    private async Task ManifestAsync(string folder, ExportState state, List<ExportSetFailure> failed, int anchors, CancellationToken cancellation)
    {
        List<CatalogueLine> catalogue = [.. ReadLines<CatalogueLine>(Path.Combine(folder, ExportSetFormat.Catalogue))];
        long entries = ReadLines<AuditEntryLine>(Path.Combine(folder, ExportSetFormat.AuditEntries)).LongCount();
        string root = Path.GetFullPath(folder);
        List<ExportSetFile> files = [];
        foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            if (Path.GetFileName(file) == StateFile)
            {
                continue;
            }

            if (file.EndsWith(".partial", StringComparison.Ordinal))
            {
                File.Delete(file);
                continue;
            }

            await using FileStream stream = File.OpenRead(file);
            files.Add(new ExportSetFile(Path.GetRelativePath(root, file).Replace('\\', '/'), Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, cancellation)), stream.Length));
        }

        ExportSetManifest manifest = new(
            ExportSetFormat.Current,
            state.TenantId,
            state.LegalEntityId,
            state.StartedAt,
            time.GetUtcNow(),
            new ExportSetCounts(
                catalogue.Count,
                catalogue.Count(l => l.Status == "committed"),
                catalogue.Count(l => l.Status == "sealed"),
                catalogue.Count(l => l.Status == "erased"),
                catalogue.Count(l => l.Status == "purged"),
                entries,
                anchors),
            state.CatalogueHead,
            state.AuditHead!.Value,
            files,
            failed);
        await WriteWholeAsync(Path.Combine(folder, ExportSetFormat.Manifest), JsonSerializer.SerializeToUtf8Bytes(manifest, ExportSetFormat.Json), cancellation);
        File.Delete(Path.Combine(folder, StateFile));
        log.WriteLine(string.Create(CultureInfo.InvariantCulture, $"Finished: {files.Count} files, {ExportSetFormat.Manifest} written."));
    }

    /// <param name="CatalogueHead">The newest audit entry before the catalogue was read: every record committed up to it is in the catalogue.</param>
    /// <param name="AuditHead">The newest audit entry once every package was fetched: the log is exported up to it. Null until then.</param>
    private sealed record ExportState(Guid TenantId, Guid? LegalEntityId, DateTimeOffset StartedAt, long CatalogueHead, bool CatalogueRead, long? AuditHead);
}
