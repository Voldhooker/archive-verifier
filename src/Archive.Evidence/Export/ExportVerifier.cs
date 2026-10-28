using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

using Archive.Evidence.Packaging;
using Archive.Evidence.Sealing;

namespace Archive.Evidence.Export;

/// <summary>
/// Checks an export package offline (ADR 0009): from the originals to the manifest, from the manifest to the decrypted
/// object, from the object to its hash, from the hash through the proof to the root, and from the root to a trusted
/// provider's signed time. It needs nothing but the package and the trust anchors, and stops at the first failed check.
/// </summary>
/// <remarks>
/// Valid proves that these originals existed exactly like this at the token's time. It doesn't prove who sealed them:
/// anyone can have a provider stamp a root of their own. Nor does it cover <c>policy.json</c> or the export time, which
/// are there to be read.
/// </remarks>
public static class ExportVerifier
{
    /// <summary>The most a package may hold, unpacked: a record is at most 100 MB (ADR 0006), and a package holds it about twice.</summary>
    public const long MaxUnpackedBytes = 512L * 1024 * 1024;

    public static ExportVerification Verify(Stream package, X509Certificate2Collection trustAnchors)
    {
        ArgumentNullException.ThrowIfNull(trustAnchors);
        try
        {
            return Check(package, trustAnchors);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // Whatever a crafted package makes the reader throw, it is a package this verifier can't vouch for.
            return Fail(null, [], ExportChecks.Package, $"It could not be read: {exception.GetType().Name}.");
        }
    }

    private static ExportVerification Check(Stream package, X509Certificate2Collection trustAnchors)
    {
        List<string> passed = [];
        Dictionary<string, byte[]> entries;
        ExportDocument document;
        try
        {
            entries = ReadEntries(package);
            document = ExportDocument.Read(entries.GetValueOrDefault(ExportPackage.DocumentEntry)
                ?? throw new InvalidDataException("It holds no export.json."));
        }
        catch (Exception exception) when (exception is InvalidDataException or JsonException or NotSupportedException)
        {
            return Fail(null, passed, ExportChecks.Package, exception.Message);
        }

        Guid recordId = document.RecordId;
        string? packageFault = PackageFault(document, entries);
        if (packageFault is not null)
        {
            return Fail(recordId, passed, ExportChecks.Package, packageFault);
        }

        passed.Add(ExportChecks.Package);
        byte[] stored = entries[ExportPackage.ObjectEntry];
        byte[] objectHash = SHA256.HashData(stored);
        if (!Convert.ToHexStringLower(objectHash).Equals(document.ObjectSha256, StringComparison.OrdinalIgnoreCase))
        {
            return Fail(recordId, passed, ExportChecks.CiphertextHash, "object.bin's SHA-256 is not the one export.json names.");
        }

        passed.Add(ExportChecks.CiphertextHash);
        byte[] decrypted;
        try
        {
            decrypted = PackageCipher.Decrypt(stored, Convert.FromHexString(document.DataKey), recordId);
        }
        catch (Exception exception) when (exception is CryptographicException or InvalidDataException or FormatException or ArgumentException)
        {
            return Fail(recordId, passed, ExportChecks.Decryption, "object.bin does not decrypt with the data key for this record.");
        }

        passed.Add(ExportChecks.Decryption);
        string? manifestFault = ManifestFault(recordId, decrypted, entries);
        if (manifestFault is not null)
        {
            return Fail(recordId, passed, ExportChecks.Manifest, manifestFault);
        }

        passed.Add(ExportChecks.Manifest);
        if (document.Seal is not { } seal)
        {
            return new ExportVerification(ExportVerification.Unsealed, recordId, passed, null, null, null, null);
        }

        byte[] root;
        try
        {
            root = Convert.FromHexString(seal.Root);
            InclusionProof proof = new(seal.LeafIndex, seal.TreeSize, [.. seal.Proof.Select(Convert.FromHexString)]);
            if (!MerkleTree.Verify(objectHash, proof, root))
            {
                return Fail(recordId, passed, ExportChecks.Proof, "The proof does not lead from object.bin's hash to the root.");
            }
        }
        catch (FormatException)
        {
            return Fail(recordId, passed, ExportChecks.Proof, "The proof or the root is not hex.");
        }

        passed.Add(ExportChecks.Proof);
        byte[] token = entries[ExportPackage.TokenEntry];
        if (!TimestampTokenCheck.Covers(token, root, out DateTimeOffset stampedAt, out X509Certificate2? signer) || signer is null)
        {
            return Fail(recordId, passed, ExportChecks.Timestamp, "The timestamp token does not cover the root, or its signature does not check.");
        }

        passed.Add(ExportChecks.Timestamp);
        if (!TimestampTokenCheck.Trusts(signer, trustAnchors, TimestampTokenCheck.CertificatesIn(token), stampedAt))
        {
            return Fail(recordId, passed, ExportChecks.Trust, $"The token's signer, {signer.Subject}, does not chain to a trusted provider.");
        }

        passed.Add(ExportChecks.Trust);
        return new ExportVerification(ExportVerification.Valid, recordId, passed, null, null, stampedAt, signer.Subject);
    }

    private static Dictionary<string, byte[]> ReadEntries(Stream package)
    {
        Dictionary<string, byte[]> entries = new(StringComparer.Ordinal);
        using ZipArchive zip = new(package, ZipArchiveMode.Read, leaveOpen: true);
        if (zip.Entries.Sum(e => e.Length) > MaxUnpackedBytes)
        {
            throw new InvalidDataException($"It unpacks to more than {MaxUnpackedBytes / (1024 * 1024)} MiB.");
        }

        foreach (ZipArchiveEntry entry in zip.Entries)
        {
            if (entry.FullName.EndsWith('/'))
            {
                continue;
            }

            using Stream data = entry.Open();
            using MemoryStream copy = new();
            data.CopyTo(copy);
            if (!entries.TryAdd(entry.FullName, copy.ToArray()))
            {
                throw new InvalidDataException($"It holds {entry.FullName} twice.");
            }
        }

        return entries;
    }

    /// <summary>What is wrong with the package's shape, or null: format 1, the entries it names, and nothing else.</summary>
    private static string? PackageFault(ExportDocument document, Dictionary<string, byte[]> entries)
    {
        if (document.Format != ExportDocument.CurrentFormat)
        {
            return $"Export format {document.Format} is not one this verifier reads.";
        }

        if (document.ObjectSha256 is null || document.DataKey is null || !entries.ContainsKey(ExportPackage.ObjectEntry))
        {
            return "It holds no object.bin, or export.json names no hash or key for it.";
        }

        if (entries.ContainsKey(ExportPackage.TokenEntry) != document.Seal is not null)
        {
            return document.Seal is null ? "It holds a token but export.json names no seal." : "export.json names a seal but the package holds no token.";
        }

        if (document.Seal is { } seal && (seal.Proof is null || seal.Root is null || seal.Proof.Any(hash => hash is null)))
        {
            return "export.json's seal names no proof or root.";
        }

        string[] known = [ExportPackage.DocumentEntry, ExportPackage.ObjectEntry, ExportPackage.TokenEntry, ExportPackage.ManifestEntry,
            ExportPackage.PolicyEntry, ExportPackage.ReadmeEntry];
        string? unknown = entries.Keys.FirstOrDefault(name => !known.Contains(name) && ExportPackage.OriginalNumber(name) is null);
        return unknown is null ? null : $"It holds {unknown}, which format 1 doesn't name.";
    }

    /// <summary>What is wrong with the decrypted package or the loose files, or null.</summary>
    private static string? ManifestFault(Guid recordId, byte[] decrypted, Dictionary<string, byte[]> entries)
    {
        PackageManifest manifest;
        IReadOnlyList<PackageContent> contents;
        try
        {
            (manifest, contents) = ArchivalPackage.Read(decrypted);
        }
        catch (Exception exception) when (exception
            is InvalidDataException or FormatException or EndOfStreamException or OverflowException or ArgumentOutOfRangeException)
        {
            return $"The decrypted package does not check out: {exception.Message}";
        }

        if (manifest.RecordId != recordId)
        {
            return "The decrypted package is another record's.";
        }

        // Held to the manifest's bytes as sealed, not to a fresh serialization, so a later change in how JSON is written
        // can never fail an old package.
        if (!entries.TryGetValue(ExportPackage.ManifestEntry, out byte[]? loose)
            || ArchivalPackage.ManifestBytes(decrypted) is not { } sealedManifest
            || !loose.AsSpan().SequenceEqual(sealedManifest))
        {
            return "manifest.json differs from the manifest object.bin holds.";
        }

        // Each original under exactly the name the manifest gives it, and its bytes exactly as sealed.
        string[] originals = [.. entries.Keys.Where(name => ExportPackage.OriginalNumber(name) is not null)];
        if (originals.Length != contents.Count)
        {
            return $"The package holds {originals.Length} originals; object.bin holds {contents.Count}.";
        }

        for (int i = 0; i < contents.Count; i++)
        {
            string expected = ExportPackage.OriginalEntry(i + 1, manifest.Components[i].Name);
            if (!entries.TryGetValue(expected, out byte[]? original) || !original.AsSpan().SequenceEqual(contents[i].Bytes.Span))
            {
                return $"Original {i + 1} is missing as {expected}, or differs from the one object.bin holds.";
            }
        }

        return null;
    }

    private static ExportVerification Fail(Guid? recordId, List<string> passed, string check, string reason) =>
        new(ExportVerification.Invalid, recordId, passed, check, reason, null, null);
}
