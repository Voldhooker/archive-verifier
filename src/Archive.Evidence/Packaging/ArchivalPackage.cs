using System.Formats.Tar;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace Archive.Evidence.Packaging;

/// <summary>
/// The archival package, format 1 (ADR 0006): an uncompressed POSIX ustar archive holding <c>manifest.json</c> first,
/// then each original unchanged as <c>content/1</c>, <c>content/2</c> and so on. Entries carry no owner and the Unix
/// epoch as their time, so the same record always gives the same bytes.
/// </summary>
public static class ArchivalPackage
{
    public const string ManifestPath = "manifest.json";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    private static readonly UnixFileMode EntryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    /// <summary>Builds the package. The components of <paramref name="manifest"/> are filled in from <paramref name="contents"/>.</summary>
    public static (byte[] Package, PackageManifest Manifest) Create(PackageManifest manifest, IReadOnlyList<PackageContent> contents)
    {
        ArgumentOutOfRangeException.ThrowIfZero(contents.Count);

        PackageComponent[] components = [.. contents.Select((content, index) => new PackageComponent(
            $"content/{index + 1}",
            content.Name,
            content.MediaType,
            content.Bytes.Length,
            Convert.ToHexStringLower(SHA256.HashData(content.Bytes.Span))))];
        PackageManifest complete = manifest with { Format = PackageManifest.CurrentFormat, Components = components };

        using MemoryStream package = new();
        using (TarWriter writer = new(package, TarEntryFormat.Ustar, leaveOpen: true))
        {
            Write(writer, ManifestPath, ManifestJson(complete));
            for (int i = 0; i < components.Length; i++)
            {
                Write(writer, components[i].Path, contents[i].Bytes);
            }
        }

        return (package.ToArray(), complete);
    }

    /// <summary>The manifest's JSON, exactly as a package holds it.</summary>
    public static byte[] ManifestJson(PackageManifest manifest) => JsonSerializer.SerializeToUtf8Bytes(manifest, Json);

    /// <summary>The manifest's bytes exactly as the package holds them, its first entry; null when it has none.</summary>
    public static byte[]? ManifestBytes(ReadOnlyMemory<byte> package)
    {
        using TarReader reader = new(AsStream(package));
        if (reader.GetNextEntry(copyData: false) is not { Name: ManifestPath } entry)
        {
            return null;
        }

        byte[] data = new byte[entry.Length];
        entry.DataStream?.ReadExactly(data);
        return data;
    }

    /// <summary>Reads a package and checks every component against the manifest.</summary>
    /// <exception cref="InvalidDataException">The package is malformed, or a component's size or hash differs from the manifest.</exception>
    public static (PackageManifest Manifest, IReadOnlyList<PackageContent> Contents) Read(ReadOnlyMemory<byte> package)
    {
        Dictionary<string, byte[]> entries = new(StringComparer.Ordinal);
        string? first = null;
        using (TarReader reader = new(AsStream(package)))
        {
            // copyData: false reads each entry straight from the package, which outlives the reader.
            while (reader.GetNextEntry(copyData: false) is { } entry)
            {
                first ??= entry.Name;
                byte[] data = new byte[entry.Length];
                entry.DataStream?.ReadExactly(data);
                if (!entries.TryAdd(entry.Name, data))
                {
                    throw new InvalidDataException($"The package holds {entry.Name} twice.");
                }
            }
        }

        if (first != ManifestPath)
        {
            throw new InvalidDataException("The package does not start with manifest.json.");
        }

        PackageManifest manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<PackageManifest>(entries[ManifestPath], Json)
                ?? throw new InvalidDataException("manifest.json is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"manifest.json is not valid: {exception.Message}");
        }

        if (manifest.Format != PackageManifest.CurrentFormat)
        {
            throw new InvalidDataException($"Package format {manifest.Format} is not one this version reads.");
        }

        // Every entry but the manifest must be listed exactly once, so nothing goes unverified.
        if (manifest.Components is not { Count: > 0 } listed
            || !listed.Select(c => c.Path).Order(StringComparer.Ordinal)
                .SequenceEqual(entries.Keys.Where(k => k != ManifestPath).Order(StringComparer.Ordinal)))
        {
            throw new InvalidDataException("The manifest's components do not match the package's entries one to one.");
        }

        List<PackageContent> contents = [];
        foreach (PackageComponent component in manifest.Components)
        {
            if (!entries.TryGetValue(component.Path, out byte[]? bytes))
            {
                throw new InvalidDataException($"{component.Path} is listed in the manifest but missing.");
            }

            if (bytes.Length != component.Size || Convert.ToHexStringLower(SHA256.HashData(bytes)) != component.Sha256)
            {
                throw new InvalidDataException($"{component.Path} does not match its hash in the manifest.");
            }

            contents.Add(new PackageContent(component.Name, component.MediaType, bytes));
        }

        return (manifest, contents);
    }

    /// <summary>A read-only stream over the bytes, without copying them when they are a plain array.</summary>
    private static MemoryStream AsStream(ReadOnlyMemory<byte> bytes) =>
        MemoryMarshal.TryGetArray(bytes, out ArraySegment<byte> segment)
            ? new MemoryStream(segment.Array!, segment.Offset, segment.Count, writable: false)
            : new MemoryStream(bytes.ToArray(), writable: false);

    private static void Write(TarWriter writer, string path, ReadOnlyMemory<byte> bytes)
    {
        using MemoryStream data = AsStream(bytes);
        writer.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, path)
        {
            DataStream = data,
            Mode = EntryMode,
            ModificationTime = DateTimeOffset.UnixEpoch
        });
    }
}
