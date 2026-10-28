using System.Formats.Tar;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Archive.Evidence.Packaging;
using Shouldly;

namespace Archive.Evidence.Tests;

public sealed class ArchivalPackageTests
{
    private static readonly PackageManifest Manifest = new(
        0,
        Guid.Parse("0199e9a0-0000-7000-8000-0000000000aa"),
        Guid.Parse("0199e9a0-0000-7000-8000-0000000000bb"),
        "file",
        new DateOnly(2026, 3, 10),
        "submitter",
        new DateOnly(2031, 12, 31),
        "DK",
        "2026.1",
        "DK-BOOKKEEPING",
        []);

    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    private static readonly PackageContent Invoice = new("invoice.pdf", "application/pdf", Encoding.ASCII.GetBytes("%PDF-1.7 an invoice"));

    [Fact]
    public void Create_ThenRead_ReturnsTheOriginalUnchangedAndAManifestWithItsHash()
    {
        // Act
        (byte[] package, PackageManifest manifest) = ArchivalPackage.Create(Manifest, [Invoice]);
        (PackageManifest read, IReadOnlyList<PackageContent> contents) = ArchivalPackage.Read(package);

        // Assert
        manifest.Format.ShouldBe(1);
        PackageComponent component = manifest.Components.ShouldHaveSingleItem();
        component.ShouldBe(new PackageComponent(
            "content/1", "invoice.pdf", "application/pdf", Invoice.Bytes.Length, Convert.ToHexStringLower(SHA256.HashData(Invoice.Bytes.Span))));
        (read with { Components = [] }).ShouldBe(manifest with { Components = [] });
        read.Components.ShouldBe(manifest.Components);
        contents.ShouldHaveSingleItem().Bytes.ToArray().ShouldBe(Invoice.Bytes.ToArray());
    }

    [Fact]
    public void ManifestJson_UnderTheLawAlone_HasTheShapeOfEveryEarlierManifest()
    {
        // Act: the custom fields came with custom profiles and are written only when set.
        string json = Encoding.UTF8.GetString(ArchivalPackage.ManifestJson(Manifest));
        string custom = Encoding.UTF8.GetString(ArchivalPackage.ManifestJson(Manifest with { CustomProfile = "ACME", CustomVersion = "3" }));

        // Assert
        json.ShouldNotContain("custom", Case.Insensitive);
        custom.ShouldContain("\"customProfile\": \"ACME\"");
    }

    [Fact]
    public void ManifestBytes_AreTheManifestAsSealed_WhateverTheShapeItWasWrittenIn()
    {
        // Arrange: a package whose manifest was written with keys in an order no serializer of today would choose.
        byte[] manifest = Encoding.UTF8.GetBytes(
            "{\"recordId\":\"0199e9a0-0000-7000-8000-0000000000aa\",\"format\":0,\"legalEntityId\":\"0199e9a0-0000-7000-8000-0000000000bb\","
            + "\"recordType\":\"file\",\"recordDate\":\"2026-03-10\",\"recordDateSource\":\"submitter\",\"expiry\":\"2031-12-31\","
            + "\"profileCountry\":\"DK\",\"profileVersion\":\"2026.1\",\"retentionClass\":\"DK-BOOKKEEPING\",\"components\":[]}");
        using MemoryStream tar = new();
        using (TarWriter writer = new(tar, TarEntryFormat.Ustar, leaveOpen: true))
        {
            writer.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, "manifest.json") { DataStream = new MemoryStream(manifest) });
        }

        // Act and assert: an export copies these bytes, which the verifier holds byte for byte.
        ArchivalPackage.ManifestBytes(tar.ToArray()).ShouldBe(manifest);
    }

    [Fact]
    public void Create_StoresManifestFirstThenEachContentAsUstarWithNoOwnerOrTime()
    {
        // Act
        (byte[] package, _) = ArchivalPackage.Create(Manifest, [Invoice, Invoice with { Name = "copy.pdf" }]);

        // Assert
        using TarReader reader = new(new MemoryStream(package));
        List<TarEntry> entries = [];
        while (reader.GetNextEntry() is { } entry)
        {
            entries.Add(entry);
        }

        entries.Select(e => e.Name).ShouldBe(["manifest.json", "content/1", "content/2"]);
        entries.ShouldAllBe(e => e.Format == TarEntryFormat.Ustar && e.ModificationTime == DateTimeOffset.UnixEpoch && e.Uid == 0);
    }

    [Fact]
    public void Create_TwiceForTheSameRecord_GivesTheSameBytes()
    {
        // Act
        (byte[] first, _) = ArchivalPackage.Create(Manifest, [Invoice]);
        (byte[] second, _) = ArchivalPackage.Create(Manifest, [Invoice]);

        // Assert
        second.ShouldBe(first);
    }

    [Fact]
    public void Read_WithAlteredContent_FailsNamingTheComponent()
    {
        // Arrange: change one byte of the original inside the tar.
        (byte[] package, _) = ArchivalPackage.Create(Manifest, [Invoice]);
        int at = IndexOf(package, Invoice.Bytes.ToArray());
        package[at] ^= 0x01;

        // Act and assert
        Should.Throw<InvalidDataException>(() => ArchivalPackage.Read(package)).Message.ShouldContain("content/1");
    }

    [Fact]
    public void Read_WithManifestListingOneComponentTwice_Fails()
    {
        // Arrange: two contents, but a manifest naming content/1 twice, so content/2 would go unverified.
        (_, PackageManifest manifest) = ArchivalPackage.Create(Manifest, [Invoice, Invoice with { Name = "copy.pdf" }]);
        PackageManifest forged = manifest with { Components = [manifest.Components[0], manifest.Components[0]] };
        byte[] package = Repack(forged, Invoice.Bytes.ToArray(), Invoice.Bytes.ToArray());

        // Act and assert
        Should.Throw<InvalidDataException>(() => ArchivalPackage.Read(package)).Message.ShouldContain("one to one");
    }

    private static byte[] Repack(PackageManifest manifest, params byte[][] contents)
    {
        using MemoryStream package = new();
        using (TarWriter writer = new(package, TarEntryFormat.Ustar, leaveOpen: true))
        {
            Add(writer, "manifest.json", JsonSerializer.SerializeToUtf8Bytes(manifest, Web));
            for (int i = 0; i < contents.Length; i++)
            {
                Add(writer, $"content/{i + 1}", contents[i]);
            }
        }

        return package.ToArray();
    }

    private static void Add(TarWriter writer, string name, byte[] bytes) =>
        writer.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, name) { DataStream = new MemoryStream(bytes) });

    private static int IndexOf(byte[] haystack, byte[] needle) =>
        Enumerable.Range(0, haystack.Length - needle.Length).First(i => haystack.AsSpan(i, needle.Length).SequenceEqual(needle));
}
