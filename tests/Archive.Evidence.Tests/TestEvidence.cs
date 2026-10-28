using System.Formats.Asn1;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Archive.Evidence.Export;
using Archive.Evidence.Packaging;
using Archive.Evidence.Sealing;

namespace Archive.Evidence.Tests;

/// <summary>
/// Builds export packages as the archive does, signed by a throwaway provider whose certificate chains to a throwaway
/// CA, so each part can be changed on its way into the package.
/// </summary>
internal sealed class TestEvidence : IDisposable
{
    public static readonly Guid RecordId = Guid.Parse("0199e9a0-0000-7000-8000-00000000e001");

    public TestEvidence()
    {
        using ECDsa caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest ca = new("CN=Test Root CA", caKey, HashAlgorithmName.SHA256);
        ca.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        ca.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Root = ca.CreateSelfSigned(now.AddDays(-30), now.AddYears(5));

        using ECDsa tsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest tsa = new("CN=Test TSA", tsaKey, HashAlgorithmName.SHA256);
        tsa.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(TimestampTokenCheck.TimeStampingUsage)], critical: true));
        tsa.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using X509Certificate2 issued = tsa.Create(Root, now.AddDays(-1), now.AddYears(1), RandomNumberGenerator.GetBytes(8));
        Signer = issued.CopyWithPrivateKey(tsaKey);
    }

    public X509Certificate2 Root { get; }

    public X509Certificate2 Signer { get; }

    public X509Certificate2Collection Trust => [Root];

    /// <summary>A signed RFC 3161 token over <paramref name="hash"/>, with the signer's certificate and the ESS attribute RFC 3161 asks for.</summary>
    /// <param name="at">The token's time; now unless given.</param>
    public static byte[] Token(byte[] hash, X509Certificate2 signer, DateTimeOffset? at = null)
    {
        byte[] serial = RandomNumberGenerator.GetBytes(8);
        serial[0] = (byte)((serial[0] & 0x7f) | 0x01);
        Rfc3161TimestampTokenInfo info = new(
            new Oid("1.3.6.1.4.1.32473.1"), new Oid("2.16.840.1.101.3.4.2.1"), hash, serial, at ?? DateTimeOffset.UtcNow);
        SignedCms cms = new(new ContentInfo(new Oid("1.2.840.113549.1.9.16.1.4"), info.Encode()));
        CmsSigner cmsSigner = new(SubjectIdentifierType.IssuerAndSerialNumber, signer)
        {
            DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"),
            IncludeOption = X509IncludeOption.EndCertOnly
        };
        AsnWriter ess = new(AsnEncodingRules.DER);
        using (ess.PushSequence())
        {
            using (ess.PushSequence())
            {
                using (ess.PushSequence())
                {
                    ess.WriteOctetString(SHA256.HashData(signer.RawData));
                }
            }
        }

        cmsSigner.SignedAttributes.Add(new AsnEncodedData(new Oid("1.2.840.113549.1.9.16.2.47"), ess.Encode()));
        cms.ComputeSignature(cmsSigner);
        return cms.Encode();
    }

    /// <summary>Adds an entry to a finished package, as someone handling it might.</summary>
    public static byte[] WithEntry(byte[] package, string name, byte[] content)
    {
        using MemoryStream zip = new();
        zip.Write(package);
        using (ZipArchive archive = new(zip, ZipArchiveMode.Update, leaveOpen: true))
        {
            using Stream entry = archive.CreateEntry(name).Open();
            entry.Write(content);
        }

        return zip.ToArray();
    }

    public static ExportVerification Verify(byte[] package, X509Certificate2Collection trust)
    {
        using MemoryStream stream = new(package, writable: false);
        return ExportVerifier.Verify(stream, trust);
    }

    /// <summary>A provider certificate the trusted CA issues, valid from <paramref name="from"/> to <paramref name="to"/>.</summary>
    public X509Certificate2 Issue(DateTimeOffset from, DateTimeOffset to, bool timeStamping = true)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new("CN=Issued TSA", key, HashAlgorithmName.SHA256);
        if (timeStamping)
        {
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(TimestampTokenCheck.TimeStampingUsage)], critical: true));
        }

        using X509Certificate2 issued = request.Create(Root, from, to, RandomNumberGenerator.GetBytes(8));
        return issued.CopyWithPrivateKey(key);
    }

    public void Dispose()
    {
        Root.Dispose();
        Signer.Dispose();
    }

    /// <summary>A package as the archive makes it, for a record sealed as leaf 2 of 5; <paramref name="change"/> alters a part first.</summary>
    /// <param name="recordId"><see cref="RecordId"/> unless given.</param>
    public byte[] Package(Func<Parts, Parts>? change = null, bool sealedRecord = true, Guid? recordId = null)
    {
        Guid id = recordId ?? RecordId;
        byte[] key = RandomNumberGenerator.GetBytes(32);
        PackageManifest manifest = new(
            PackageManifest.CurrentFormat,
            id,
            Guid.NewGuid(),
            "file",
            new DateOnly(2026, 10, 22),
            "submitter",
            new DateOnly(2031, 12, 31),
            "DK",
            "2026.1",
            "DK-BOOKKEEPING",
            []);
        PackageContent original = new("invoice.pdf", "application/pdf", Encoding.UTF8.GetBytes("%PDF-1.7 an invoice"));
        (byte[] package, PackageManifest complete) = ArchivalPackage.Create(manifest, [original]);
        byte[] stored = PackageCipher.Encrypt(package, key, id);
        byte[] hash = SHA256.HashData(stored);

        ExportSeal? seal = null;
        byte[]? token = null;
        if (sealedRecord)
        {
            byte[][] leaves = [SHA256.HashData("a"u8), SHA256.HashData("b"u8), hash, SHA256.HashData("d"u8), SHA256.HashData("e"u8)];
            (byte[] root, IReadOnlyList<InclusionProof> proofs) = MerkleTree.Build(leaves);
            seal = new ExportSeal(Guid.NewGuid(), 2, 5, [.. proofs[2].Path.Select(Convert.ToHexStringLower)], Convert.ToHexStringLower(root));
            token = Token(root, Signer);
        }

        Parts parts = new(
            new ExportDocument(ExportDocument.CurrentFormat, id, DateTimeOffset.UtcNow, Convert.ToHexStringLower(hash), Convert.ToHexStringLower(key), seal),
            stored,
            token,
            complete,
            [original]);
        parts = change?.Invoke(parts) ?? parts;

        using MemoryStream zip = new();
        ExportPackage.Write(zip, parts.Document, parts.Stored, parts.Token, ArchivalPackage.ManifestJson(parts.Manifest), parts.Contents, "{}"u8.ToArray());
        return zip.ToArray();
    }

    public sealed record Parts(
        ExportDocument Document, byte[] Stored, byte[]? Token, PackageManifest Manifest, IReadOnlyList<PackageContent> Contents);
}
