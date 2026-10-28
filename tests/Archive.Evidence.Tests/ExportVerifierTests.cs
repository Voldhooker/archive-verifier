using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Archive.Evidence.Export;
using Archive.Evidence.Packaging;
using Shouldly;

namespace Archive.Evidence.Tests;

public sealed class ExportVerifierTests : IDisposable
{
    private readonly TestEvidence _evidence = new();

    public void Dispose() => _evidence.Dispose();

    [Fact]
    public void Verify_APackageAsMade_IsValidWithItsTimeAndProvider()
    {
        // Act
        ExportVerification result = TestEvidence.Verify(_evidence.Package(), _evidence.Trust);

        // Assert
        result.Outcome.ShouldBe(ExportVerification.Valid);
        result.RecordId.ShouldBe(TestEvidence.RecordId);
        result.Passed.ShouldBe([ExportChecks.Package, ExportChecks.CiphertextHash, ExportChecks.Decryption, ExportChecks.Manifest,
            ExportChecks.Proof, ExportChecks.Timestamp, ExportChecks.Trust]);
        result.SealedAt.ShouldNotBeNull().ShouldBeGreaterThan(DateTimeOffset.UtcNow.AddMinutes(-1));
        result.Provider.ShouldBe("CN=Test TSA");
    }

    [Fact]
    public void Verify_AnUnsealedPackage_IsWholeButUnsealed()
    {
        // Act
        ExportVerification result = TestEvidence.Verify(_evidence.Package(sealedRecord: false), _evidence.Trust);

        // Assert
        result.Outcome.ShouldBe(ExportVerification.Unsealed);
        result.Passed.ShouldBe([ExportChecks.Package, ExportChecks.CiphertextHash, ExportChecks.Decryption, ExportChecks.Manifest]);
        result.SealedAt.ShouldBeNull();
    }

    [Fact]
    public void Verify_WithAByteOfTheObjectChanged_FailsTheCiphertextHash() =>
        FailsAt(ExportChecks.CiphertextHash, p => p with { Stored = Flip(p.Stored, 100) });

    [Fact]
    public void Verify_WithTheObjectChangedAndItsHashUpdated_FailsDecryption() =>
        FailsAt(ExportChecks.Decryption, p =>
        {
            byte[] stored = Flip(p.Stored, 100);
            return p with { Stored = stored, Document = p.Document with { ObjectSha256 = Convert.ToHexStringLower(SHA256.HashData(stored)) } };
        });

    [Fact]
    public void Verify_WithAnotherKey_FailsDecryption() =>
        FailsAt(ExportChecks.Decryption, p => p with { Document = p.Document with { DataKey = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)) } });

    [Fact]
    public void Verify_WithAnotherRecordId_FailsDecryption() =>
        FailsAt(ExportChecks.Decryption, p => p with { Document = p.Document with { RecordId = Guid.NewGuid() } });

    [Fact]
    public void Verify_WithAnOriginalChanged_FailsTheManifest() =>
        FailsAt(ExportChecks.Manifest, p => p with { Contents = [p.Contents[0] with { Bytes = Encoding.UTF8.GetBytes("%PDF-1.7 another invoice") }] });

    [Fact]
    public void Verify_WithTheLooseManifestChanged_FailsTheManifest() =>
        FailsAt(ExportChecks.Manifest, p => p with { Manifest = p.Manifest with { RetentionClass = "DK-NOTHING" } });

    [Fact]
    public void Verify_WithAProofSiblingChanged_FailsTheProof() =>
        FailsAt(ExportChecks.Proof, p => p with
        {
            Document = p.Document with { Seal = p.Document.Seal! with { Proof = [new string('0', 64), .. p.Document.Seal.Proof.Skip(1)] } }
        });

    [Fact]
    public void Verify_WithATokenOverAnotherRoot_FailsTheTimestamp() =>
        FailsAt(ExportChecks.Timestamp, p => p with { Token = TestEvidence.Token(SHA256.HashData("another root"u8), _evidence.Signer) });

    [Fact]
    public void Verify_WithAProviderNobodyTrusts_FailsTrust()
    {
        // Arrange: a token signed by a certificate that doesn't chain to the trusted CA.
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new("CN=Rogue TSA", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.8")], critical: true));
        using X509Certificate2 rogue = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        // Act and assert
        FailsAt(ExportChecks.Trust, p => p with { Token = TestEvidence.Token(Convert.FromHexString(p.Document.Seal!.Root), rogue) });
    }

    [Fact]
    public void Verify_WithASignerTheCaIssuedWithoutTheTimeStampingUsage_FailsTrust()
    {
        // Arrange: a certificate with no usage list chains fine, and a chain check alone would take it as any usage.
        using X509Certificate2 signer = _evidence.Issue(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), timeStamping: false);

        // Act and assert: .NET's token check refuses it already; the trust check would again.
        FailsAtOneOf([ExportChecks.Timestamp, ExportChecks.Trust], p => p with { Token = TestEvidence.Token(Convert.FromHexString(p.Document.Seal!.Root), signer) });
    }

    [Fact]
    public void Trusts_ASignerWithoutTheTimeStampingUsage_Refuses()
    {
        // Arrange: chains to the trusted CA, but names no usage.
        using X509Certificate2 signer = _evidence.Issue(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), timeStamping: false);

        // Act and assert
        Archive.Evidence.Sealing.TimestampTokenCheck.Trusts(signer, _evidence.Trust, [], DateTimeOffset.UtcNow).ShouldBeFalse();
        Archive.Evidence.Sealing.TimestampTokenCheck.Trusts(_evidence.Signer, _evidence.Trust, [], DateTimeOffset.UtcNow).ShouldBeTrue();
    }

    [Fact]
    public void Verify_WithASignerThatExpiredAfterTheToken_IsValid()
    {
        // Arrange: valid from 10 to 5 days ago; the token was made 7 days ago.
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using X509Certificate2 signer = _evidence.Issue(now.AddDays(-10), now.AddDays(-5));

        // Act
        ExportVerification result = TestEvidence.Verify(
            _evidence.Package(p => p with { Token = TestEvidence.Token(Convert.FromHexString(p.Document.Seal!.Root), signer, now.AddDays(-7)) }),
            _evidence.Trust);

        // Assert
        result.Outcome.ShouldBe(ExportVerification.Valid, $"{result.FailedCheck}: {result.Reason}");
    }

    [Fact]
    public void Verify_WithASignerNotYetValidAtTheTokensTime_FailsTrust()
    {
        // Arrange
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using X509Certificate2 signer = _evidence.Issue(now.AddDays(1), now.AddYears(1));

        // Act and assert: .NET's token check refuses it already; the trust check would again.
        FailsAtOneOf([ExportChecks.Timestamp, ExportChecks.Trust], p => p with { Token = TestEvidence.Token(Convert.FromHexString(p.Document.Seal!.Root), signer) });
    }

    [Fact]
    public void Verify_WithAnOriginalUnderAnotherName_FailsTheManifest() =>
        FailsAt(ExportChecks.Manifest, p => p with { Contents = [p.Contents[0] with { Name = "receipt.exe" }] });

    [Fact]
    public void Verify_WithASealButNoToken_FailsThePackage() =>
        FailsAt(ExportChecks.Package, p => p with { Token = null });

    [Fact]
    public void Verify_WithAProofHashMissing_FailsThePackage() =>
        FailsAt(ExportChecks.Package, p => p with { Document = p.Document with { Seal = p.Document.Seal! with { Proof = [null!] } } });

    [Theory]
    [InlineData("originals/01-invoice.pdf")]
    [InlineData("originals/1-..\\invoice.pdf")]
    public void Verify_WithANonCanonicalOriginalName_FailsThePackage(string name)
    {
        // Act
        ExportVerification result = TestEvidence.Verify(TestEvidence.WithEntry(_evidence.Package(), name, "x"u8.ToArray()), _evidence.Trust);

        // Assert
        result.FailedCheck.ShouldBe(ExportChecks.Package);
    }

    [Fact]
    public void Verify_WithNoTrustAnchors_FailsTrust()
    {
        // Act
        ExportVerification result = TestEvidence.Verify(_evidence.Package(), []);

        // Assert
        result.FailedCheck.ShouldBe(ExportChecks.Trust);
    }

    [Fact]
    public void Verify_WithAnEntryFormat1DoesntName_FailsThePackage()
    {
        // Act
        ExportVerification result = TestEvidence.Verify(TestEvidence.WithEntry(_evidence.Package(), "note.txt", "trust me"u8.ToArray()), _evidence.Trust);

        // Assert
        result.FailedCheck.ShouldBe(ExportChecks.Package);
    }

    [Fact]
    public void Verify_WithATokenButNoSeal_FailsThePackage() =>
        FailsAt(ExportChecks.Package, p => p with { Document = p.Document with { Seal = null } });

    [Fact]
    public void Verify_OfSomethingThatIsNoZip_FailsThePackage()
    {
        // Act
        ExportVerification result = TestEvidence.Verify("not a zip"u8.ToArray(), _evidence.Trust);

        // Assert
        result.Outcome.ShouldBe(ExportVerification.Invalid);
        result.FailedCheck.ShouldBe(ExportChecks.Package);
    }

    [Theory]
    [InlineData("../../etc/passwd", "originals/1-_.._etc_passwd")]
    [InlineData("C:\\Windows\\win.ini", "originals/1-C__Windows_win.ini")]
    [InlineData("faktura æøå.pdf", "originals/1-faktura ___.pdf")]
    [InlineData("...", "originals/1-file")]
    public void OriginalEntry_KeepsNamesInsideTheOriginalsFolder(string name, string entry)
    {
        // Act and assert
        ExportPackage.OriginalEntry(1, name).ShouldBe(entry);
        ExportPackage.OriginalNumber(entry).ShouldBe(1);
    }

    private static byte[] Flip(byte[] bytes, int index)
    {
        byte[] changed = [.. bytes];
        changed[index] ^= 1;
        return changed;
    }

    private void FailsAtOneOf(string[] checks, Func<TestEvidence.Parts, TestEvidence.Parts> change)
    {
        // Act
        ExportVerification result = TestEvidence.Verify(_evidence.Package(change), _evidence.Trust);

        // Assert
        result.Outcome.ShouldBe(ExportVerification.Invalid);
        result.FailedCheck.ShouldBeOneOf(checks);
    }

    private void FailsAt(string check, Func<TestEvidence.Parts, TestEvidence.Parts> change)
    {
        // Act
        ExportVerification result = TestEvidence.Verify(_evidence.Package(change), _evidence.Trust);

        // Assert
        result.Outcome.ShouldBe(ExportVerification.Invalid);
        result.FailedCheck.ShouldBe(check);
        result.Reason.ShouldNotBeNullOrWhiteSpace();
    }
}
