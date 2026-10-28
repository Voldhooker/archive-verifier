using System.Security.Cryptography;
using System.Text;

using Archive.Evidence.Packaging;
using Shouldly;

namespace Archive.Evidence.Tests;

public sealed class PackageCipherTests
{
    private static readonly Guid RecordId = Guid.Parse("0199e9a0-0000-7000-8000-0000000000aa");
    private static readonly byte[] Package = Encoding.ASCII.GetBytes("a package that is not really a tar");
    private static readonly byte[] Key = RandomNumberGenerator.GetBytes(32);

    [Fact]
    public void Encrypt_ThenDecrypt_ReturnsThePackage()
    {
        // Act
        byte[] stored = PackageCipher.Encrypt(Package, Key, RecordId);
        byte[] package = PackageCipher.Decrypt(stored, Key, RecordId);

        // Assert
        package.ShouldBe(Package);
        stored.Length.ShouldBe(PackageCipher.HeaderSize + Package.Length + 16);
    }

    [Fact]
    public void Encrypt_WritesTheDocumentedHeader()
    {
        // Act
        byte[] stored = PackageCipher.Encrypt(Package, Key, RecordId);

        // Assert: ARCHIVE, format 1, AES-256-GCM, 12-byte nonce, record id in RFC 4122 order (ADR 0006).
        Encoding.ASCII.GetString(stored, 0, 7).ShouldBe("ARCHIVE");
        stored[7].ShouldBe((byte)1);
        stored[8].ShouldBe((byte)1);
        new Guid(stored.AsSpan(21, 16), bigEndian: true).ShouldBe(RecordId);
    }

    [Fact]
    public void Encrypt_TwiceWithOneKey_UsesFreshNonces()
    {
        // Act
        byte[] first = PackageCipher.Encrypt(Package, Key, RecordId);
        byte[] second = PackageCipher.Encrypt(Package, Key, RecordId);

        // Assert
        second.AsSpan(9, 12).SequenceEqual(first.AsSpan(9, 12)).ShouldBeFalse();
    }

    [Fact]
    public void Decrypt_WithWrongKey_Fails()
    {
        // Arrange
        byte[] stored = PackageCipher.Encrypt(Package, Key, RecordId);

        // Act and assert
        Should.Throw<AuthenticationTagMismatchException>(() => PackageCipher.Decrypt(stored, RandomNumberGenerator.GetBytes(32), RecordId));
    }

    [Theory]
    [InlineData(9)] // a nonce byte
    [InlineData(40)] // a ciphertext byte
    [InlineData(-1)] // the last tag byte
    public void Decrypt_WithAnyByteChanged_Fails(int position)
    {
        // Arrange
        byte[] stored = PackageCipher.Encrypt(Package, Key, RecordId);
        stored[position < 0 ? stored.Length + position : position] ^= 0x01;

        // Act and assert
        Should.Throw<AuthenticationTagMismatchException>(() => PackageCipher.Decrypt(stored, Key, RecordId));
    }

    [Fact]
    public void Decrypt_UnderAnotherRecordId_Fails()
    {
        // Arrange
        byte[] stored = PackageCipher.Encrypt(Package, Key, RecordId);

        // Act and assert: an object copied onto another record is refused before decryption.
        Should.Throw<InvalidDataException>(() => PackageCipher.Decrypt(stored, Key, Guid.CreateVersion7()));
    }

    [Fact]
    public void Decrypt_WithUnknownFormat_Fails()
    {
        // Arrange
        byte[] stored = PackageCipher.Encrypt(Package, Key, RecordId);
        stored[7] = 2;

        // Act and assert
        Should.Throw<InvalidDataException>(() => PackageCipher.Decrypt(stored, Key, RecordId)).Message.ShouldContain("format 2");
    }
}
