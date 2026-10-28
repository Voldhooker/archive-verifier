using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Archive.Evidence.Packaging;

/// <summary>
/// The stored object, format 1 (ADR 0006): a 37-byte header, then the package encrypted with AES-256-GCM, then the
/// 16-byte tag. The header is <c>ARCHIVE</c> (7 bytes ASCII), format version (1 byte), algorithm (1 byte, 1 =
/// AES-256-GCM), nonce (12 bytes) and the record id (16 bytes, RFC 4122 order). The whole header is associated data,
/// so an object copied onto another record's id, or with any header byte changed, fails to decrypt.
/// </summary>
public static class PackageCipher
{
    public const byte FormatVersion = 1;
    public const byte AesGcm256 = 1;
    public const int HeaderSize = MagicSize + 2 + NonceSize + 16;

    private const int MagicSize = 7;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;

    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("ARCHIVE");

    public static byte[] Encrypt(ReadOnlySpan<byte> package, ReadOnlySpan<byte> dataKey, Guid recordId)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(dataKey.Length, KeySize, nameof(dataKey));

        byte[] stored = new byte[HeaderSize + package.Length + TagSize];
        Span<byte> header = stored.AsSpan(0, HeaderSize);
        Magic.CopyTo(header);
        header[MagicSize] = FormatVersion;
        header[MagicSize + 1] = AesGcm256;
        RandomNumberGenerator.Fill(header.Slice(MagicSize + 2, NonceSize));
        recordId.TryWriteBytes(header[(MagicSize + 2 + NonceSize)..], bigEndian: true, out _);

        using AesGcm aes = new(dataKey, TagSize);
        aes.Encrypt(
            header.Slice(MagicSize + 2, NonceSize),
            package,
            stored.AsSpan(HeaderSize, package.Length),
            stored.AsSpan(HeaderSize + package.Length, TagSize),
            header);
        return stored;
    }

    /// <exception cref="InvalidDataException">The header is not format 1 for <paramref name="recordId"/>.</exception>
    /// <exception cref="AuthenticationTagMismatchException">The key is wrong, or the object was altered.</exception>
    public static byte[] Decrypt(ReadOnlySpan<byte> stored, ReadOnlySpan<byte> dataKey, Guid recordId)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(dataKey.Length, KeySize, nameof(dataKey));
        if (stored.Length < HeaderSize + TagSize || !stored[..MagicSize].SequenceEqual(Magic))
        {
            throw new InvalidDataException("Not an archive object.");
        }

        ReadOnlySpan<byte> header = stored[..HeaderSize];
        if (header[MagicSize] != FormatVersion || header[MagicSize + 1] != AesGcm256)
        {
            throw new InvalidDataException($"Object format {header[MagicSize]}, algorithm {header[MagicSize + 1]} is not one this version reads.");
        }

        if (new Guid(header[(MagicSize + 2 + NonceSize)..], bigEndian: true) != recordId)
        {
            throw new InvalidDataException("The object belongs to another record.");
        }

        int length = stored.Length - HeaderSize - TagSize;
        byte[] package = new byte[length];
        using AesGcm aes = new(dataKey, TagSize);
        aes.Decrypt(header.Slice(MagicSize + 2, NonceSize), stored.Slice(HeaderSize, length), stored[^TagSize..], package, header);
        return package;
    }
}
