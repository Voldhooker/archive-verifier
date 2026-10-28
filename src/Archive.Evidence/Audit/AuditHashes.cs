using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Archive.Evidence.Audit;

/// <summary>
/// The audit log's hashes (ADR 0008): one entry's content hash, and the link that chains it to the entry before.
/// The server writes them and the verifier rebuilds them with this same code, so the two can never disagree. Their
/// output is a contract with every chain ever stored: it never changes; a new layout is a new format byte.
/// </summary>
public static class AuditHashes
{
    /// <summary>The layout <see cref="ContentHash"/> hashes.</summary>
    public const byte ContentFormat = 1;

    /// <summary>What comes before the first entry: 32 zero bytes.</summary>
    public static ReadOnlySpan<byte> Genesis => new byte[32];

    /// <summary>
    /// SHA-256 over format 1: the byte 1; the tenant id as 16 bytes, big-endian (RFC 9562 order); the time as
    /// microseconds since the Unix epoch, a big-endian int64; then actor, action, target, outcome and correlation id,
    /// each as a big-endian int32 byte length (-1 for null) followed by its UTF-8 bytes.
    /// </summary>
    public static byte[] ContentHash(
        Guid tenantId, DateTimeOffset at, string actor, string action, string? target, string outcome, string? correlationId)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> number = stackalloc byte[8];
        hash.AppendData([ContentFormat]);
        hash.AppendData(tenantId.ToByteArray(bigEndian: true));
        BinaryPrimitives.WriteInt64BigEndian(number, (at.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / TimeSpan.TicksPerMicrosecond);
        hash.AppendData(number);
        foreach (string? field in (string?[])[actor, action, target, outcome, correlationId])
        {
            byte[]? bytes = field is null ? null : Encoding.UTF8.GetBytes(field);
            BinaryPrimitives.WriteInt32BigEndian(number[..4], bytes?.Length ?? -1);
            hash.AppendData(number[..4]);
            hash.AppendData(bytes ?? []);
        }

        return hash.GetHashAndReset();
    }

    /// <summary>An entry's chain hash: SHA-256(the previous entry's hash ‖ its content hash), as the database sets it.</summary>
    public static byte[] Link(ReadOnlySpan<byte> previousHash, ReadOnlySpan<byte> contentHash)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(previousHash);
        hash.AppendData(contentHash);
        return hash.GetHashAndReset();
    }
}
