using System.Buffers.Binary;

using Archive.Evidence.Sealing;

namespace Archive.Evidence.Audit;

/// <summary>
/// One tenant's place in a daily anchor (ADR 0008): its chain's head, as the leaf data of the anchor's Merkle tree.
/// The leaf names its tenant and its sequence, so a proof can't be moved to another tenant or another entry.
/// </summary>
public static class AnchorLeaf
{
    public const byte Format = 1;

    public const int Size = 1 + 16 + 8 + MerkleTree.HashSize;

    /// <summary>
    /// Format 1, 57 bytes: the byte 1; the tenant id as 16 bytes, big-endian (RFC 9562 order); the head's sequence as a
    /// big-endian int64; the head's hash, 32 bytes.
    /// </summary>
    public static byte[] Of(Guid tenantId, long sequence, byte[] headHash)
    {
        ArgumentNullException.ThrowIfNull(headHash);
        ArgumentOutOfRangeException.ThrowIfNotEqual(headHash.Length, MerkleTree.HashSize);
        ArgumentOutOfRangeException.ThrowIfLessThan(sequence, 1);
        byte[] leaf = new byte[Size];
        leaf[0] = Format;
        tenantId.TryWriteBytes(leaf.AsSpan(1, 16), bigEndian: true, out _);
        BinaryPrimitives.WriteInt64BigEndian(leaf.AsSpan(17, 8), sequence);
        headHash.CopyTo(leaf.AsSpan(25));
        return leaf;
    }
}
