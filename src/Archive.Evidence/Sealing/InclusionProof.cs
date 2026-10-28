namespace Archive.Evidence.Sealing;

/// <summary>
/// A record's proof (RFC 9162 §2.1.3): its leaf's place in the seal batch tree and the sibling hashes from the leaf up
/// to the root, lowest first.
/// </summary>
public sealed record InclusionProof(long LeafIndex, long TreeSize, IReadOnlyList<byte[]> Path)
{
    /// <summary>The path as stored: its hashes one after another, 32 bytes each.</summary>
    public byte[] PathBytes() => [.. Path.SelectMany(hash => hash)];

    public static InclusionProof FromStored(long leafIndex, long treeSize, byte[] pathBytes)
    {
        ArgumentNullException.ThrowIfNull(pathBytes);
        if (pathBytes.Length % MerkleTree.HashSize != 0)
        {
            throw new ArgumentException($"A stored path is a whole number of {MerkleTree.HashSize}-byte hashes.", nameof(pathBytes));
        }

        return new InclusionProof(leafIndex, treeSize, [.. pathBytes.Chunk(MerkleTree.HashSize)]);
    }
}
