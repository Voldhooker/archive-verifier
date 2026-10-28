using System.Security.Cryptography;

namespace Archive.Evidence.Sealing;

/// <summary>
/// The Merkle tree hash and inclusion proofs of RFC 9162 §2.1 over SHA-256, the seal batch tree of ADR 0007. A leaf
/// hashes as SHA-256(0x00 ‖ data) and a node as SHA-256(0x01 ‖ left ‖ right), so a leaf can never pass as a node. A
/// level with an odd count carries its last hash up unchanged, which builds the same tree as the RFC's split at the
/// largest power of two below the count: no hash is ever duplicated.
/// </summary>
public static class MerkleTree
{
    public const int HashSize = 32;

    private const byte LeafPrefix = 0x00;
    private const byte NodePrefix = 0x01;

    public static byte[] LeafHash(ReadOnlySpan<byte> data)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData([LeafPrefix]);
        hash.AppendData(data);
        return hash.GetHashAndReset();
    }

    public static byte[] NodeHash(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData([NodePrefix]);
        hash.AppendData(left);
        hash.AppendData(right);
        return hash.GetHashAndReset();
    }

    /// <summary>Builds the tree over <paramref name="leaves"/>, each the data of one leaf, in leaf order.</summary>
    /// <returns>The root and each leaf's inclusion proof, in leaf order.</returns>
    public static (byte[] Root, IReadOnlyList<InclusionProof> Proofs) Build(IReadOnlyList<byte[]> leaves)
    {
        ArgumentNullException.ThrowIfNull(leaves);
        ArgumentOutOfRangeException.ThrowIfZero(leaves.Count);

        List<byte[][]> levels = [[.. leaves.Select(leaf => LeafHash(leaf))]];
        while (levels[^1].Length > 1)
        {
            byte[][] below = levels[^1];
            byte[][] level = new byte[(below.Length + 1) / 2][];
            for (int i = 0; i < level.Length; i++)
            {
                int left = 2 * i;
                level[i] = left + 1 < below.Length ? NodeHash(below[left], below[left + 1]) : below[left];
            }

            levels.Add(level);
        }

        InclusionProof[] proofs = new InclusionProof[leaves.Count];
        for (int leaf = 0; leaf < proofs.Length; leaf++)
        {
            List<byte[]> path = [];
            int index = leaf;
            foreach (byte[][] level in levels.Take(levels.Count - 1))
            {
                // A left node's sibling is to its right, if it has one; a lone last node is carried up without one.
                int sibling = index % 2 == 1 ? index - 1 : index + 1;
                if (sibling < level.Length)
                {
                    path.Add(level[sibling]);
                }

                index /= 2;
            }

            proofs[leaf] = new InclusionProof(leaf, leaves.Count, path);
        }

        return (levels[^1][0], proofs);
    }

    /// <summary>The verification of RFC 9162 §2.1.3.2: whether <paramref name="proof"/> leads from the leaf to <paramref name="root"/>.</summary>
    /// <param name="leafData">The leaf's data, such as a record's ciphertext hash; it is hashed as a leaf here.</param>
    public static bool Verify(ReadOnlySpan<byte> leafData, InclusionProof proof, ReadOnlySpan<byte> root)
    {
        ArgumentNullException.ThrowIfNull(proof);
        if (proof.LeafIndex < 0 || proof.LeafIndex >= proof.TreeSize)
        {
            return false;
        }

        long fn = proof.LeafIndex;
        long sn = proof.TreeSize - 1;
        byte[] r = LeafHash(leafData);
        foreach (byte[] p in proof.Path)
        {
            if (sn == 0 || p.Length != HashSize)
            {
                return false;
            }

            if ((fn & 1) == 1 || fn == sn)
            {
                r = NodeHash(p, r);
                while ((fn & 1) == 0 && fn != 0)
                {
                    fn >>= 1;
                    sn >>= 1;
                }
            }
            else
            {
                r = NodeHash(r, p);
            }

            fn >>= 1;
            sn >>= 1;
        }

        return sn == 0 && r.AsSpan().SequenceEqual(root);
    }
}
