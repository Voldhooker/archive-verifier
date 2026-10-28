using System.Security.Cryptography;
using System.Text;

using Archive.Evidence.Sealing;
using Shouldly;

namespace Archive.Evidence.Tests;

public sealed class MerkleTreeTests
{
    // The leaves of the RFC 6962 reference test vectors (certificate-transparency), which RFC 9162's tree hash keeps.
    private static readonly byte[][] ReferenceLeaves =
    [
        [],
        [0x00],
        [0x10],
        [0x20, 0x21],
        [0x30, 0x31],
        [0x40, 0x41, 0x42, 0x43],
        [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
        [0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f]
    ];

    [Theory]
    [InlineData(1, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")]
    [InlineData(2, "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125")]
    [InlineData(3, "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77")]
    [InlineData(4, "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7")]
    [InlineData(5, "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4")]
    [InlineData(6, "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef")]
    [InlineData(7, "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c")]
    [InlineData(8, "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328")]
    public void Build_OverTheReferenceLeaves_GivesTheReferenceRoots(int size, string root)
    {
        // Act
        (byte[] built, _) = MerkleTree.Build(ReferenceLeaves[..size]);

        // Assert
        Convert.ToHexStringLower(built).ShouldBe(root);
    }

    [Theory]
    [InlineData(5, "5f8b6d7a1c69c5784e2966d821a0e05fa93f34e36ae59aca75fd6f294684b7c8")]
    [InlineData(17, "fe496a6fb84d64e6269888b4aa5a748e76d990a2411b4ef97e2d73b20ef7080a")]
    public void Build_OverHashLeaves_GivesTheRootComputedApart(int size, string root)
    {
        // The roots were computed in Python from RFC 9162's recursive definition, apart from this code.
        (byte[] built, _) = MerkleTree.Build(HashLeaves(size));

        Convert.ToHexStringLower(built).ShouldBe(root);
    }

    [Fact]
    public void Build_ForALeafCarriedUpALevel_GivesTheProofComputedApart()
    {
        // Act: leaf 4 of 7 has no sibling on the second level, so the lone node 6 is its sibling there.
        (_, IReadOnlyList<InclusionProof> proofs) = MerkleTree.Build(HashLeaves(7));

        // Assert
        proofs[4].Path.Select(Convert.ToHexStringLower).ShouldBe(
        [
            "f1b5e06afdecbb8a285afd9a008f479d91c2f1894b44bcd2db0264ca3e18189d",
            "e8745960918ae9ee5b61277ef81fc4759efa47d9b3c89edd14225a4b01724f40",
            "148466cbc58d477034e1ad9582c65a11d2c372f97c189927fa22f9f0dc0593eb"
        ]);
    }

    [Fact]
    public void Build_ForEveryTreeSizeUpTo17_GivesEveryLeafAProofThatVerifies()
    {
        for (int size = 1; size <= 17; size++)
        {
            // Act
            byte[][] leaves = HashLeaves(size);
            (byte[] root, IReadOnlyList<InclusionProof> proofs) = MerkleTree.Build(leaves);

            // Assert
            proofs.Count.ShouldBe(size);
            for (int leaf = 0; leaf < size; leaf++)
            {
                proofs[leaf].LeafIndex.ShouldBe(leaf);
                proofs[leaf].TreeSize.ShouldBe(size);
                MerkleTree.Verify(leaves[leaf], proofs[leaf], root).ShouldBeTrue($"leaf {leaf} of {size}");
            }
        }
    }

    [Fact]
    public void Verify_WithAChangedLeaf_Fails()
    {
        // Arrange
        byte[][] leaves = HashLeaves(9);
        (byte[] root, IReadOnlyList<InclusionProof> proofs) = MerkleTree.Build(leaves);
        byte[] changed = [.. leaves[3]];
        changed[0] ^= 1;

        // Act and assert
        MerkleTree.Verify(changed, proofs[3], root).ShouldBeFalse();
    }

    [Fact]
    public void Verify_WithAChangedPathHash_Fails()
    {
        // Arrange
        byte[][] leaves = HashLeaves(9);
        (byte[] root, IReadOnlyList<InclusionProof> proofs) = MerkleTree.Build(leaves);
        byte[][] path = [.. proofs[3].Path.Select(h => (byte[])[.. h])];
        path[1][31] ^= 1;

        // Act and assert
        MerkleTree.Verify(leaves[3], proofs[3] with { Path = path }, root).ShouldBeFalse();
    }

    [Theory]
    [InlineData(2, 9)]
    [InlineData(4, 9)]
    [InlineData(3, 8)]
    [InlineData(3, 17)]
    [InlineData(9, 9)]
    [InlineData(-1, 9)]
    public void Verify_WithAnotherIndexOrSize_Fails(long leafIndex, long treeSize)
    {
        // Arrange: the proof belongs to leaf 3 of 9. A size whose tree has the same shape on that leaf's path (10, say)
        // checks the same hashes, which is why the size a proof is checked against comes from its seal batch.
        byte[][] leaves = HashLeaves(9);
        (byte[] root, IReadOnlyList<InclusionProof> proofs) = MerkleTree.Build(leaves);

        // Act and assert
        MerkleTree.Verify(leaves[3], proofs[3] with { LeafIndex = leafIndex, TreeSize = treeSize }, root).ShouldBeFalse();
    }

    [Fact]
    public void Verify_ALeafHashPresentedAsALeaf_Fails()
    {
        // Arrange: the root of two leaves, then its node's children offered as if they were leaf data.
        byte[][] leaves = HashLeaves(4);
        (byte[] root, _) = MerkleTree.Build(leaves);
        byte[] left = MerkleTree.NodeHash(MerkleTree.LeafHash(leaves[0]), MerkleTree.LeafHash(leaves[1]));
        byte[] right = MerkleTree.NodeHash(MerkleTree.LeafHash(leaves[2]), MerkleTree.LeafHash(leaves[3]));

        // Act: a two-leaf proof claiming the inner node is a leaf.
        bool verified = MerkleTree.Verify(left, new InclusionProof(0, 2, [right]), root);

        // Assert: the leaf prefix keeps a node from passing as a leaf.
        verified.ShouldBeFalse();
    }

    [Fact]
    public void PathBytes_RoundTripThroughStorage()
    {
        // Arrange
        (_, IReadOnlyList<InclusionProof> proofs) = MerkleTree.Build(HashLeaves(13));

        // Act
        InclusionProof stored = InclusionProof.FromStored(proofs[5].LeafIndex, proofs[5].TreeSize, proofs[5].PathBytes());

        // Assert
        stored.Path.Select(Convert.ToHexString).ShouldBe(proofs[5].Path.Select(Convert.ToHexString));
    }

    /// <summary>Leaf i is SHA-256 of the ASCII text <c>leaf i</c>, as in the Python reference.</summary>
    private static byte[][] HashLeaves(int count) =>
        [.. Enumerable.Range(0, count).Select(i => SHA256.HashData(Encoding.ASCII.GetBytes($"leaf {i}")))];
}
