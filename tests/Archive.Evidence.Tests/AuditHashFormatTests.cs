using Archive.Evidence.Audit;
using Archive.Evidence.Sealing;
using Shouldly;

namespace Archive.Evidence.Tests;

/// <summary>
/// The audit log's hashes are a contract with every chain ever stored (ADR 0008), and with every export set's verifier
/// (ADR 0012). These vectors were computed outside .NET from the documented layout: any change to the code that makes
/// them fail breaks every stored chain.
/// </summary>
public sealed class AuditHashFormatTests
{
    private static readonly Guid Tenant = Guid.Parse("0199e9a0-0000-7000-8000-0000000000b1");
    private static readonly DateTimeOffset At = new(2026, 10, 27, 9, 15, 30, 123, 456, TimeSpan.Zero);

    [Fact]
    public void ContentHashes_MatchTheVectors()
    {
        // Act
        byte[][] hashes =
        [
            AuditHashes.ContentHash(Tenant, At, "system:ingest", "CommitRecord", "record/0199e9a0-0000-7000-8000-0000000000bb", "succeeded", "4bf92f3577b34da6a3ce929d0e0e4736"),
            AuditHashes.ContentHash(Tenant, At, "5d1c7a0e-6b2f-4c1a-9e1d-000000000001", "SearchRecords", null, "refused:429", null),
            AuditHashes.ContentHash(Tenant, new DateTimeOffset(1999, 12, 31, 23, 59, 59, 999, 999, TimeSpan.Zero), "æøå-person", "Håndtér", "legal-hold/x", "failed:timeout", string.Empty),
        ];

        // Assert: an empty string and null differ (length 0 against -1).
        hashes.Select(Convert.ToHexStringLower).ShouldBe(
        [
            "4509217dc652e9f79bdd65286c4165498fca307a9ffe04ae8ad4aa93d9216fc9",
            "c198849e98913a7edd331d7ed4cc789712379b47f8206caf88743a1413712847",
            "bdc31950fc5bec0a9f0ba6568b49fdaa58b86601808c0603d4f108e10758e844",
        ]);
    }

    [Fact]
    public void ChainLinks_FromGenesis_MatchTheVectors()
    {
        // Arrange
        byte[] first = Convert.FromHexString("4509217dc652e9f79bdd65286c4165498fca307a9ffe04ae8ad4aa93d9216fc9");
        byte[] second = Convert.FromHexString("c198849e98913a7edd331d7ed4cc789712379b47f8206caf88743a1413712847");

        // Act
        byte[] link1 = AuditHashes.Link(AuditHashes.Genesis, first);
        byte[] link2 = AuditHashes.Link(link1, second);

        // Assert
        Convert.ToHexStringLower(link1).ShouldBe("627830f941aa2010322577d997058bdb99ca4d95ecba3a7b46d59e16c8c45d02");
        Convert.ToHexStringLower(link2).ShouldBe("f393dde073eaadf3e3216e2344c6569b4ce25a64b9d56a6fd4531d6d5286f795");
    }

    [Fact]
    public void AnAnchorLeaf_MatchesTheVector()
    {
        // Arrange
        byte[] head = Convert.FromHexString("f393dde073eaadf3e3216e2344c6569b4ce25a64b9d56a6fd4531d6d5286f795");

        // Act
        byte[] leaf = AnchorLeaf.Of(Tenant, 42, head);

        // Assert
        Convert.ToHexStringLower(MerkleTree.LeafHash(leaf)).ShouldBe("66b02fb4e9a9cf28d3e9dc1f9624a68019a0b42aaa796aeef39a95a3f7b11044");
    }
}
