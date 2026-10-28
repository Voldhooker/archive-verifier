using Archive.Evidence.Audit;
using Shouldly;

namespace Archive.Evidence.Tests;

/// <summary>The audit log's chain check (ADR 0008), which the server and the export set's verifier both run.</summary>
public sealed class AuditLogChainTests
{
    private static readonly Guid TenantId = Guid.Parse("0199e9a0-0000-7000-8000-000000000001");
    private static readonly DateTimeOffset At = new(2026, 10, 21, 9, 30, 0, 123, 456, TimeSpan.Zero);

    [Fact]
    public void Add_AnIntactChain_EndsIntactAtItsHead()
    {
        // Arrange
        AuditRecord[] entries = Chained("a", "b", "c");
        AuditLogChain chain = new();

        // Act
        bool intact = entries.All(chain.Add);

        // Assert
        intact.ShouldBeTrue();
        chain.Complete().Intact.ShouldBeTrue();
        (chain.Entries, chain.HeadSequence).ShouldBe((3, 3));
        chain.HeadHash.ShouldBe(entries[2].Hash);
    }

    [Fact]
    public void Add_AnEntryWhoseFieldChanged_BreaksAtThatEntry()
    {
        // Arrange: entry 2's outcome rewritten after the fact, its hashes left as they were.
        AuditRecord[] entries = Chained("a", "b", "c");
        entries[1] = entries[1] with { Outcome = "refused:404" };

        // Act and assert
        BrokenAt(entries).ShouldBe(2);
    }

    [Fact]
    public void Add_AnEntryWhoseHashChanged_BreaksAtThatEntry()
    {
        // Arrange: the fields and content hash left alone, the chain hash replaced.
        AuditRecord[] entries = Chained("a", "b", "c");
        entries[1] = entries[1] with { Hash = entries[0].Hash };

        // Act and assert
        BrokenAt(entries).ShouldBe(2);
    }

    [Fact]
    public void Add_AnEntryRewrittenWithItsHashes_BreaksAtTheNextLink()
    {
        // Arrange: entry 2 rewritten consistently, both hashes included; entry 3 still links to the old one.
        AuditRecord[] entries = Chained("a", "b", "c");
        entries[1] = Chained("a", "forged")[1];

        // Act and assert
        BrokenAt(entries).ShouldBe(3);
    }

    [Fact]
    public void Add_WithAnEntryRemoved_BreaksAtTheGap()
    {
        // Arrange
        AuditRecord[] entries = Chained("a", "b", "c");

        // Act and assert
        BrokenAt([entries[0], entries[2]]).ShouldBe(3);
    }

    [Fact]
    public void Add_AnEntryWhoseSequenceSkips_BreaksAtIt()
    {
        // Arrange: entry 2 renumbered 3, its hashes intact, so only the sequence can tell.
        AuditRecord[] entries = Chained("a", "b");

        // Act and assert
        BrokenAt([entries[0], entries[1] with { Sequence = 3 }]).ShouldBe(3);
    }

    [Fact]
    public void Add_WithTwoEntriesSwapped_Breaks()
    {
        // Arrange: their sequences swapped too.
        AuditRecord[] entries = Chained("a", "b", "c");

        // Act and assert
        BrokenAt([entries[0], entries[2] with { Sequence = 2 }, entries[1] with { Sequence = 3 }]).ShouldBe(2);
    }

    [Fact]
    public void Add_AChainRewrittenWithEveryHashRecomputed_BreaksAtTheFirstAnchoredHeadAfterTheRewrite()
    {
        // Arrange: heads 2 and 4 anchored, then the chain rebuilt from entry 3 on, every hash consistent.
        AuditRecord[] original = Chained("a", "b", "c", "d", "e");
        AuditRecord[] rewritten = Chained("a", "b", "forged", "d", "e");
        AuditLogChain chain = new();
        chain.Anchored(2, original[1].Hash);
        chain.Anchored(4, original[3].Hash);

        // Act
        foreach (AuditRecord entry in rewritten)
        {
            chain.Add(entry);
        }

        // Assert: the walk alone finds nothing; the anchor at 4 does.
        BrokenAt(rewritten).ShouldBeNull();
        chain.Complete().BrokenAt.ShouldBe(4);
        chain.AnchorsChecked.ShouldBe(2);
    }

    [Fact]
    public void Complete_WithAnAnchoredHeadBeyondTheLastEntry_BreaksAtThatHead()
    {
        // Arrange: head 3 anchored, then entry 3 removed.
        AuditRecord[] entries = Chained("a", "b", "c");
        AuditLogChain chain = new();
        chain.Anchored(3, entries[2].Hash);

        // Act
        chain.Add(entries[0]);
        chain.Add(entries[1]);

        // Assert
        chain.Intact.ShouldBeTrue();
        chain.Complete().BrokenAt.ShouldBe(3);
    }

    [Fact]
    public void Anchored_ByAnInvalidAnchor_BreaksAtItsHead()
    {
        // Arrange: an anchor that failed its own checks holds its head with an empty hash.
        AuditRecord[] entries = Chained("a", "b");
        AuditLogChain chain = new();
        chain.Anchored(1, []);

        // Act and assert
        entries.All(chain.Add).ShouldBeFalse();
        chain.Complete().BrokenAt.ShouldBe(1);
    }

    [Fact]
    public void Anchored_ByTwoAnchorsThatDisagreeOnAHead_Breaks()
    {
        // Arrange: a true anchor and a planted one for the same head.
        AuditRecord[] entries = Chained("a", "b");
        AuditLogChain chain = new();
        chain.Anchored(2, entries[1].Hash);
        chain.Anchored(2, entries[0].Hash);

        // Act and assert
        entries.All(chain.Add).ShouldBeFalse();
        chain.Complete().BrokenAt.ShouldBe(2);
    }

    [Fact]
    public void After_AnAnchoredEntry_ChecksOnlyTheStretchSince()
    {
        // Arrange
        AuditRecord[] entries = Chained("a", "b", "c", "d");
        AuditRecord[] rewrittenBefore = Chained("a", "forged", "c", "d");

        // Act
        AuditLogChain since = AuditLogChain.After(2, entries[1].Hash);
        bool intact = entries[2..].All(since.Add);
        AuditLogChain afterRewrite = AuditLogChain.After(2, entries[1].Hash);
        afterRewrite.Add(rewrittenBefore[2]);

        // Assert: the stretch since checks out; a chain rewritten before the anchored entry no longer links to it.
        intact.ShouldBeTrue();
        since.Complete().HeadSequence.ShouldBe(4);
        afterRewrite.Complete().BrokenAt.ShouldBe(3);
    }

    /// <summary>Entries chained from the first, as the server writes them.</summary>
    private static AuditRecord[] Chained(params string[] actions)
    {
        byte[] previous = AuditHashes.Genesis.ToArray();
        AuditRecord[] entries = new AuditRecord[actions.Length];
        for (int i = 0; i < actions.Length; i++)
        {
            byte[] content = AuditHashes.ContentHash(TenantId, At, "subject-1", actions[i], null, "succeeded", null);
            previous = AuditHashes.Link(previous, content);
            entries[i] = new AuditRecord(TenantId, i + 1, At, "subject-1", actions[i], null, "succeeded", null, content, previous);
        }

        return entries;
    }

    private static long? BrokenAt(IEnumerable<AuditRecord> entries)
    {
        AuditLogChain chain = new();
        foreach (AuditRecord entry in entries)
        {
            chain.Add(entry);
        }

        return chain.BrokenAt;
    }
}
