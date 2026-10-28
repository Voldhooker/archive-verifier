namespace Archive.Evidence.Audit;

/// <summary>
/// Checks one tenant's audit log, fed entry by entry in sequence order, so a long log is never held in memory. Each
/// entry's content hash is rebuilt from its fields, and each chain hash from the one before: a changed field, a changed
/// hash, a removed entry or two swapped entries all show at the first entry they touch. Anchored heads (ADR 0008) are checked
/// too: a chain rewritten with every hash recomputed still differs from the head an anchor holds. The server's checks
/// and the offline verifier run this same code.
/// </summary>
public sealed class AuditLogChain
{
    private readonly SortedDictionary<long, List<byte[]>> _anchored = [];
    private byte[] _previous = AuditHashes.Genesis.ToArray();
    private long _last;

    /// <summary>How many entries were fed in.</summary>
    public long Entries { get; private set; }

    /// <summary>The newest entry that checked out, or the anchored entry the check started after.</summary>
    public long? HeadSequence { get; private set; }

    public byte[]? HeadHash { get; private set; }

    /// <summary>The sequence of the first entry that doesn't fit, or that an anchor holds otherwise; null while intact.</summary>
    public long? BrokenAt { get; private set; }

    public bool Intact => BrokenAt is null;

    /// <summary>How many anchored heads the chain was held to.</summary>
    public int AnchorsChecked { get; private set; }

    /// <summary>
    /// A check that starts after an entry an anchor vouches for, fed only the entries after it: the stretch since the
    /// last anchor, which the anchorer checks before it vouches for more.
    /// </summary>
    public static AuditLogChain After(long sequence, byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(hash);
        return new AuditLogChain { _previous = hash, _last = sequence, HeadSequence = sequence, HeadHash = hash };
    }

    /// <summary>
    /// Holds the chain to an anchor's head: the entry at <paramref name="sequence"/> must exist and have
    /// <paramref name="hash"/>. Every anchor naming a sequence must agree, so a second anchor can never stand in for one.
    /// </summary>
    /// <remarks>
    /// An anchor that failed its own checks is held with an empty hash, which no entry has. A head at or before the
    /// entry a check starts after (<see cref="After"/>) was vouched for already and is not held again.
    /// </remarks>
    public void Anchored(long sequence, byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(hash);
        if (sequence <= _last)
        {
            return;
        }

        if (!_anchored.TryGetValue(sequence, out List<byte[]>? hashes))
        {
            _anchored[sequence] = hashes = [];
        }

        hashes.Add(hash);
    }

    /// <returns>Whether the chain is still intact after this entry. Entries after a break are counted, not checked.</returns>
    public bool Add(AuditRecord entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        Entries++;
        if (!Intact)
        {
            return false;
        }

        byte[] content = AuditHashes.ContentHash(entry.TenantId, entry.At, entry.Actor, entry.Action, entry.Target, entry.Outcome, entry.CorrelationId);
        bool fits = entry.Sequence == _last + 1
            && content.AsSpan().SequenceEqual(entry.ContentHash)
            && AuditHashes.Link(_previous, content).AsSpan().SequenceEqual(entry.Hash);
        if (fits && _anchored.Remove(entry.Sequence, out List<byte[]>? anchored))
        {
            AnchorsChecked += anchored.Count;
            fits = anchored.TrueForAll(hash => hash.AsSpan().SequenceEqual(entry.Hash));
        }

        if (!fits)
        {
            BrokenAt = entry.Sequence;
            return false;
        }

        _previous = entry.Hash;
        _last = entry.Sequence;
        HeadSequence = entry.Sequence;
        HeadHash = entry.Hash;
        return true;
    }

    /// <summary>
    /// Ends the check once every entry was fed in. An anchored head beyond the last entry means entries were removed:
    /// the chain breaks at the first such head.
    /// </summary>
    public AuditLogChain Complete()
    {
        if (Intact && _anchored.Count > 0)
        {
            BrokenAt = _anchored.Keys.First();
        }

        return this;
    }
}
