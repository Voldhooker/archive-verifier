namespace Archive.Evidence.ExportSet;

/// <summary>What the set verifier found: each check in order, and the outcome.</summary>
/// <param name="Outcome"><see cref="Valid"/>, <see cref="NotYetProven"/> or <see cref="Invalid"/>.</param>
/// <param name="Unsealed">How many packages are whole but not sealed yet.</param>
/// <param name="AnchoredTo">The newest audit entry an anchor holds; null when no anchor does. Entries after it rest on the chain alone.</param>
/// <param name="AnchoredAt">When that anchor was stamped.</param>
public sealed record ExportSetVerification(
    string Outcome, IReadOnlyList<SetCheck> Checks, long Records, long Unsealed, long AuditEntries, int Anchors, long? AnchoredTo, DateTimeOffset? AnchoredAt)
{
    /// <summary>Every check passed, every record is sealed and the log is anchored.</summary>
    public const string Valid = "valid";

    /// <summary>
    /// Every check passed, but some records aren't sealed yet, or no anchor holds the log: their time is not proven, and a
    /// log no anchor holds could have been rewritten with every hash recomputed.
    /// </summary>
    public const string NotYetProven = "unproven";

    public const string Invalid = "invalid";
}
