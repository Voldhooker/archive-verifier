using Archive.Evidence.Audit;

namespace Archive.Evidence.ExportSet;

/// <summary>One audit entry in a set's <c>audit/entries.jsonl</c>, oldest first: its fields, and both hashes in hex.</summary>
public sealed record AuditEntryLine(
    long Sequence,
    DateTimeOffset At,
    string Actor,
    string Action,
    string? Target,
    string Outcome,
    string? CorrelationId,
    string ContentHash,
    string Hash)
{
    /// <exception cref="FormatException">A hash is not hex.</exception>
    public AuditRecord ToRecord(Guid tenantId) => new(
        tenantId, Sequence, At, Actor, Action, Target, Outcome, CorrelationId, Convert.FromHexString(ContentHash), Convert.FromHexString(Hash));
}
