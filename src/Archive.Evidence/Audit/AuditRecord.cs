namespace Archive.Evidence.Audit;

/// <summary>One audit entry as a chain check reads it, from the database or from an export set's <c>audit/entries.jsonl</c>.</summary>
/// <param name="ContentHash">As stored: checked against the hash rebuilt from the fields.</param>
/// <param name="Hash">The chain hash as stored: checked against the link from the entry before.</param>
public sealed record AuditRecord(
    Guid TenantId,
    long Sequence,
    DateTimeOffset At,
    string Actor,
    string Action,
    string? Target,
    string Outcome,
    string? CorrelationId,
    byte[] ContentHash,
    byte[] Hash);
