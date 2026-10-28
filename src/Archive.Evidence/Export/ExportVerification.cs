namespace Archive.Evidence.Export;

/// <summary>What the verifier found.</summary>
/// <param name="Outcome"><see cref="Valid"/>, <see cref="Unsealed"/> or <see cref="Invalid"/>.</param>
/// <param name="Passed">The checks that passed, in order.</param>
/// <param name="FailedCheck">The first check that failed; null unless invalid.</param>
/// <param name="Reason">Why it failed, for a person; null unless invalid.</param>
/// <param name="SealedAt">The time in the seal batch's token; null unless valid.</param>
/// <param name="Provider">The subject of the certificate that signed the token; null unless valid.</param>
public sealed record ExportVerification(
    string Outcome,
    Guid? RecordId,
    IReadOnlyList<string> Passed,
    string? FailedCheck,
    string? Reason,
    DateTimeOffset? SealedAt,
    string? Provider)
{
    /// <summary>Every check passed: the record existed exactly like this at <see cref="SealedAt"/>.</summary>
    public const string Valid = "valid";

    /// <summary>The record is whole, but not sealed yet: its time is not proven.</summary>
    public const string Unsealed = "unsealed";

    public const string Invalid = "invalid";
}
