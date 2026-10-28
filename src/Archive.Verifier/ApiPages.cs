using Archive.Evidence.ExportSet;

namespace Archive.Verifier;

/// <summary>The pages the export reads, as the archive's API answers them (ADR 0012).</summary>
internal static class ApiPages
{
    internal sealed record CataloguePage(IReadOnlyList<CatalogueLine> Records, Guid? Next);

    internal sealed record AuditPage(Guid TenantId, IReadOnlyList<AuditEntryLine> Entries, long? Next, long Head);

    internal sealed record AnchorsPage(IReadOnlyList<AnchorSummary> Anchors, Guid? Next);

    internal sealed record AnchorSummary(Guid Id, DateTimeOffset StampedAt, long Sequence);

    internal sealed record AnchorProofPage(AnchorProof Proof, string Token);

    internal sealed record ProfilesPage(IReadOnlyList<ProfileSummary> Profiles);

    /// <param name="Kind">statutory or custom.</param>
    internal sealed record ProfileSummary(string Kind, string? Country, string? Name);

    internal sealed record VersionsPage(IReadOnlyList<VersionSummary> Versions);

    internal sealed record VersionSummary(string Version);

    internal sealed record VersionFile(string Text);
}
