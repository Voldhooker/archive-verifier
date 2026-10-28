namespace Archive.Evidence.ExportSet;

/// <summary>
/// One daily anchor as a set holds it (ADR 0008): the tenant's head in it, that head's inclusion proof to the anchor's
/// root, and the root. Only this tenant's leaf and proof, never another tenant's head. The anchor's RFC 3161 token is
/// beside it, as <c>&lt;id&gt;.tsr</c>, DER, so tools other than ours can read it too.
/// </summary>
/// <param name="Root">The RFC 9162 root over every tenant's head that day, hex: what the token covers.</param>
/// <param name="TreeSize">How many tenants' heads the tree holds.</param>
/// <param name="Path">The sibling hashes from the leaf up, hex.</param>
/// <param name="HeadHash">The tenant's chain hash at <paramref name="Sequence"/>, hex.</param>
public sealed record AnchorProof(
    Guid AnchorId,
    DateTimeOffset StampedAt,
    string Root,
    long TreeSize,
    long LeafIndex,
    IReadOnlyList<string> Path,
    Guid TenantId,
    long Sequence,
    string HeadHash);
