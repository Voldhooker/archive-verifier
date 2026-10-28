namespace Archive.Evidence.Export;

/// <summary>A record's place in its seal batch: its RFC 9162 inclusion proof and the root the batch's token covers (ADR 0007).</summary>
/// <param name="Proof">The sibling hashes from the leaf up, lowest first.</param>
public sealed record ExportSeal(Guid SealBatchId, long LeafIndex, long TreeSize, IReadOnlyList<string> Proof, string Root);
