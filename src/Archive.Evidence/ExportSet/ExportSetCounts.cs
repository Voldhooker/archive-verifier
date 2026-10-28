namespace Archive.Evidence.ExportSet;

/// <summary>How many of each the set holds.</summary>
public sealed record ExportSetCounts(long Records, long Committed, long Sealed, long Erased, long Purged, long AuditEntries, long Anchors);
