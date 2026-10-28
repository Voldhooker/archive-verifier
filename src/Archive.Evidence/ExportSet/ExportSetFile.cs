namespace Archive.Evidence.ExportSet;

/// <param name="Path">Relative to the set's folder, with forward slashes.</param>
public sealed record ExportSetFile(string Path, string Sha256, long Size);
