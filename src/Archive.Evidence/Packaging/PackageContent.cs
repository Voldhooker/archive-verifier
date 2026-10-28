namespace Archive.Evidence.Packaging;

/// <summary>One original, unchanged, as it goes into a package or comes out of one.</summary>
public sealed record PackageContent(string Name, string MediaType, ReadOnlyMemory<byte> Bytes);
