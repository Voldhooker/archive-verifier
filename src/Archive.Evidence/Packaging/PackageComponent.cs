namespace Archive.Evidence.Packaging;

/// <param name="Path">The tar entry holding the bytes, such as <c>content/1</c>.</param>
/// <param name="Name">The name the submitter gave it.</param>
/// <param name="Sha256">Lower-case hex SHA-256 of the original bytes.</param>
public sealed record PackageComponent(string Path, string Name, string MediaType, long Size, string Sha256);
