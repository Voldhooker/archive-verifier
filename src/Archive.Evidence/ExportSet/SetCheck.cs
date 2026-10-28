namespace Archive.Evidence.ExportSet;

/// <param name="Detail">What was checked, or why it failed, for a person.</param>
public sealed record SetCheck(string Name, bool Passed, string Detail);
