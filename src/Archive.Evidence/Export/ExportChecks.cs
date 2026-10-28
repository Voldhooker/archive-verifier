namespace Archive.Evidence.Export;

/// <summary>The verifier's checks, in the order it runs them (ADR 0009). Each name is what a failure reports.</summary>
public static class ExportChecks
{
    /// <summary>The zip and <c>export.json</c> are format 1, with nothing in it the format doesn't name.</summary>
    public const string Package = "package";

    /// <summary>The SHA-256 of <c>object.bin</c> is the one <c>export.json</c> names.</summary>
    public const string CiphertextHash = "ciphertext-hash";

    /// <summary><c>object.bin</c> decrypts with the data key, for the record id (its GCM tag covers the header).</summary>
    public const string Decryption = "decryption";

    /// <summary>The decrypted package names the record, its originals match the manifest's hashes, and the loose files match it.</summary>
    public const string Manifest = "manifest";

    /// <summary>The ciphertext hash, as a leaf, leads through the proof to the root.</summary>
    public const string Proof = "proof";

    /// <summary>The token covers the root, and its signature checks against the certificate in it.</summary>
    public const string Timestamp = "timestamp";

    /// <summary>The token's signer chains to a trusted certificate with the time-stamping usage, at the token's time.</summary>
    public const string Trust = "trust";
}
