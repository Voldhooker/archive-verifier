using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Archive.Evidence.Sealing;

/// <summary>
/// Checks a stored RFC 3161 token: it decodes, covers the hash, and its signature checks against the certificate in
/// it. <see cref="Trusts"/> also decides whether that certificate belongs to a trusted provider, which only a verifier
/// with its trust anchors can.
/// </summary>
public static class TimestampTokenCheck
{
    /// <summary>The time-stamping key usage (RFC 3161 §2.3) a provider's certificate must carry.</summary>
    public const string TimeStampingUsage = "1.3.6.1.5.5.7.3.8";

    /// <param name="stampedAt">The time in the token, when it decodes.</param>
    public static bool Covers(byte[] token, byte[] sha256, out DateTimeOffset stampedAt) =>
        Covers(token, sha256, out stampedAt, out _);

    /// <param name="stampedAt">The time in the token, when it decodes.</param>
    /// <param name="signer">The certificate whose key signed the token, when the signature checks.</param>
    public static bool Covers(byte[] token, byte[] sha256, out DateTimeOffset stampedAt, out X509Certificate2? signer)
    {
        ArgumentNullException.ThrowIfNull(token);
        stampedAt = default;
        signer = null;
        try
        {
            if (!Rfc3161TimestampToken.TryDecode(token, out Rfc3161TimestampToken? decoded, out int read) || read != token.Length)
            {
                return false;
            }

            stampedAt = decoded.TokenInfo.Timestamp;
            return decoded.TokenInfo.GetMessageHash().Span.SequenceEqual(sha256)
                && decoded.VerifySignatureForHash(sha256, HashAlgorithmName.SHA256, out signer, extraCandidates: null);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// Whether <paramref name="signer"/> chains to one of <paramref name="anchors"/>, with the time-stamping usage, as
    /// things stood at <paramref name="at"/>, the token's time: a provider's certificate that expired since still vouches
    /// for what it signed while valid. Offline, so revocation is not checked.
    /// </summary>
    /// <param name="intermediates">Certificates the token carries, which may complete the chain.</param>
    public static bool Trusts(X509Certificate2 signer, X509Certificate2Collection anchors, X509Certificate2Collection intermediates, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(anchors);
        if (anchors.Count == 0 || !HasTimeStampingUsage(signer))
        {
            return false;
        }

        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(anchors);
        chain.ChainPolicy.ExtraStore.AddRange(intermediates);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = at.UtcDateTime;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(TimeStampingUsage));
        return chain.Build(signer);
    }

    /// <summary>
    /// Whether the certificate names the time-stamping usage itself (RFC 3161 §2.3). A chain check alone would let a
    /// certificate with no usage list through, since that means any usage.
    /// </summary>
    public static bool HasTimeStampingUsage(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .Any(usage => usage.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == TimeStampingUsage));
    }

    /// <summary>The certificates a token carries, for <see cref="Trusts"/>.</summary>
    public static X509Certificate2Collection CertificatesIn(byte[] token)
    {
        SignedCms cms = new();
        cms.Decode(token);
        return cms.Certificates;
    }
}
