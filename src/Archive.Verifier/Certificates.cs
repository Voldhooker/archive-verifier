using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Archive.Verifier;

/// <summary>The timestamp providers' CA certificates a caller names with <c>--trust</c>.</summary>
internal static class Certificates
{
    /// <summary>Adds the certificates in a PEM file, or the one in a DER file.</summary>
    public static bool TryLoad(string path, X509Certificate2Collection trust)
    {
        if (!File.Exists(path))
        {
            return false;
        }

        try
        {
            int before = trust.Count;
            trust.ImportFromPemFile(path);
            if (trust.Count > before)
            {
                return true;
            }

            trust.Add(X509CertificateLoader.LoadCertificateFromFile(path));
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
