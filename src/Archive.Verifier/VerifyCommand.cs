using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Archive.Evidence.Export;

namespace Archive.Verifier;

/// <summary>
/// <c>archive-verify &lt;package.zip&gt; --trust &lt;ca.pem&gt; [--trust …]</c>: checks an export package offline and
/// says whether the record existed exactly like this at its sealing time, signed by a provider the caller trusts.
/// </summary>
public static class VerifyCommand
{
    public const int Valid = 0;
    public const int Invalid = 1;
    public const int Unsealed = 2;
    public const int Usage = 3;

    private const string UsageText = """
        Usage: archive-verify [verify] <package.zip> --trust <certificate> [--trust <certificate> ...]
               archive-verify set <folder> --trust <certificate> [--trust <certificate> ...]
               archive-verify export --api <url> --token-url <url> --client-id <id> --out <folder> [--legal-entity <id>]

        Checks an Archive export package offline; set checks a whole export set (ADR 0012), and export pulls one. Each --trust names a PEM or DER file with the CA certificate a
        timestamp provider's certificate chains to; the token's signer must chain to one of them.
        Exit codes: 0 valid, 1 invalid, 2 not sealed yet, 3 usage.
        """;

    public static int Run(string[] args, TextWriter output, TextWriter errors)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(errors);

        string? package = null;
        X509Certificate2Collection trust = [];
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--trust" && i + 1 < args.Length)
            {
                string path = args[++i];
                if (!Certificates.TryLoad(path, trust))
                {
                    errors.WriteLine($"Cannot read a certificate from {path}.");
                    return Usage;
                }
            }
            else if (package is null && !args[i].StartsWith('-'))
            {
                package = args[i];
            }
            else
            {
                errors.WriteLine(UsageText);
                return Usage;
            }
        }

        if (package is null || trust.Count == 0)
        {
            errors.WriteLine(UsageText);
            return Usage;
        }

        if (!File.Exists(package))
        {
            errors.WriteLine($"No such file: {package}");
            return Usage;
        }

        ExportVerification result;
        using (FileStream stream = File.OpenRead(package))
        {
            result = ExportVerifier.Verify(stream, trust);
        }

        foreach (string check in result.Passed)
        {
            output.WriteLine($"  ok      {check}");
        }

        switch (result.Outcome)
        {
            case ExportVerification.Valid:
                output.WriteLine(string.Create(
                    CultureInfo.InvariantCulture, $"VALID: record {result.RecordId} existed exactly like this at {result.SealedAt:O}, sealed by {result.Provider}."));
                output.WriteLine("        This proves the originals and the manifest at that time. It doesn't prove who sealed them, nor policy.json or the export time.");
                return Valid;
            case ExportVerification.Unsealed:
                output.WriteLine($"UNSEALED: record {result.RecordId} is whole and unchanged, but not sealed yet, so its time is not proven.");
                return Unsealed;
            default:
                output.WriteLine($"  FAILED  {result.FailedCheck}: {result.Reason}");
                output.WriteLine($"INVALID: the {result.FailedCheck} check failed.");
                return Invalid;
        }
    }
}
