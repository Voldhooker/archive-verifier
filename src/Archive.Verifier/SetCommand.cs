using System.Globalization;
using System.Security.Cryptography.X509Certificates;

using Archive.Evidence.ExportSet;

namespace Archive.Verifier;

/// <summary>
/// <c>archive-verify set &lt;folder&gt; --trust &lt;ca.pem&gt; [--trust …]</c>: checks a whole export set offline (ADR 0012)
/// and prints one line per check.
/// </summary>
public static class SetCommand
{
    private const string UsageText = """
        Usage: archive-verify set <folder> --trust <certificate> [--trust <certificate> ...]

        Checks an Archive export set offline: every file against its manifest, every record's package, the audit log
        from its first entry, every daily anchor, and the catalogue against the log. Each --trust names a PEM or DER file
        with a timestamp provider's CA certificate. Exit codes: 0 valid, 1 invalid, 2 valid but not yet proven (records
        not sealed yet, or a log no anchor holds), 3 usage.
        """;

    public static int Run(string[] args, TextWriter output, TextWriter errors)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(errors);

        string? folder = null;
        X509Certificate2Collection trust = [];
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--trust" && i + 1 < args.Length)
            {
                if (!Certificates.TryLoad(args[++i], trust))
                {
                    errors.WriteLine($"Cannot read a certificate from {args[i]}.");
                    return VerifyCommand.Usage;
                }
            }
            else if (folder is null && !args[i].StartsWith('-'))
            {
                folder = args[i];
            }
            else
            {
                errors.WriteLine(UsageText);
                return VerifyCommand.Usage;
            }
        }

        if (folder is null || trust.Count == 0 || !Directory.Exists(folder))
        {
            errors.WriteLine(folder is not null && !Directory.Exists(folder) ? $"No such folder: {folder}" : UsageText);
            return VerifyCommand.Usage;
        }

        ExportSetVerification result = ExportSetVerifier.Verify(folder, trust);
        foreach (SetCheck check in result.Checks)
        {
            output.WriteLine($"  {(check.Passed ? "ok    " : "FAILED")}  {check.Name}: {Printable(check.Detail)}");
        }

        string anchored = result.AnchoredTo is { } to
            ? string.Create(CultureInfo.InvariantCulture, $"the audit log up to entry {to} at {result.AnchoredAt:O}, when its newest anchor was stamped; the entries after it rest on the chain alone")
            : "the audit log has no anchor yet";
        switch (result.Outcome)
        {
            case ExportSetVerification.Valid:
                output.WriteLine(string.Create(CultureInfo.InvariantCulture, $"VALID: {result.Records} records, {result.AuditEntries} audit entries and {result.Anchors} anchors check out."));
                output.WriteLine($"        The originals existed exactly like this when each was sealed, and {anchored}.");
                return VerifyCommand.Valid;
            case ExportSetVerification.NotYetProven:
                output.WriteLine(string.Create(
                    CultureInfo.InvariantCulture,
                    $"VALID, NOT YET PROVEN: the set is whole, but {result.Unsealed} records aren't sealed yet, and {anchored}. Export again later."));
                return VerifyCommand.Unsealed;
            default:
                output.WriteLine("INVALID: see the failed checks above.");
                return VerifyCommand.Invalid;
        }
    }

    /// <summary>A detail as the terminal may show it: the set is untrusted, so no control character reaches it.</summary>
    private static string Printable(string text) => new([.. text.Select(c => char.IsControl(c) ? '?' : c)]);
}
