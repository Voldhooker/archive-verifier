using System.Globalization;
using System.Net.Http.Json;
using System.Text.Json;

namespace Archive.Verifier;

/// <summary>
/// <c>archive-verify export --api &lt;url&gt; --token-url &lt;url&gt; --client-id &lt;id&gt; --out &lt;folder&gt; [--legal-entity &lt;id&gt;]</c>:
/// pulls the tenant's export set (ADR 0012) with a service client holding the reader and auditor roles. The client
/// secret comes from the environment variable <see cref="SecretVariable"/>, never from the command line, where process
/// lists and shell histories would keep it.
/// </summary>
public static class ExportCommand
{
    public const string SecretVariable = "ARCHIVE_CLIENT_SECRET";

    private const string UsageText = """
        Usage: archive-verify export --api <url> --token-url <url> --client-id <id> --out <folder> [--legal-entity <id>]

        Pulls an Archive export set into <folder>: every record's package, the catalogue, the audit log and its anchors.
        The client signs in with client credentials at --token-url and needs the archive-reader and archive-auditor
        roles; its secret is read from the environment variable ARCHIVE_CLIENT_SECRET. Run it again with the same
        arguments to resume. Then check the set with: archive-verify set <folder> --trust <ca.pem>
        Exit codes: 0 finished, 1 finished with records whose package couldn't be fetched, 3 usage or failure.
        """;

    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter errors, CancellationToken cancellation = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(errors);

        Dictionary<string, string> options = [];
        for (int i = 0; i + 1 < args.Length; i += 2)
        {
            options[args[i]] = args[i + 1];
        }

        string? secret = Environment.GetEnvironmentVariable(SecretVariable);
        if (args.Length % 2 != 0
            || !options.TryGetValue("--api", out string? apiUrl) || !Uri.TryCreate(apiUrl.TrimEnd('/') + "/", UriKind.Absolute, out Uri? api)
            || !options.TryGetValue("--token-url", out string? tokenUrl) || !Uri.TryCreate(tokenUrl, UriKind.Absolute, out Uri? tokenUri)
            || !options.TryGetValue("--client-id", out string? clientId)
            || !options.TryGetValue("--out", out string? folder)
            || options.Keys.Except(["--api", "--token-url", "--client-id", "--out", "--legal-entity"]).Any())
        {
            errors.WriteLine(UsageText);
            return VerifyCommand.Usage;
        }

        Guid? legalEntity = null;
        if (options.TryGetValue("--legal-entity", out string? entity))
        {
            if (!Guid.TryParse(entity, out Guid parsed))
            {
                errors.WriteLine(UsageText);
                return VerifyCommand.Usage;
            }

            legalEntity = parsed;
        }

        // The secret, the token and every record's data key travel these: in clear text only on this machine.
        if (new[] { api, tokenUri }.FirstOrDefault(u => u.Scheme != Uri.UriSchemeHttps && !u.IsLoopback) is { } plain)
        {
            errors.WriteLine($"{plain} isn't https: the export carries the client secret and every record's data key.");
            return VerifyCommand.Usage;
        }

        if (string.IsNullOrEmpty(secret))
        {
            errors.WriteLine($"Set the client secret in the environment variable {SecretVariable}.");
            return VerifyCommand.Usage;
        }

        output.WriteLine(SetExporter.Warning);
        using HttpClient http = new() { BaseAddress = api, Timeout = TimeSpan.FromMinutes(10) };
        ClientCredentials credentials = new(http, tokenUri, clientId, secret);
        try
        {
            IReadOnlyList<Evidence.ExportSet.ExportSetFailure> failed = await new SetExporter(new ArchiveApi(http, credentials.TokenAsync, output), output, TimeProvider.System)
                .ExportAsync(folder, legalEntity, cancellation);
            output.WriteLine(failed.Count == 0
                ? $"Done. Check it with: archive-verify set {folder} --trust <ca.pem>"
                : string.Create(CultureInfo.InvariantCulture, $"Done, but {failed.Count} packages couldn't be fetched; the set names them and won't verify."));
            return failed.Count == 0 ? VerifyCommand.Valid : VerifyCommand.Invalid;
        }
        catch (Exception exception) when (exception is HttpRequestException or InvalidOperationException or IOException or JsonException or KeyNotFoundException
            || (exception is TaskCanceledException && !cancellation.IsCancellationRequested))
        {
            errors.WriteLine($"The export stopped: {exception.Message} Run it again with the same arguments to resume.");
            return VerifyCommand.Usage;
        }
    }

    /// <summary>A client-credentials token, fetched when first needed and again when the archive says it expired.</summary>
    private sealed class ClientCredentials(HttpClient http, Uri tokenUrl, string clientId, string secret)
    {
        private string? _token;

        public async Task<string> TokenAsync(bool renew, CancellationToken cancellation)
        {
            if (_token is not null && !renew)
            {
                return _token;
            }

            using FormUrlEncodedContent form = new(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = secret
            });
            using HttpResponseMessage response = await http.PostAsync(tokenUrl, form, cancellation);
            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException($"The identity provider refused the sign-in ({(int)response.StatusCode}).");
            }

            using JsonDocument body = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellation), cancellationToken: cancellation);
            _token = body.RootElement.GetProperty("access_token").GetString()
                ?? throw new InvalidOperationException("The identity provider answered without a token.");
            return _token;
        }
    }
}
