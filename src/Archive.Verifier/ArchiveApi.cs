using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

using Archive.Evidence.ExportSet;

namespace Archive.Verifier;

/// <summary>
/// The archive's API as the export tool calls it: a bearer token from <paramref name="token"/>, renewed once when the
/// archive says it expired; a 429 waits as long as <c>Retry-After</c> says; a 5xx, a timeout or a dropped connection
/// is tried again a few times. A full export runs for days, so none of these may end it.
/// </summary>
public sealed class ArchiveApi(HttpClient http, Func<bool, CancellationToken, Task<string>> token, TextWriter log)
{
    private const int Attempts = 6;

    /// <summary>A GET answered with JSON, read with the export set's settings.</summary>
    public Task<T> GetJsonAsync<T>(string path, CancellationToken cancellation)
    {
        return RetryingAsync(path, ReadAsync, cancellation);

        async Task<T> ReadAsync()
        {
            using HttpResponseMessage response = await SendAsync(path, accept: null, cancellation);
            await using Stream body = await response.Content.ReadAsStreamAsync(cancellation);
            return await JsonSerializer.DeserializeAsync<T>(body, ExportSetFormat.Json, cancellation)
                ?? throw new InvalidDataException($"{path} answered no JSON.");
        }
    }

    /// <summary>A GET streamed to <paramref name="file"/>, through a temporary file, so a file there is always whole.</summary>
    /// <returns>
    /// Null when written; otherwise 404 or 410 for a record erased since, or 502 when the archive itself says the record
    /// is damaged. A 502 from anything else on the way, a proxy say, is tried again like any 5xx.
    /// </returns>
    public Task<HttpStatusCode?> DownloadAsync(string path, string file, CancellationToken cancellation)
    {
        return RetryingAsync(path, FetchAsync, cancellation);

        async Task<HttpStatusCode?> FetchAsync()
        {
            using HttpResponseMessage response = await SendAsync(path, Refusal, cancellation);
            if (!response.IsSuccessStatusCode)
            {
                return response.StatusCode;
            }

            string partial = file + ".partial";
            try
            {
                await using (FileStream output = File.Create(partial))
                {
                    await response.Content.CopyToAsync(output, cancellation);
                }

                File.Move(partial, file, overwrite: true);
                return null;
            }
            finally
            {
                File.Delete(partial);
            }
        }
    }

    /// <summary>An answer that says the record can't be exported, as the archive gives it: not one to try again.</summary>
    private static bool Refusal(HttpResponseMessage response) =>
        response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Gone
        || (response.StatusCode == HttpStatusCode.BadGateway && response.Content.Headers.ContentType?.MediaType == "application/problem+json");

    /// <summary>A connection dropped or timed out, before the answer or while reading it: worth trying again.</summary>
    private static bool Transient(Exception exception, CancellationToken cancellation) =>
        exception is HttpRequestException { StatusCode: null } or IOException
        || (exception is TaskCanceledException && !cancellation.IsCancellationRequested);

    /// <summary>The whole call, the answer's body included, tried again after a dropped connection or a timeout.</summary>
    private async Task<T> RetryingAsync<T>(string path, Func<Task<T>> call, CancellationToken cancellation)
    {
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                return await call();
            }
            catch (Exception exception) when (attempt < Attempts && Transient(exception, cancellation))
            {
                await WaitAsync(attempt, $"{path}: {exception.Message}", cancellation);
            }
        }
    }

    /// <summary>The status-driven retries: a token renewed once on 401, 429 waited out, a 5xx tried a few times.</summary>
    private async Task<HttpResponseMessage> SendAsync(string path, Func<HttpResponseMessage, bool>? accept, CancellationToken cancellation)
    {
        bool renewed = false;
        for (int attempt = 1; ; attempt++)
        {
            using HttpRequestMessage request = new(HttpMethod.Get, path);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await token(false, cancellation));
            HttpResponseMessage response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation);
            if (response.IsSuccessStatusCode || accept?.Invoke(response) == true)
            {
                return response;
            }

            HttpStatusCode status = response.StatusCode;
            TimeSpan? retryAfter = response.Headers.RetryAfter?.Delta;
            response.Dispose();
            if (status == HttpStatusCode.Unauthorized && !renewed)
            {
                renewed = true;
                await token(true, cancellation);
                continue;
            }

            if (status == HttpStatusCode.TooManyRequests)
            {
                // The archive's own rate limit: wait as told, however often, so a long export just runs slower.
                TimeSpan wait = retryAfter ?? TimeSpan.FromSeconds(10);
                log.WriteLine(string.Create(CultureInfo.InvariantCulture, $"  rate limited; waiting {wait.TotalSeconds:0} s"));
                await Task.Delay(wait, cancellation);
                attempt--;
                continue;
            }

            if ((int)status >= 500 && attempt < Attempts)
            {
                await WaitAsync(attempt, $"{path}: {(int)status}", cancellation);
                continue;
            }

            throw new HttpRequestException($"{path} answered {(int)status}.", null, status);
        }
    }

    private async Task WaitAsync(int attempt, string why, CancellationToken cancellation)
    {
        TimeSpan wait = TimeSpan.FromSeconds(Math.Pow(2, attempt));
        log.WriteLine(string.Create(CultureInfo.InvariantCulture, $"  {why}; trying again in {wait.TotalSeconds:0} s"));
        await Task.Delay(wait, cancellation);
    }
}
