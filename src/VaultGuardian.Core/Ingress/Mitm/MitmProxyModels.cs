using System.Text.Json.Serialization;

namespace VaultGuardian.Core.Ingress.Mitm;

public enum MitmProxyState
{
    Stopped,
    Starting,
    Running,
    Faulted
}

public sealed record MitmProxyStatus(
    MitmProxyState State,
    int ListenPort,
    string? BrowserProfilePath,
    string? LastError,
    int ImportedFlows);

public sealed record MitmProxyOptions(
    string MitmDumpPath,
    int ListenPort,
    string BrowserExecutablePath,
    string BrowserProfilePath)
{
    public static MitmProxyOptions Default(string baseDirectory) => new(
        "mitmdump",
        18080,
        "msedge",
        Path.Combine(baseDirectory, "mitm-browser-profile"));
}

internal sealed record MitmFlowJson(
    string Id,
    MitmMessageJson Request,
    MitmResponseJson? Response,
    DateTimeOffset TimestampStart);

internal sealed record MitmMessageJson(
    string Method,
    string Url,
    Dictionary<string, string> Headers,
    string? Text);

internal sealed record MitmResponseJson(
    [property: JsonPropertyName("status_code")] int? StatusCode,
    Dictionary<string, string> Headers,
    string? Text);
