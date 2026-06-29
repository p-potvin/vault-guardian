namespace VaultGuardian.Core.Ingress.Telemetry;

public enum IngressContentSource
{
    PassivePacket,
    MitmRequest,
    MitmResponse,
    KeyLogDecryptedTrace
}

public sealed record MitmHttpFlowEvent(
    string FlowId,
    DateTimeOffset CapturedAt,
    string Url,
    string Method,
    int? StatusCode,
    IReadOnlyDictionary<string, string> RequestHeaders,
    IReadOnlyDictionary<string, string> ResponseHeaders,
    string? RequestBody,
    string? ResponseBody);

public sealed record IngressContentEvent(
    IngressContentSource Source,
    DateTimeOffset CapturedAt,
    string? RemoteAddress,
    int? RemotePort,
    string? LocalAddress,
    int? LocalPort,
    TrafficProtocol Protocol,
    int? ProcessId,
    string? ProcessName,
    string? ProcessPath,
    string? Host,
    string? Url,
    string? Path,
    string? HttpMethod,
    int? StatusCode,
    string? ContentType,
    IngressContentClassification Classification,
    string? Text,
    long BodyLength,
    string? FlowId)
{
    public static IngressContentEvent FromPacketObservation(IngressPacketObservation observation)
    {
        var sample = observation.PayloadSample;
        return new IngressContentEvent(
            IngressContentSource.PassivePacket,
            observation.Timestamp,
            observation.Flow.RemoteAddress,
            observation.Flow.RemotePort,
            observation.Flow.LocalAddress,
            observation.Flow.LocalPort,
            observation.Flow.Protocol,
            observation.Flow.ProcessId,
            observation.Flow.ProcessName,
            observation.Flow.ProcessPath,
            Host: null,
            Url: null,
            Path: null,
            HttpMethod: null,
            StatusCode: null,
            ContentType: ExtractHeader(sample?.TextPreview, "content-type"),
            sample?.Classification ?? IngressContentClassification.Unknown,
            sample?.TextPreview,
            observation.PayloadLength,
            FlowId: null);
    }

    public static IngressContentEvent FromMitmFlow(MitmHttpFlowEvent flow)
    {
        var uri = new Uri(flow.Url);
        var contentType = flow.RequestHeaders.TryGetValue("content-type", out var value)
            ? value
            : null;

        return new IngressContentEvent(
            IngressContentSource.MitmRequest,
            flow.CapturedAt,
            RemoteAddress: null,
            RemotePort: null,
            LocalAddress: null,
            LocalPort: null,
            TrafficProtocol.Tcp,
            ProcessId: null,
            ProcessName: "BrowserProfile",
            ProcessPath: null,
            uri.Host,
            flow.Url,
            string.IsNullOrWhiteSpace(uri.Query) ? uri.AbsolutePath : uri.PathAndQuery,
            flow.Method,
            flow.StatusCode,
            contentType,
            IngressContentClassification.Plaintext,
            flow.RequestBody,
            flow.RequestBody?.Length ?? 0,
            flow.FlowId);
    }

    private static string? ExtractHeader(string? text, string headerName)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        foreach (var line in text.Split(["\r\n", "\n"], StringSplitOptions.None))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            if (string.Equals(line[..separator].Trim(), headerName, StringComparison.OrdinalIgnoreCase))
            {
                return line[(separator + 1)..].Trim();
            }
        }

        return null;
    }
}
