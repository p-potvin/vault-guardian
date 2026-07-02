using System.Text.Json;
using System.Text.Json.Serialization;
using VaultGuardian.Core.Ingress.Telemetry;

namespace VaultGuardian.Core.Ingress.Mitm;

public sealed class MitmFlowImporter
{
    public async Task<IReadOnlyList<IngressContentEvent>> ImportAsync(string path, CancellationToken cancellationToken = default)
    {
        await using var stream = File.OpenRead(path);
        var flow = await JsonSerializer.DeserializeAsync(
                stream,
                MitmJsonContext.Default.MitmFlowJson,
                cancellationToken)
            .ConfigureAwait(false);
        if (flow == null)
        {
            return [];
        }

        return [ConvertFlow(flow)];
    }

    public async Task<MitmFlowImportBatch> ImportJsonLinesAsync(
        string path,
        long startLineNumber,
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(path))
        {
            return new MitmFlowImportBatch([], startLineNumber);
        }

        var events = new List<IngressContentEvent>();
        long lineNumber = 0;
        using var reader = new StreamReader(path);
        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var currentLineNumber = lineNumber;
            lineNumber++;

            if (currentLineNumber < startLineNumber || string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            MitmFlowJson? flow;
            try
            {
                flow = JsonSerializer.Deserialize(line, MitmJsonContext.Default.MitmFlowJson);
            }
            catch (JsonException)
            {
                // Skip the malformed line and keep advancing — returning here would
                // pin NextLineNumber to this line forever, stalling every future poll.
                continue;
            }

            if (flow != null)
            {
                events.Add(ConvertFlow(flow));
            }
        }

        return new MitmFlowImportBatch(events, lineNumber);
    }

    private static IngressContentEvent ConvertFlow(MitmFlowJson flow)
    {
        var eventFlow = new MitmHttpFlowEvent(
            flow.Id,
            flow.TimestampStart,
            flow.Request.Url,
            flow.Request.Method,
            flow.Response?.StatusCode,
            flow.Request.Headers,
            flow.Response?.Headers ?? new Dictionary<string, string>(),
            flow.Request.Text,
            flow.Response?.Text);
        return IngressContentEvent.FromMitmFlow(eventFlow);
    }
}

public sealed record MitmFlowImportBatch(
    IReadOnlyList<IngressContentEvent> Events,
    long NextLineNumber);

[JsonSerializable(typeof(MitmFlowJson))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower)]
internal sealed partial class MitmJsonContext : JsonSerializerContext;
