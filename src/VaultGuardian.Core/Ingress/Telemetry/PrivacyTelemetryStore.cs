using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VaultGuardian.Core.Ingress.Telemetry;

public sealed class PrivacyTelemetryStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<PrivacyTelemetryHit> _hits;

    public PrivacyTelemetryStore(string path)
    {
        _path = path;
        _hits = Load(path);
    }

    public async Task AppendAsync(IEnumerable<PrivacyTelemetryHit> hits, CancellationToken cancellationToken = default)
    {
        var newHits = hits.ToArray();
        if (newHits.Length == 0)
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directory = Path.GetDirectoryName(_path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // Batch to a single append so we're not opening/closing the file per hit.
            var buffer = new StringBuilder();
            foreach (var hit in newHits)
            {
                _hits.Add(hit);
                var line = JsonSerializer.Serialize(hit, PrivacyTelemetryJsonContext.Default.PrivacyTelemetryHit);
                buffer.Append(line).Append(Environment.NewLine);
            }
            await File.AppendAllTextAsync(_path, buffer.ToString(), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public IReadOnlyList<PrivacyTelemetryHit> ListRecent(int count = 50)
    {
        _gate.Wait();
        try
        {
            return _hits.OrderByDescending(hit => hit.DetectedAt).Take(count).ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    private static List<PrivacyTelemetryHit> Load(string path)
    {
        if (!File.Exists(path))
        {
            return [];
        }

        var hits = new List<PrivacyTelemetryHit>();
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            // A malformed line here used to crash app startup because the store is
            // constructed as a singleton — skip and keep loading.
            PrivacyTelemetryHit? hit;
            try
            {
                hit = JsonSerializer.Deserialize(line, PrivacyTelemetryJsonContext.Default.PrivacyTelemetryHit);
            }
            catch (JsonException)
            {
                continue;
            }

            if (hit != null)
            {
                hits.Add(hit);
            }
        }

        return hits;
    }
}

[JsonSerializable(typeof(PrivacyTelemetryHit))]
[JsonSourceGenerationOptions(WriteIndented = false, Converters = [typeof(JsonStringEnumConverter<PrivacyHitConfidence>)])]
internal sealed partial class PrivacyTelemetryJsonContext : JsonSerializerContext;
