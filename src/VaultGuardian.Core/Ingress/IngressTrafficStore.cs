using System.Text.Json;
using System.Text.Json.Serialization;

namespace VaultGuardian.Core.Ingress;

public sealed record IngressTrafficStoreOptions(
    long? MaxArchiveBytes = 536_870_912,
    long MinimumFreeDiskBytes = 536_870_912);

public sealed class IngressArchiveSafetyException : InvalidOperationException
{
    public IngressArchiveSafetyException(string message)
        : base(message)
    {
    }
}

public sealed class IngressTrafficStore : IIngressTrafficStore, IAsyncDisposable
{
    private readonly string _archivePath;
    private readonly IngressTrafficStoreOptions _options;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private List<IngressPacketObservation> _observations;
    private static readonly JsonSerializerOptions JsonLineOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters =
        {
            new JsonStringEnumConverter<TrafficProtocol>(),
            new JsonStringEnumConverter<IngressContentClassification>()
        }
    };

    public IngressTrafficStore(string archivePath, IngressTrafficStoreOptions? options = null)
    {
        if (string.IsNullOrWhiteSpace(archivePath))
        {
            throw new ArgumentException("Archive path is required.", nameof(archivePath));
        }

        _archivePath = archivePath;
        _options = options ?? new IngressTrafficStoreOptions();
        _observations = LoadArchive(archivePath);
    }

    public async Task AppendAsync(IngressPacketObservation observation, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var line = SerializeObservation(observation);
            EnsureArchiveCanAccept(line);
            _observations.Add(observation);
            await AppendObservationAsync(line, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public IngressTrafficSnapshot GetSnapshot()
    {
        IngressPacketObservation[] observations;
        _gate.Wait();
        try
        {
            observations = _observations.ToArray();
        }
        finally
        {
            _gate.Release();
        }

        return BuildSnapshot(observations);
    }

    public IReadOnlyList<IngressPacketObservation> ListFlowPackets(IngressFlowKey flowKey)
    {
        _gate.Wait();
        try
        {
            return _observations
                .Where(observation => observation.Flow == flowKey)
                .OrderBy(observation => observation.Timestamp)
                .ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task ClearAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _observations.Clear();
            var directory = Path.GetDirectoryName(_archivePath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            await File.WriteAllTextAsync(_archivePath, string.Empty, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<string> ExportFlowAsync(
        IngressFlowKey flowKey,
        string exportDirectory,
        CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(exportDirectory);
        var safeRemote = flowKey.RemoteAddress.Replace(':', '_').Replace('.', '_');
        var filePath = Path.Combine(
            exportDirectory,
            $"ingress-{safeRemote}-{flowKey.RemotePort}-{flowKey.LocalPort}.json");

        var packets = ListFlowPackets(flowKey).ToList();
        await using var stream = File.Create(filePath);
        await JsonSerializer.SerializeAsync(
                stream,
                packets,
                IngressTrafficJsonContext.Default.ListIngressPacketObservation,
                cancellationToken)
            .ConfigureAwait(false);
        return filePath;
    }

    public ValueTask DisposeAsync()
    {
        _gate.Dispose();
        return ValueTask.CompletedTask;
    }

    private static IngressTrafficSnapshot BuildSnapshot(IReadOnlyCollection<IngressPacketObservation> observations)
    {
        if (observations.Count == 0)
        {
            return IngressTrafficSnapshot.Empty;
        }

        var flows = observations
            .GroupBy(observation => observation.Flow)
            .Select(group => new IngressFlowSummary(
                group.Key,
                group.Count(),
                group.Sum(observation => (long)observation.PacketLength),
                group.Sum(observation => (long)observation.PayloadLength),
                group.Min(observation => observation.Timestamp),
                group.Max(observation => observation.Timestamp),
                group.Select(observation => observation.PayloadSample)
                    .Where(sample => sample != null)
                    .Cast<PayloadSample>()
                    .OrderByDescending(sample => sample.CapturedAt)
                    .Take(5)
                    .ToArray()))
            .ToArray();

        var sources = flows
            .GroupBy(flow => flow.Key.RemoteAddress)
            .Select(group => new IngressSourceSummary(
                group.Key,
                group.Sum(flow => flow.PacketCount),
                group.Count(),
                group.Sum(flow => flow.TotalBytes),
                group.Sum(flow => flow.TotalPayloadBytes),
                group.Min(flow => flow.FirstSeen),
                group.Max(flow => flow.LastSeen),
                group.OrderByDescending(flow => flow.LastSeen).ToArray()))
            .OrderByDescending(source => source.LastSeen)
            .ToArray();

        return new IngressTrafficSnapshot(
            observations.Count,
            observations.Sum(observation => (long)observation.PacketLength),
            observations.Sum(observation => (long)observation.PayloadLength),
            sources);
    }

    private static List<IngressPacketObservation> LoadArchive(string archivePath)
    {
        if (!File.Exists(archivePath))
        {
            return [];
        }

        try
        {
            var text = File.ReadAllText(archivePath);
            if (string.IsNullOrWhiteSpace(text))
            {
                return [];
            }

            if (text.TrimStart().StartsWith("[", StringComparison.Ordinal))
            {
                return JsonSerializer.Deserialize(
                    text,
                    IngressTrafficJsonContext.Default.ListIngressPacketObservation) ?? [];
            }

            var observations = new List<IngressPacketObservation>();
            // The whole file is already in `text` — re-reading with File.ReadLines
            // would double the disk I/O for large archives.
            using var reader = new StringReader(text);
            while (reader.ReadLine() is { } line)
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                var observation = JsonSerializer.Deserialize<IngressPacketObservation>(
                    line,
                    JsonLineOptions);
                if (observation != null)
                {
                    observations.Add(observation);
                }
            }

            return observations;
        }
        catch
        {
            return [];
        }
    }

    private void EnsureArchiveCanAccept(string serializedLine)
    {
        var fullPath = Path.GetFullPath(_archivePath);
        var directory = Path.GetDirectoryName(fullPath);
        var currentLength = File.Exists(fullPath) ? new FileInfo(fullPath).Length : 0;
        var incomingBytes = System.Text.Encoding.UTF8.GetByteCount(serializedLine + Environment.NewLine);

        if (_options.MaxArchiveBytes is { } maxArchiveBytes &&
            currentLength + incomingBytes > maxArchiveBytes)
        {
            throw new IngressArchiveSafetyException(
                $"Ingress archive would exceed the configured archive safety limit of {maxArchiveBytes:N0} bytes.");
        }

        var root = Path.GetPathRoot(fullPath);
        if (!string.IsNullOrWhiteSpace(root) && _options.MinimumFreeDiskBytes > 0)
        {
            try
            {
                var drive = new DriveInfo(root);
                if (drive.IsReady && drive.AvailableFreeSpace - incomingBytes < _options.MinimumFreeDiskBytes)
                {
                    throw new IngressArchiveSafetyException(
                        $"Ingress archive stopped because disk free space would fall below {_options.MinimumFreeDiskBytes:N0} bytes.");
                }
            }
            catch (IngressArchiveSafetyException)
            {
                throw;
            }
            catch
            {
                // If the drive cannot be inspected, keep the archive appendable.
            }
        }

        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    private static string SerializeObservation(IngressPacketObservation observation)
    {
        return JsonSerializer.Serialize(
            observation,
            JsonLineOptions);
    }

    private async Task AppendObservationAsync(string serializedLine, CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(_archivePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.AppendAllTextAsync(_archivePath, serializedLine + Environment.NewLine, cancellationToken).ConfigureAwait(false);
    }
}
