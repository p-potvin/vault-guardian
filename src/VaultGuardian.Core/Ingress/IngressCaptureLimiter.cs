using VaultGuardian.Core.Ingress.Tracing;

namespace VaultGuardian.Core.Ingress;

public sealed record IngressCaptureLimiterOptions(
    TimeSpan MinimumIntervalPerFlow,
    int MaxArchivedPacketsPerFlow,
    int MaxPayloadSamplesPerFlow,
    int MaxArchivedPacketsPerMinute)
{
    public static IngressCaptureLimiterOptions Default { get; } = new(
        MinimumIntervalPerFlow: TimeSpan.FromSeconds(1),
        MaxArchivedPacketsPerFlow: 300,
        MaxPayloadSamplesPerFlow: 20,
        MaxArchivedPacketsPerMinute: 600);
}

public sealed class IngressCaptureLimiter
{
    private readonly object _lock = new();
    private readonly IngressCaptureLimiterOptions _options;
    private readonly FullTraceManager? _fullTraceManager;
    private readonly Dictionary<IngressFlowKey, FlowBudget> _flows = new();
    private readonly Queue<DateTimeOffset> _globalArchiveWindow = new();

    public IngressCaptureLimiter(IngressCaptureLimiterOptions? options = null, FullTraceManager? fullTraceManager = null)
    {
        _options = options ?? IngressCaptureLimiterOptions.Default;
        _fullTraceManager = fullTraceManager;
    }

    public long ArchivedPackets { get; private set; }

    public long SkippedPackets { get; private set; }

    public long SuppressedPayloadSamples { get; private set; }

    public IngressPacketObservation? Apply(IngressPacketObservation observation)
    {
        lock (_lock)
        {
            TrimGlobalWindow(observation.Timestamp);
            if (_globalArchiveWindow.Count >= _options.MaxArchivedPacketsPerMinute)
            {
                SkippedPackets++;
                return null;
            }

            if (!_flows.TryGetValue(observation.Flow, out var budget))
            {
                budget = new FlowBudget();
                _flows[observation.Flow] = budget;
            }

            var bypassSampling = _fullTraceManager?.ShouldBypassSampling(
                observation.Flow,
                observation.Timestamp,
                observation.PacketLength) == true;

            if (budget.ArchivedPackets >= _options.MaxArchivedPacketsPerFlow)
            {
                SkippedPackets++;
                return null;
            }

            if (!bypassSampling &&
                budget.ArchivedPackets > 0 &&
                observation.Timestamp - budget.LastArchivedAt < _options.MinimumIntervalPerFlow)
            {
                SkippedPackets++;
                return null;
            }

            var limitedObservation = observation;
            if (!bypassSampling &&
                observation.PayloadSample != null &&
                budget.PayloadSamples >= _options.MaxPayloadSamplesPerFlow)
            {
                limitedObservation = observation with { PayloadSample = null };
                SuppressedPayloadSamples++;
            }

            budget.ArchivedPackets++;
            if (limitedObservation.PayloadSample != null)
            {
                budget.PayloadSamples++;
            }

            budget.LastArchivedAt = observation.Timestamp;
            ArchivedPackets++;
            _globalArchiveWindow.Enqueue(observation.Timestamp);
            return limitedObservation;
        }
    }

    private void TrimGlobalWindow(DateTimeOffset now)
    {
        while (_globalArchiveWindow.Count > 0 &&
               now - _globalArchiveWindow.Peek() >= TimeSpan.FromMinutes(1))
        {
            _globalArchiveWindow.Dequeue();
        }
    }

    private sealed class FlowBudget
    {
        public int ArchivedPackets { get; set; }

        public int PayloadSamples { get; set; }

        public DateTimeOffset LastArchivedAt { get; set; }
    }
}
