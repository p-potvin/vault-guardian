namespace VaultGuardian.Core.Ingress.Tracing;

public sealed class FullTraceManager
{
    private readonly object _lock = new();
    private readonly FullTraceOptions _options;
    private ActiveFullTrace? _active;
    private string? _lastTraceId;

    public FullTraceManager(FullTraceOptions? options = null)
    {
        _options = options ?? FullTraceOptions.Default;
    }

    public ActiveFullTrace Trigger(FullTraceTrigger trigger)
    {
        lock (_lock)
        {
            _active = new ActiveFullTrace(
                TraceId: $"trace-{Guid.NewGuid():N}",
                trigger.ScopeKind,
                trigger.Flow,
                trigger.Reason,
                trigger.TriggeredAt,
                CapturedBytes: 0,
                CapturedPackets: 0);
            return _active;
        }
    }

    public bool ShouldBypassSampling(IngressFlowKey flow, DateTimeOffset now, int packetLength)
    {
        lock (_lock)
        {
            if (_active == null)
            {
                return false;
            }

            if (now - _active.StartedAt > _options.MaxDuration ||
                _active.CapturedBytes + packetLength > _options.MaxBytes ||
                _active.CapturedPackets + 1 > _options.MaxPackets)
            {
                StopActive();
                return false;
            }

            var matches = _active.ScopeKind switch
            {
                FullTraceScopeKind.Flow => _active.Flow == flow,
                FullTraceScopeKind.Source => string.Equals(
                    _active.Flow?.RemoteAddress,
                    flow.RemoteAddress,
                    StringComparison.OrdinalIgnoreCase),
                FullTraceScopeKind.BrowserProfile => string.Equals(
                    flow.ProcessName,
                    "BrowserProfile",
                    StringComparison.OrdinalIgnoreCase),
                _ => false
            };

            if (!matches)
            {
                return false;
            }

            _active = _active with
            {
                CapturedBytes = _active.CapturedBytes + packetLength,
                CapturedPackets = _active.CapturedPackets + 1
            };
            return true;
        }
    }

    public FullTraceStatus GetStatus()
    {
        lock (_lock)
        {
            if (_active == null)
            {
                return new FullTraceStatus(FullTraceState.Stopped, null, _lastTraceId, null, 0, 0);
            }

            return new FullTraceStatus(
                FullTraceState.Active,
                _active.TraceId,
                _lastTraceId,
                _active.Reason,
                _active.CapturedBytes,
                _active.CapturedPackets);
        }
    }

    private void StopActive()
    {
        if (_active != null)
        {
            _lastTraceId = _active.TraceId;
            _active = null;
        }
    }
}
