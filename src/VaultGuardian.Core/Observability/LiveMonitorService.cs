using VaultGuardian.Core.Ingress;
using VaultGuardian.Core.Ingress.Mitm;
using VaultGuardian.Core.Ingress.Telemetry;
using VaultGuardian.Core.Ingress.Tracing;

namespace VaultGuardian.Core.Observability;

public sealed class LiveMonitorService : IDisposable, IAsyncDisposable
{
    private readonly ResourceMonitor _resourceMonitor;
    private readonly TrafficStats _trafficStats;
    private readonly IIngressTrafficStore? _ingressTrafficStore;
    private readonly IIngressTrafficWatcher? _ingressTrafficWatcher;
    private readonly PrivacyTelemetryStore? _privacyTelemetryStore;
    private readonly FullTraceManager? _fullTraceManager;
    private readonly MitmProxyService? _mitmProxyService;
    private readonly LiveMitmFlowProcessor? _liveMitmFlowProcessor;

    public LiveMonitorService(
        ResourceMonitor resourceMonitor,
        TrafficStats trafficStats,
        IIngressTrafficStore? ingressTrafficStore = null,
        IIngressTrafficWatcher? ingressTrafficWatcher = null,
        PrivacyTelemetryStore? privacyTelemetryStore = null,
        FullTraceManager? fullTraceManager = null,
        MitmProxyService? mitmProxyService = null,
        LiveMitmFlowProcessor? liveMitmFlowProcessor = null)
    {
        _resourceMonitor = resourceMonitor;
        _trafficStats = trafficStats;
        _ingressTrafficStore = ingressTrafficStore;
        _ingressTrafficWatcher = ingressTrafficWatcher;
        _privacyTelemetryStore = privacyTelemetryStore;
        _fullTraceManager = fullTraceManager;
        _mitmProxyService = mitmProxyService;
        _liveMitmFlowProcessor = liveMitmFlowProcessor;

        // Kick off the background mitm-flow processor so the UI-thread accessor below
        // stays pure. The loop is torn down in DisposeAsync.
        _liveMitmFlowProcessor?.Start();
    }

    /// <summary>
    /// Returns a pure read of the latest metrics snapshot. No I/O, no side effects —
    /// safe to call every UI tick. Background flow ingestion runs independently via
    /// <see cref="LiveMitmFlowProcessor"/>.
    /// </summary>
    public AggregateMetrics GetSnapshot()
    {
        return new AggregateMetrics(
            _resourceMonitor.GetCurrentMetrics(),
            _trafficStats.GetSnapshot(),
            _ingressTrafficStore?.GetSnapshot() ?? IngressTrafficSnapshot.Empty,
            _ingressTrafficWatcher?.GetStatus() ?? IngressWatcherStatus.Stopped,
            _privacyTelemetryStore?.ListRecent() ?? [],
            _fullTraceManager?.GetStatus() ?? new FullTraceStatus(FullTraceState.Stopped, null, null, null, 0, 0),
            _mitmProxyService?.GetStatus() ?? new MitmProxyStatus(MitmProxyState.Stopped, 18080, null, null, 0)
        );
    }

    public void Dispose()
    {
        // Best-effort synchronous teardown of the background loop for callers that
        // can't use await. Prefer DisposeAsync when possible.
        if (_liveMitmFlowProcessor != null)
        {
            try { _liveMitmFlowProcessor.StopAsync().GetAwaiter().GetResult(); }
            catch { }
        }
        _resourceMonitor.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        if (_liveMitmFlowProcessor != null)
        {
            await _liveMitmFlowProcessor.StopAsync().ConfigureAwait(false);
        }
        _resourceMonitor.Dispose();
    }
}
