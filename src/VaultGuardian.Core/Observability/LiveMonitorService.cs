using VaultGuardian.Core.Ingress;
using VaultGuardian.Core.Ingress.Mitm;
using VaultGuardian.Core.Ingress.Telemetry;
using VaultGuardian.Core.Ingress.Tracing;

namespace VaultGuardian.Core.Observability;

public sealed class LiveMonitorService : IDisposable
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
    }

    public AggregateMetrics GetLatestMetrics()
    {
        _liveMitmFlowProcessor?.ProcessNewFlows();

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
        _resourceMonitor.Dispose();
    }
}
