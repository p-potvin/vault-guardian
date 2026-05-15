namespace VaultGuardian.Core.Observability;

public sealed class LiveMonitorService : IDisposable
{
    private readonly ResourceMonitor _resourceMonitor;
    private readonly TrafficStats _trafficStats;

    public LiveMonitorService(ResourceMonitor resourceMonitor, TrafficStats trafficStats)
    {
        _resourceMonitor = resourceMonitor;
        _trafficStats = trafficStats;
    }

    public AggregateMetrics GetLatestMetrics()
    {
        return new AggregateMetrics(
            _resourceMonitor.GetCurrentMetrics(),
            _trafficStats.GetSnapshot()
        );
    }

    public void Dispose()
    {
        _resourceMonitor.Dispose();
    }
}
