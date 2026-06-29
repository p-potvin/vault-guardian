using VaultGuardian.Core.Ingress;
using VaultGuardian.Core.Ingress.Mitm;
using VaultGuardian.Core.Ingress.Telemetry;
using VaultGuardian.Core.Ingress.Tracing;
using VaultGuardian.Core.Observability;

namespace VaultGuardian.Core.Tests;

public sealed class IngressMetricsContractTests
{
    [Fact]
    public void AggregateMetrics_CarriesIngressSnapshot()
    {
        var metrics = new AggregateMetrics(
            new SystemResourceMetrics(0, 0, 0),
            new TrafficStatsSnapshot(0, 0, 0),
            IngressTrafficSnapshot.Empty,
            IngressWatcherStatus.Stopped,
            Array.Empty<PrivacyTelemetryHit>(),
            new FullTraceStatus(FullTraceState.Stopped, null, null, null, 0, 0),
            new MitmProxyStatus(MitmProxyState.Stopped, 18080, null, null, 0));

        Assert.Same(IngressTrafficSnapshot.Empty, metrics.Ingress);
        Assert.Equal(IngressWatcherState.Stopped, metrics.IngressWatcher.State);
        Assert.NotNull(metrics.IngressTelemetryHits);
        Assert.NotNull(metrics.FullTrace);
        Assert.NotNull(metrics.MitmProxy);
    }
}
