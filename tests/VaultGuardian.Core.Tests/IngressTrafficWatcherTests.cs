using Microsoft.Extensions.Logging.Abstractions;
using VaultGuardian.Core;
using VaultGuardian.Core.Ingress;
using VaultGuardian.Core.Interception;

namespace VaultGuardian.Core.Tests;

public sealed class IngressTrafficWatcherTests
{
    [Fact]
    public async Task GetSnapshot_ReturnsStoreSnapshotWithoutStartingDriver()
    {
        var archivePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-ingress.json");
        await using var store = new IngressTrafficStore(archivePath);
        var watcher = new WinDivertIngressTrafficWatcher(store, NullLogger<WinDivertIngressTrafficWatcher>.Instance);

        var snapshot = watcher.GetSnapshot();
        var status = watcher.GetStatus();

        Assert.Equal(0, snapshot.TotalPackets);
        Assert.False(status.IsRunning);
        Assert.Equal(IngressWatcherState.Stopped, status.State);
        Assert.Equal(0, status.ArchivedPackets);
        Assert.Equal(0, status.SkippedPackets);
    }

    [Fact]
    public void FlowCorrelator_ResolvesInboundPacketToKnownProcessFlow()
    {
        var correlator = new IngressFlowCorrelator();
        var flow = new IngressFlowKey(
            RemoteAddress: "203.0.113.30",
            RemotePort: 443,
            LocalAddress: "192.168.1.25",
            LocalPort: 53000,
            Protocol: TrafficProtocol.Tcp,
            ProcessId: 99,
            ProcessName: "browser",
            ProcessPath: @"C:\Apps\browser.exe");

        correlator.ObserveFlow(flow);

        var resolved = correlator.Resolve(
            RemoteAddress: "203.0.113.30",
            RemotePort: 443,
            LocalAddress: "192.168.1.25",
            LocalPort: 53000,
            Protocol: TrafficProtocol.Tcp);

        Assert.Equal(flow, resolved);
    }
}
