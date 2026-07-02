using VaultGuardian.Core;
using VaultGuardian.Core.Ingress;
using VaultGuardian.Core.Ingress.Tracing;

namespace VaultGuardian.Core.Tests;

public sealed class IngressFullTraceManagerTests
{
    [Fact]
    public void Trigger_ActivatesTraceForMatchingFlowAndStopsAtByteLimit()
    {
        var manager = new FullTraceManager(new FullTraceOptions(
            MaxDuration: TimeSpan.FromMinutes(5),
            MaxBytes: 100,
            MaxPackets: 10));
        var flow = Flow();
        var now = DateTimeOffset.UtcNow;

        var trigger = manager.Trigger(new FullTraceTrigger(
            FullTraceScopeKind.Flow,
            flow,
            "privacy selector `email.primary` matched",
            now));

        Assert.True(manager.ShouldBypassSampling(flow, now, packetLength: 50));
        Assert.True(manager.ShouldBypassSampling(flow, now.AddSeconds(1), packetLength: 50));
        Assert.False(manager.ShouldBypassSampling(flow, now.AddSeconds(2), packetLength: 1));
        Assert.Equal(FullTraceState.Stopped, manager.GetStatus().State);
        Assert.Equal(trigger.TraceId, manager.GetStatus().LastTraceId);
    }

    private static IngressFlowKey Flow()
    {
        return new IngressFlowKey(
            "203.0.113.55",
            443,
            "192.168.1.25",
            51000,
            TrafficProtocol.Tcp,
            42,
            "browser",
            @"C:\Apps\browser.exe");
    }
}
