using System.Text;
using VaultGuardian.Core;
using VaultGuardian.Core.Ingress;

namespace VaultGuardian.Core.Tests;

public sealed class IngressCaptureLimiterTests
{
    [Fact]
    public void Apply_AllowsFirstPacketThenThrottlesRapidSameFlow()
    {
        var limiter = new IngressCaptureLimiter(new IngressCaptureLimiterOptions(
            MinimumIntervalPerFlow: TimeSpan.FromSeconds(1),
            MaxArchivedPacketsPerFlow: 10,
            MaxPayloadSamplesPerFlow: 10,
            MaxArchivedPacketsPerMinute: 100));
        var flow = Flow(localPort: 51000);
        var now = DateTimeOffset.UtcNow;

        var first = limiter.Apply(Packet(flow, now));
        var rapid = limiter.Apply(Packet(flow, now.AddMilliseconds(100)));
        var later = limiter.Apply(Packet(flow, now.AddSeconds(2)));

        Assert.NotNull(first);
        Assert.Null(rapid);
        Assert.NotNull(later);
        Assert.Equal(1, limiter.SkippedPackets);
        Assert.Equal(2, limiter.ArchivedPackets);
    }

    [Fact]
    public void Apply_DropsPayloadSamplesAfterPerFlowSampleLimit()
    {
        var limiter = new IngressCaptureLimiter(new IngressCaptureLimiterOptions(
            MinimumIntervalPerFlow: TimeSpan.Zero,
            MaxArchivedPacketsPerFlow: 10,
            MaxPayloadSamplesPerFlow: 1,
            MaxArchivedPacketsPerMinute: 100));
        var flow = Flow(localPort: 52000);
        var now = DateTimeOffset.UtcNow;

        var first = limiter.Apply(Packet(flow, now));
        var second = limiter.Apply(Packet(flow, now.AddSeconds(1)));

        Assert.NotNull(first?.PayloadSample);
        Assert.NotNull(second);
        Assert.Null(second.PayloadSample);
        Assert.Equal(1, limiter.SuppressedPayloadSamples);
    }

    [Fact]
    public void Apply_EnforcesGlobalArchiveBudget()
    {
        var limiter = new IngressCaptureLimiter(new IngressCaptureLimiterOptions(
            MinimumIntervalPerFlow: TimeSpan.Zero,
            MaxArchivedPacketsPerFlow: 10,
            MaxPayloadSamplesPerFlow: 10,
            MaxArchivedPacketsPerMinute: 2));
        var now = DateTimeOffset.UtcNow;

        var first = limiter.Apply(Packet(Flow(localPort: 53000), now));
        var second = limiter.Apply(Packet(Flow(localPort: 53001), now.AddSeconds(1)));
        var third = limiter.Apply(Packet(Flow(localPort: 53002), now.AddSeconds(2)));

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.Null(third);
        Assert.Equal(1, limiter.SkippedPackets);
        Assert.Equal(2, limiter.ArchivedPackets);
    }

    private static IngressFlowKey Flow(int localPort)
    {
        return new IngressFlowKey(
            RemoteAddress: "203.0.113.200",
            RemotePort: 443,
            LocalAddress: "192.168.1.25",
            LocalPort: localPort,
            Protocol: TrafficProtocol.Tcp,
            ProcessId: 200,
            ProcessName: "browser",
            ProcessPath: @"C:\Apps\browser.exe");
    }

    private static IngressPacketObservation Packet(IngressFlowKey flow, DateTimeOffset timestamp)
    {
        var payload = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\npayload");
        return new IngressPacketObservation(
            flow,
            timestamp,
            PacketLength: payload.Length + 40,
            PayloadLength: payload.Length,
            IngressPayloadClassifier.ClassifyAndSample(payload, timestamp));
    }
}
