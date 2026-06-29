using System.Text;
using VaultGuardian.Core;
using VaultGuardian.Core.Ingress;
using VaultGuardian.Core.Ingress.Telemetry;

namespace VaultGuardian.Core.Tests;

public sealed class IngressContentEventTests
{
    [Fact]
    public void FromPacketObservation_CarriesFlowAndPlaintextSample()
    {
        var flow = new IngressFlowKey(
            "203.0.113.10",
            443,
            "192.168.1.25",
            51000,
            TrafficProtocol.Tcp,
            42,
            "browser",
            @"C:\Apps\browser.exe");
        var payload = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nemail@example.test");
        var sample = IngressPayloadClassifier.ClassifyAndSample(payload, DateTimeOffset.UtcNow);
        var observation = new IngressPacketObservation(flow, DateTimeOffset.UtcNow, payload.Length + 40, payload.Length, sample);

        var contentEvent = IngressContentEvent.FromPacketObservation(observation);

        Assert.Equal(IngressContentSource.PassivePacket, contentEvent.Source);
        Assert.Equal("203.0.113.10", contentEvent.RemoteAddress);
        Assert.Equal("browser", contentEvent.ProcessName);
        Assert.Equal(IngressContentClassification.Plaintext, contentEvent.Classification);
        Assert.Contains("email@example.test", contentEvent.Text ?? string.Empty);
    }

    [Fact]
    public void FromMitmFlow_CarriesHttpMetadataWithoutProcessAttribution()
    {
        var flow = new MitmHttpFlowEvent(
            FlowId: "flow-1",
            CapturedAt: DateTimeOffset.UtcNow,
            Url: "https://telemetry.example.test/collect",
            Method: "POST",
            StatusCode: 204,
            RequestHeaders: new Dictionary<string, string> { ["content-type"] = "application/json" },
            ResponseHeaders: new Dictionary<string, string>(),
            RequestBody: "{\"device\":\"abc\"}",
            ResponseBody: string.Empty);

        var contentEvent = IngressContentEvent.FromMitmFlow(flow);

        Assert.Equal(IngressContentSource.MitmRequest, contentEvent.Source);
        Assert.Equal("telemetry.example.test", contentEvent.Host);
        Assert.Equal("POST", contentEvent.HttpMethod);
        Assert.Equal("/collect", contentEvent.Path);
        Assert.Contains("device", contentEvent.Text ?? string.Empty);
    }
}
