using VaultGuardian.Core;
using VaultGuardian.Core.Ingress;
using VaultGuardian.Core.Ingress.Telemetry;

namespace VaultGuardian.Core.Tests;

public sealed class IngressTelemetryAnalyzerTests
{
    [Fact]
    public void Analyze_DetectsPrivacySelectorAndTelemetryEndpoint()
    {
        var profile = new PrivacyWatchProfile([
            new PrivacySelector("email.primary", PrivacySelectorKind.Literal, "person@example.test", Enabled: true)
        ]);
        var analyzer = new PrivacyTelemetryAnalyzer(profile);
        var contentEvent = new IngressContentEvent(
            IngressContentSource.MitmRequest,
            DateTimeOffset.UtcNow,
            RemoteAddress: null,
            RemotePort: null,
            LocalAddress: null,
            LocalPort: null,
            TrafficProtocol.Tcp,
            ProcessId: null,
            ProcessName: "BrowserProfile",
            ProcessPath: null,
            Host: "analytics.example.test",
            Url: "https://analytics.example.test/collect",
            Path: "/collect",
            HttpMethod: "POST",
            StatusCode: 204,
            ContentType: "application/json",
            IngressContentClassification.Plaintext,
            Text: "{\"email\":\"person@example.test\"}",
            BodyLength: 31,
            FlowId: "flow-1");

        var result = analyzer.Analyze(contentEvent);

        Assert.Contains(result.Hits, hit => hit.SelectorLabel == "email.primary");
        Assert.Contains(result.Tags, tag => tag == "telemetry.endpoint");
        Assert.DoesNotContain("person@example.test", string.Join("\n", result.Hits.Select(hit => hit.EvidencePreview)));
    }
}
