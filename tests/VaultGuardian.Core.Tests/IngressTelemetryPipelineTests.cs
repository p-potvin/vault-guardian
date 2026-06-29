using VaultGuardian.Core.Ingress.Mitm;
using VaultGuardian.Core.Ingress.Telemetry;
using VaultGuardian.Core.Ingress.Tracing;

namespace VaultGuardian.Core.Tests;

public sealed class IngressTelemetryPipelineTests
{
    [Fact]
    public async Task ProcessMitmFixture_AppendsHitAndTriggersFullTrace()
    {
        var repoRoot = FindRepoRoot();
        var fixturePath = Path.Combine(repoRoot, "tests", "VaultGuardian.Core.Tests", "Fixtures", "mitmproxy-flow-httpbin.json");
        var hitPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-hits.jsonl");
        var profile = new PrivacyWatchProfile([
            new PrivacySelector("email.primary", PrivacySelectorKind.Literal, "person@example.test", Enabled: true)
        ]);
        var pipeline = new IngressTelemetryPipeline(
            new MitmFlowImporter(),
            new PrivacyTelemetryAnalyzer(profile),
            new PrivacyTelemetryStore(hitPath),
            new FullTraceManager(new FullTraceOptions(TimeSpan.FromMinutes(1), 1024 * 1024, 100)));

        var result = await pipeline.ProcessMitmFileAsync(fixturePath);

        Assert.Equal(1, result.EventsProcessed);
        Assert.Equal(1, result.HitsDetected);
        Assert.Equal(FullTraceState.Active, result.FullTrace.State);
    }

    private static string FindRepoRoot()
    {
        var current = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (current != null)
        {
            if (File.Exists(Path.Combine(current.FullName, "VaultGuardian.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Could not locate VaultGuardian repository root.");
    }
}
