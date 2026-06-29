using VaultGuardian.Core.Diagnostics;
using VaultGuardian.Core.Ingress.Mitm;
using VaultGuardian.Core.Ingress.Telemetry;
using VaultGuardian.Core.Ingress.Tracing;

namespace VaultGuardian.Core.Tests;

public sealed class LiveMitmFlowProcessorTests
{
    [Fact]
    public async Task ProcessNewFlows_AppendsPrivacyHitsAndUpdatesImportedFlowCount()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-live-mitm");
        Directory.CreateDirectory(tempRoot);
        var flowPath = Path.Combine(tempRoot, "mitm-flows.jsonl");
        var profilePath = Path.Combine(tempRoot, "privacy-watch-profile.json");
        var hitPath = Path.Combine(tempRoot, "privacy-telemetry-hits.jsonl");
        await File.WriteAllTextAsync(flowPath,
            """
            {"id":"live-1","request":{"method":"POST","url":"https://telemetry.example.test/collect","headers":{"content-type":"application/json"},"text":"{\"email\":\"person@example.test\"}"},"response":{"status_code":204,"headers":{},"text":""},"timestamp_start":"2026-06-29T12:00:00-04:00"}

            """);
        var profileStore = new PrivacyWatchProfileStore(profilePath);
        await profileStore.SaveAsync(new PrivacyWatchProfile([
            new PrivacySelector("email.primary", PrivacySelectorKind.Literal, "person@example.test", Enabled: true)
        ]));
        var service = new MitmProxyService(
            new RecordingManagedProcessLauncher(),
            new MitmProxyOptions("mitmdump", 18080, "msedge", tempRoot, flowPath, Path.Combine(tempRoot, "addon.py")));
        await service.StartAsync(CancellationToken.None);
        var telemetryStore = new PrivacyTelemetryStore(hitPath);
        var processor = new LiveMitmFlowProcessor(
            service,
            new MitmFlowImporter(),
            profileStore,
            telemetryStore,
            new FullTraceManager());

        processor.ProcessNewFlows();
        processor.ProcessNewFlows();

        var hit = Assert.Single(telemetryStore.ListRecent());
        Assert.Equal("email.primary", hit.SelectorLabel);
        Assert.DoesNotContain("person@example.test", hit.EvidencePreview);
        Assert.Equal(1, service.GetStatus().ImportedFlows);
    }

    private sealed class RecordingManagedProcessLauncher : IManagedProcessLauncher
    {
        public IManagedProcess Start(string fileName, IReadOnlyList<string> arguments) => new RecordingManagedProcess();
    }

    private sealed class RecordingManagedProcess : IManagedProcess
    {
        public int ProcessId => 1234;
        public bool HasExited { get; private set; }
        public void Stop() => HasExited = true;
        public void Dispose() => Stop();
    }
}
