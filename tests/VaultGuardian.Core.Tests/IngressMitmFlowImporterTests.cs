using VaultGuardian.Core.Ingress.Mitm;
using VaultGuardian.Core.Ingress.Telemetry;

namespace VaultGuardian.Core.Tests;

public sealed class IngressMitmFlowImporterTests
{
    [Fact]
    public async Task ImportAsync_ConvertsMitmJsonFixtureToContentEvent()
    {
        var repoRoot = FindRepoRoot();
        var fixturePath = Path.Combine(repoRoot, "tests", "VaultGuardian.Core.Tests", "Fixtures", "mitmproxy-flow-httpbin.json");
        var importer = new MitmFlowImporter();

        var events = await importer.ImportAsync(fixturePath);

        var contentEvent = Assert.Single(events);
        Assert.Equal(IngressContentSource.MitmRequest, contentEvent.Source);
        Assert.Equal("telemetry.example.test", contentEvent.Host);
        Assert.Equal("POST", contentEvent.HttpMethod);
        Assert.Contains("person@example.test", contentEvent.Text);
    }

    [Fact]
    public async Task ImportJsonLinesAsync_ImportsOnlyNewLiveMitmFlows()
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-mitm-live.jsonl");
        await File.WriteAllLinesAsync(path, [
            """
            {"id":"live-1","request":{"method":"POST","url":"https://telemetry.example.test/collect","headers":{"content-type":"application/json"},"text":"{\"email\":\"person@example.test\"}"},"response":{"status_code":204,"headers":{},"text":""},"timestamp_start":"2026-06-29T12:00:00-04:00"}
            """,
            """
            {"id":"live-2","request":{"method":"GET","url":"https://example.test/pixel","headers":{},"text":""},"response":{"status_code":200,"headers":{},"text":""},"timestamp_start":"2026-06-29T12:00:01-04:00"}
            """
        ]);
        var importer = new MitmFlowImporter();

        var firstBatch = await importer.ImportJsonLinesAsync(path, startLineNumber: 0);
        var secondBatch = await importer.ImportJsonLinesAsync(path, firstBatch.NextLineNumber);

        Assert.Equal(2, firstBatch.Events.Count);
        Assert.Equal(2, firstBatch.NextLineNumber);
        Assert.Empty(secondBatch.Events);
        Assert.Equal(2, secondBatch.NextLineNumber);
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
