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
