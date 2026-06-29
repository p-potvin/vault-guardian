namespace VaultGuardian.Core.Tests;

public sealed class IngressUiContractTests
{
    [Fact]
    public void MainWindow_ExposesIngressPivotAndArchiveActions()
    {
        var repoRoot = FindRepoRoot();
        var xaml = File.ReadAllText(Path.Combine(repoRoot, "src", "VaultGuardian.UI", "MainWindow.xaml"));
        var codeBehind = File.ReadAllText(Path.Combine(repoRoot, "src", "VaultGuardian.UI", "MainWindow.xaml.cs"));

        Assert.Contains("PivotItem Header=\"Ingress\"", xaml);
        Assert.Contains("IngressSourceList", xaml);
        Assert.Contains("IngressStatusText", xaml);
        Assert.Contains("OnClearIngressArchiveClick", codeBehind);
        Assert.Contains("OnExportIngressFlowClick", codeBehind);
        Assert.Contains("EnableIngressPacketCapture", codeBehind);
        Assert.Contains("SkippedPackets", codeBehind);
        Assert.Contains("IngressTelemetryHitsList", xaml);
        Assert.Contains("MitmProxyStatusText", xaml);
        Assert.Contains("StartBrowserMitmButton", xaml);
        Assert.Contains("StopBrowserMitmButton", xaml);
        Assert.Contains("FullTraceStatusText", xaml);
        Assert.Contains("OnStartBrowserMitmClick", codeBehind);
        Assert.Contains("OnStopBrowserMitmClick", codeBehind);
        Assert.Contains("ImportedFlows", codeBehind);
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
