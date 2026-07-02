using VaultGuardian.Core.Diagnostics;
using VaultGuardian.Core.Ingress.Mitm;

namespace VaultGuardian.Core.Tests;

public sealed class IngressMitmProxyServiceTests
{
    [Fact]
    public async Task StartAsync_CreatesBrowserProfileAndBuildsMitmCommand()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-mitm-profile");
        var launcher = new RecordingManagedProcessLauncher();
        var options = new MitmProxyOptions(
            "mitmdump",
            18080,
            "msedge",
            tempRoot);
        var service = new MitmProxyService(launcher, options);

        await service.StartAsync(CancellationToken.None);

        Assert.True(Directory.Exists(tempRoot));
        Assert.Contains(launcher.Commands, command => command.FileName == "mitmdump" && command.Arguments.Contains("--listen-port"));
        Assert.Contains(launcher.Commands, command => command.FileName == "mitmdump" && command.Arguments.Contains("18080"));
        Assert.Contains(launcher.Commands, command => command.FileName == "msedge" && command.Arguments.Any(argument => argument.StartsWith("--user-data-dir=", StringComparison.Ordinal)));
        Assert.Equal(MitmProxyState.Running, service.GetStatus().State);
    }

    [Fact]
    public async Task StartAsync_WritesMitmAddonAndFlowExportPath()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-mitm-profile");
        var flowPath = Path.Combine(tempRoot, "mitm-flows.jsonl");
        var scriptPath = Path.Combine(tempRoot, "mitm-flow-exporter.py");
        var launcher = new RecordingManagedProcessLauncher();
        var service = new MitmProxyService(
            launcher,
            new MitmProxyOptions("mitmdump", 18080, "msedge", tempRoot, flowPath, scriptPath));

        await service.StartAsync(CancellationToken.None);

        var mitmCommand = Assert.Single(launcher.Commands, command => command.FileName == "mitmdump");
        Assert.Contains("-s", mitmCommand.Arguments);
        Assert.Contains(scriptPath, mitmCommand.Arguments);
        Assert.Contains($"vaultguardian_flow_path={flowPath}", mitmCommand.Arguments);
        Assert.True(File.Exists(scriptPath));
        var script = await File.ReadAllTextAsync(scriptPath);
        Assert.Contains("vaultguardian_flow_path", script);
        Assert.Contains("datetime.fromtimestamp", script);
        Assert.Equal(flowPath, service.FlowExportPath);
    }

    private sealed class RecordingManagedProcessLauncher : IManagedProcessLauncher
    {
        public List<(string FileName, IReadOnlyList<string> Arguments)> Commands { get; } = [];

        public IManagedProcess Start(string fileName, IReadOnlyList<string> arguments)
        {
            Commands.Add((fileName, arguments));
            return new RecordingManagedProcess();
        }
    }

    private sealed class RecordingManagedProcess : IManagedProcess
    {
        public int ProcessId => 1234;
        public bool HasExited { get; private set; }
        public void Stop() => HasExited = true;
        public void Dispose() => Stop();
    }
}
