using Microsoft.Extensions.Logging.Abstractions;
using VaultGuardian.Core.Firewall;

namespace VaultGuardian.Core.Tests;

public class WindowsFirewallRuleApplierTests
{
    private sealed class FakeProcessRunner : IProcessRunner
    {
        public List<(string FileName, string Arguments)> Invocations { get; } = new();
        public int DefaultExitCode { get; set; } = 0;

        public Task<int> RunAsync(string fileName, string arguments, CancellationToken cancellationToken = default)
        {
            Invocations.Add((fileName, arguments));
            return Task.FromResult(DefaultExitCode);
        }
    }

    private static WindowsFirewallRuleApplier Create(out FakeProcessRunner runner)
    {
        runner = new FakeProcessRunner();
        return new WindowsFirewallRuleApplier(runner, NullLogger<WindowsFirewallRuleApplier>.Instance);
    }

    [Fact]
    public async Task ApplyAsync_TranslatesFullRuleToNetshCommand()
    {
        var applier = Create(out var runner);
        var rule = new EgressRule(
            Name: "block-vendor",
            ProcessPath: @"C:\Apps\target.exe",
            RemoteAddress: "203.0.113.10",
            RemotePort: 443,
            Protocol: TrafficProtocol.Tcp,
            Block: true);

        await applier.ApplyAsync(new[] { rule });

        var addCmd = runner.Invocations.Single(i => i.Arguments.Contains("add rule"));
        Assert.Equal("netsh", addCmd.FileName);
        Assert.Contains("name=\"VG-block-vendor\"", addCmd.Arguments);
        Assert.Contains("dir=out", addCmd.Arguments);
        Assert.Contains("action=block", addCmd.Arguments);
        Assert.Contains("program=\"C:\\Apps\\target.exe\"", addCmd.Arguments);
        Assert.Contains("remoteip=203.0.113.10", addCmd.Arguments);
        Assert.Contains("remoteport=443", addCmd.Arguments);
        Assert.Contains("protocol=TCP", addCmd.Arguments);
    }

    [Fact]
    public async Task ApplyAsync_SkipsAllowRules()
    {
        var applier = Create(out var runner);
        var rule = new EgressRule(Name: "allow-it", RemoteAddress: "1.1.1.1", Block: false);

        await applier.ApplyAsync(new[] { rule });

        Assert.DoesNotContain(runner.Invocations, i => i.Arguments.Contains("add rule"));
    }

    [Fact]
    public async Task ApplyAsync_SkipsRulesWithNoSelectors()
    {
        var applier = Create(out var runner);
        var rule = new EgressRule(Name: "empty");

        await applier.ApplyAsync(new[] { rule });

        Assert.DoesNotContain(runner.Invocations, i => i.Arguments.Contains("add rule"));
    }

    [Fact]
    public async Task ApplyAsync_SkipsHostnameOnlyRules()
    {
        var applier = Create(out var runner);
        var rule = new EgressRule(Name: "host-only", RemoteHost: "api.vendor.test");

        await applier.ApplyAsync(new[] { rule });

        Assert.DoesNotContain(runner.Invocations, i => i.Arguments.Contains("add rule"));
    }

    [Fact]
    public async Task ApplyAsync_CidrRangeIsPassedThrough()
    {
        var applier = Create(out var runner);
        var rule = new EgressRule(Name: "cidr", RemoteAddress: "192.168.1.0/24");

        await applier.ApplyAsync(new[] { rule });

        var addCmd = runner.Invocations.Single(i => i.Arguments.Contains("add rule"));
        Assert.Contains("remoteip=192.168.1.0/24", addCmd.Arguments);
    }

    [Fact]
    public async Task ApplyAsync_ProgramOnlyRuleProducesProgramFilter()
    {
        var applier = Create(out var runner);
        var rule = new EgressRule(Name: "block-app", ProcessPath: @"C:\App\bad.exe");

        await applier.ApplyAsync(new[] { rule });

        var addCmd = runner.Invocations.Single(i => i.Arguments.Contains("add rule"));
        Assert.Contains("program=\"C:\\App\\bad.exe\"", addCmd.Arguments);
        Assert.DoesNotContain("remoteip=", addCmd.Arguments);
        Assert.DoesNotContain("remoteport=", addCmd.Arguments);
    }

    [Fact]
    public async Task ApplyAsync_RemovesPreviouslyAppliedRulesBeforeAddingNewSet()
    {
        var applier = Create(out var runner);
        await applier.ApplyAsync(new[]
        {
            new EgressRule("first", RemoteAddress: "1.1.1.1"),
        });
        runner.Invocations.Clear();

        await applier.ApplyAsync(new[]
        {
            new EgressRule("second", RemoteAddress: "2.2.2.2"),
        });

        Assert.Contains(runner.Invocations, i => i.Arguments.Contains("delete rule name=\"VG-first\""));
        Assert.Contains(runner.Invocations, i => i.Arguments.Contains("add rule") && i.Arguments.Contains("name=\"VG-second\""));
    }

    [Fact]
    public async Task ApplyAsync_DefaultsToTcpWhenPortHasNoProtocol()
    {
        var applier = Create(out var runner);
        var rule = new EgressRule(Name: "port-only", RemotePort: 8080, Protocol: TrafficProtocol.Any);

        await applier.ApplyAsync(new[] { rule });

        var addCmd = runner.Invocations.Single(i => i.Arguments.Contains("add rule"));
        Assert.Contains("remoteport=8080", addCmd.Arguments);
        Assert.Contains("protocol=TCP", addCmd.Arguments);
    }

    [Fact]
    public async Task ApplyAsync_RedefiningSameRuleNameDeletesOldFirst()
    {
        var applier = Create(out var runner);
        await applier.ApplyAsync(new[]
        {
            new EgressRule("svc", RemoteAddress: "1.1.1.1", RemotePort: 80, Protocol: TrafficProtocol.Tcp),
        });
        runner.Invocations.Clear();

        await applier.ApplyAsync(new[]
        {
            new EgressRule("svc", RemoteAddress: "2.2.2.2", RemotePort: 80, Protocol: TrafficProtocol.Tcp),
        });

        var deleteIndex = runner.Invocations.FindIndex(i => i.Arguments.Contains("delete rule name=\"VG-svc\""));
        var addIndex = runner.Invocations.FindIndex(i => i.Arguments.Contains("add rule") && i.Arguments.Contains("name=\"VG-svc\""));
        Assert.True(deleteIndex >= 0);
        Assert.True(addIndex > deleteIndex);
    }

    [Fact]
    public async Task ClearAsync_DeletesAppliedRules()
    {
        var applier = Create(out var runner);
        await applier.ApplyAsync(new[]
        {
            new EgressRule("a", RemoteAddress: "1.1.1.1"),
            new EgressRule("b", RemoteAddress: "2.2.2.2"),
        });
        runner.Invocations.Clear();

        await applier.ClearAsync();

        Assert.Contains(runner.Invocations, i => i.Arguments.Contains("delete rule name=\"VG-a\""));
        Assert.Contains(runner.Invocations, i => i.Arguments.Contains("delete rule name=\"VG-b\""));
    }
}
