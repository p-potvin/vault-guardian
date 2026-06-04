using Microsoft.Extensions.Logging.Abstractions;
using VaultGuardian.Core.Firewall;

namespace VaultGuardian.Core.Tests;

public class WindowsFirewallRuleApplierTests
{
    private sealed class FakeProcessRunner : IProcessRunner
    {
        public List<(string FileName, IReadOnlyList<string> Arguments)> Invocations { get; } = new();
        public int DefaultExitCode { get; set; } = 0;
        public Func<string, IReadOnlyList<string>, int>? ExitCodeFor { get; set; }

        public Task<int> RunAsync(string fileName, IEnumerable<string> arguments, CancellationToken cancellationToken = default)
        {
            var argList = arguments.ToList();
            Invocations.Add((fileName, argList));
            var code = ExitCodeFor?.Invoke(fileName, argList) ?? DefaultExitCode;
            return Task.FromResult(code);
        }
    }

    private static WindowsFirewallRuleApplier Create(out FakeProcessRunner runner, out string stateFile)
    {
        runner = new FakeProcessRunner();
        stateFile = Path.GetTempFileName();
        File.Delete(stateFile); // start absent — applier should handle missing file
        return new WindowsFirewallRuleApplier(runner, NullLogger<WindowsFirewallRuleApplier>.Instance, stateFile);
    }

    // ── Basic command translation ──────────────────────────────────────────────

    [Fact]
    public async Task ApplyAsync_TranslatesFullRuleToNetshCommand()
    {
        var applier = Create(out var runner, out var sf);
        var rule = new EgressRule(
            Name: "block-vendor",
            ProcessPath: @"C:\Apps\target.exe",
            RemoteAddress: "203.0.113.10",
            RemotePort: 443,
            Protocol: TrafficProtocol.Tcp,
            Block: true);

        await applier.ApplyAsync(new[] { rule });

        var addCmd = runner.Invocations.Single(i => i.Arguments.Contains("add"));
        Assert.Equal("netsh", addCmd.FileName);
        Assert.Contains("name=VG-block-vendor", addCmd.Arguments);
        Assert.Contains("dir=out", addCmd.Arguments);
        Assert.Contains("action=block", addCmd.Arguments);
        Assert.Contains(@"program=C:\Apps\target.exe", addCmd.Arguments);
        Assert.Contains("remoteip=203.0.113.10", addCmd.Arguments);
        Assert.Contains("remoteport=443", addCmd.Arguments);
        Assert.Contains("protocol=TCP", addCmd.Arguments);

        File.Delete(sf);
    }

    [Fact]
    public async Task ApplyAsync_SkipsAllowRules()
    {
        var applier = Create(out var runner, out var sf);
        await applier.ApplyAsync(new[] { new EgressRule(Name: "allow-it", RemoteAddress: "1.1.1.1", Block: false) });
        Assert.DoesNotContain(runner.Invocations, i => i.Arguments.Contains("add"));
        File.Delete(sf);
    }

    [Fact]
    public async Task ApplyAsync_SkipsRulesWithNoSelectors()
    {
        var applier = Create(out var runner, out var sf);
        await applier.ApplyAsync(new[] { new EgressRule(Name: "empty") });
        Assert.DoesNotContain(runner.Invocations, i => i.Arguments.Contains("add"));
        File.Delete(sf);
    }

    [Fact]
    public async Task ApplyAsync_SkipsHostnameOnlyRules()
    {
        var applier = Create(out var runner, out var sf);
        await applier.ApplyAsync(new[] { new EgressRule(Name: "host-only", RemoteHost: "api.vendor.test") });
        Assert.DoesNotContain(runner.Invocations, i => i.Arguments.Contains("add"));
        File.Delete(sf);
    }

    [Fact]
    public async Task ApplyAsync_CidrRangeIsPassedThrough()
    {
        var applier = Create(out var runner, out var sf);
        await applier.ApplyAsync(new[] { new EgressRule(Name: "cidr", RemoteAddress: "192.168.1.0/24") });
        var addCmd = runner.Invocations.Single(i => i.Arguments.Contains("add"));
        Assert.Contains("remoteip=192.168.1.0/24", addCmd.Arguments);
        File.Delete(sf);
    }

    [Fact]
    public async Task ApplyAsync_ProgramOnlyRuleProducesProgramFilter()
    {
        var applier = Create(out var runner, out var sf);
        await applier.ApplyAsync(new[] { new EgressRule(Name: "block-app", ProcessPath: @"C:\App\bad.exe") });
        var addCmd = runner.Invocations.Single(i => i.Arguments.Contains("add"));
        Assert.Contains(@"program=C:\App\bad.exe", addCmd.Arguments);
        Assert.DoesNotContain(addCmd.Arguments, a => a.StartsWith("remoteip="));
        Assert.DoesNotContain(addCmd.Arguments, a => a.StartsWith("remoteport="));
        File.Delete(sf);
    }

    [Fact]
    public async Task ApplyAsync_DefaultsToTcpWhenPortHasNoProtocol()
    {
        var applier = Create(out var runner, out var sf);
        await applier.ApplyAsync(new[] { new EgressRule(Name: "port-only", RemotePort: 8080, Protocol: TrafficProtocol.Any) });
        var addCmd = runner.Invocations.Single(i => i.Arguments.Contains("add"));
        Assert.Contains("remoteport=8080", addCmd.Arguments);
        Assert.Contains("protocol=TCP", addCmd.Arguments);
        File.Delete(sf);
    }

    // ── Delete-before-replace ──────────────────────────────────────────────────

    [Fact]
    public async Task ApplyAsync_RemovesPreviouslyAppliedRulesBeforeAddingNewSet()
    {
        var applier = Create(out var runner, out var sf);
        await applier.ApplyAsync(new[] { new EgressRule("first", RemoteAddress: "1.1.1.1") });
        runner.Invocations.Clear();

        await applier.ApplyAsync(new[] { new EgressRule("second", RemoteAddress: "2.2.2.2") });

        Assert.Contains(runner.Invocations, i => i.Arguments.Contains("delete") && i.Arguments.Contains("name=VG-first"));
        Assert.Contains(runner.Invocations, i => i.Arguments.Contains("add") && i.Arguments.Contains("name=VG-second"));
        File.Delete(sf);
    }

    [Fact]
    public async Task ApplyAsync_RedefiningSameRuleNameDeletesOldFirst()
    {
        var applier = Create(out var runner, out var sf);
        await applier.ApplyAsync(new[] { new EgressRule("svc", RemoteAddress: "1.1.1.1", RemotePort: 80, Protocol: TrafficProtocol.Tcp) });
        runner.Invocations.Clear();

        await applier.ApplyAsync(new[] { new EgressRule("svc", RemoteAddress: "2.2.2.2", RemotePort: 80, Protocol: TrafficProtocol.Tcp) });

        var deleteIndex = runner.Invocations.FindIndex(i => i.Arguments.Contains("delete") && i.Arguments.Contains("name=VG-svc"));
        var addIndex = runner.Invocations.FindIndex(i => i.Arguments.Contains("add") && i.Arguments.Contains("name=VG-svc"));
        Assert.True(deleteIndex >= 0);
        Assert.True(addIndex > deleteIndex);
        File.Delete(sf);
    }

    // ── ClearAsync ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task ClearAsync_DeletesAllAppliedRules()
    {
        var applier = Create(out var runner, out var sf);
        await applier.ApplyAsync(new[]
        {
            new EgressRule("a", RemoteAddress: "1.1.1.1"),
            new EgressRule("b", RemoteAddress: "2.2.2.2", IsPersistent: false),
        });
        runner.Invocations.Clear();

        await applier.ClearAsync();

        Assert.Contains(runner.Invocations, i => i.Arguments.Contains("delete") && i.Arguments.Contains("name=VG-a"));
        Assert.Contains(runner.Invocations, i => i.Arguments.Contains("delete") && i.Arguments.Contains("name=VG-b"));
        Assert.False(File.Exists(sf));
    }

    // ── Error handling ─────────────────────────────────────────────────────────

    [Fact]
    public async Task ApplyAsync_ThrowsWhenNetshAddFails()
    {
        var applier = Create(out var runner, out var sf);
        runner.ExitCodeFor = (_, args) => args.Contains("add") ? 1 : 0;
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => applier.ApplyAsync(new[] { new EgressRule("fail", RemoteAddress: "1.1.1.1") }));
        try { File.Delete(sf); } catch { }
    }

    [Fact]
    public async Task ApplyAsync_PersistsAlreadyAppliedRulesEvenIfLaterRuleFails()
    {
        var applier = Create(out var runner, out var sf);
        // Fail only when adding "bad" — "good" succeeds first and must end up in the state file.
        runner.ExitCodeFor = (_, args) =>
            args.Contains("add") && args.Contains("name=VG-bad") ? 1 : 0;

        await Assert.ThrowsAsync<InvalidOperationException>(() => applier.ApplyAsync(new[]
        {
            new EgressRule("good", RemoteAddress: "1.1.1.1", IsPersistent: true),
            new EgressRule("bad", RemoteAddress: "2.2.2.2", IsPersistent: true),
        }));

        Assert.True(File.Exists(sf));
        var json = await File.ReadAllTextAsync(sf);
        Assert.Contains("VG-good", json);
        Assert.DoesNotContain("VG-bad", json);
        File.Delete(sf);
    }

    [Fact]
    public async Task ApplyAsync_DoesNotInjectArgumentsViaRuleName()
    {
        var applier = Create(out var runner, out var sf);
        var rule = new EgressRule(Name: "evil dir=in action=allow", RemoteAddress: "1.1.1.1");

        await applier.ApplyAsync(new[] { rule });

        var addCmd = runner.Invocations.Single(i => i.Arguments.Contains("add"));
        Assert.Contains("name=VG-evil dir=in action=allow", addCmd.Arguments);
        Assert.Equal(1, addCmd.Arguments.Count(a => a.StartsWith("dir=")));
        Assert.Contains("dir=out", addCmd.Arguments);
        Assert.DoesNotContain("dir=in", addCmd.Arguments);
        File.Delete(sf);
    }

    // ── Persistence (IsPersistent flag + state file) ───────────────────────────

    [Fact]
    public async Task ApplyAsync_WritesOnlyPersistentNamesToStateFile()
    {
        var applier = Create(out _, out var sf);
        await applier.ApplyAsync(new[]
        {
            new EgressRule("persist-me", RemoteAddress: "1.1.1.1", IsPersistent: true),
            new EgressRule("session-only", RemoteAddress: "2.2.2.2", IsPersistent: false),
        });

        Assert.True(File.Exists(sf));
        var json = await File.ReadAllTextAsync(sf);
        Assert.Contains("VG-persist-me", json);
        Assert.DoesNotContain("VG-session-only", json);
        File.Delete(sf);
    }

    [Fact]
    public async Task ClearSessionRulesAsync_OnlyDeletesSessionRules()
    {
        var applier = Create(out var runner, out var sf);
        await applier.ApplyAsync(new[]
        {
            new EgressRule("keep", RemoteAddress: "1.1.1.1", IsPersistent: true),
            new EgressRule("drop", RemoteAddress: "2.2.2.2", IsPersistent: false),
        });
        runner.Invocations.Clear();

        await applier.ClearSessionRulesAsync();

        Assert.DoesNotContain(runner.Invocations, i => i.Arguments.Contains("name=VG-keep"));
        Assert.Contains(runner.Invocations, i => i.Arguments.Contains("delete") && i.Arguments.Contains("name=VG-drop"));

        // State file should still record the persistent rule.
        var json = await File.ReadAllTextAsync(sf);
        Assert.Contains("VG-keep", json);
        Assert.DoesNotContain("VG-drop", json);
        File.Delete(sf);
    }

    [Fact]
    public async Task CleanupPreviousSessionAsync_DeletesNamesFromStateFile()
    {
        var stateFile = Path.GetTempFileName();
        var runner = new FakeProcessRunner();
        var applier = new WindowsFirewallRuleApplier(runner, NullLogger<WindowsFirewallRuleApplier>.Instance, stateFile);

        // Simulate a state file written by a previous session.
        await File.WriteAllTextAsync(stateFile, "[\"VG-old-rule\",\"VG-another\"]");

        await applier.CleanupPreviousSessionAsync();

        Assert.Contains(runner.Invocations, i => i.Arguments.Contains("delete") && i.Arguments.Contains("name=VG-old-rule"));
        Assert.Contains(runner.Invocations, i => i.Arguments.Contains("delete") && i.Arguments.Contains("name=VG-another"));

        // State file should be cleared after cleanup.
        Assert.False(File.Exists(stateFile) && new FileInfo(stateFile).Length > 2);
        try { File.Delete(stateFile); } catch { }
    }

    [Fact]
    public async Task CleanupPreviousSessionAsync_DoesNothingWhenStateFileMissing()
    {
        var runner = new FakeProcessRunner();
        var applier = new WindowsFirewallRuleApplier(
            runner, NullLogger<WindowsFirewallRuleApplier>.Instance, "/nonexistent/firewall-state.json");

        await applier.CleanupPreviousSessionAsync(); // should not throw

        Assert.DoesNotContain(runner.Invocations, i => i.Arguments.Contains("delete"));
    }

    [Fact]
    public async Task FullLifecycle_PersistentRulesSurviveRestart_SessionRulesDontAppearInStateFile()
    {
        var sf = Path.GetTempFileName();
        var runner1 = new FakeProcessRunner();
        var applier1 = new WindowsFirewallRuleApplier(runner1, NullLogger<WindowsFirewallRuleApplier>.Instance, sf);

        // "Session 1": apply rules, then simulate graceful shutdown.
        await applier1.ApplyAsync(new[]
        {
            new EgressRule("p", RemoteAddress: "1.1.1.1", IsPersistent: true),
            new EgressRule("s", RemoteAddress: "2.2.2.2", IsPersistent: false),
        });
        await applier1.ClearSessionRulesAsync();

        // State file must only contain the persistent rule.
        var stateJson = await File.ReadAllTextAsync(sf);
        Assert.Contains("VG-p", stateJson);
        Assert.DoesNotContain("VG-s", stateJson);

        // "Session 2": cleanup previous, verify stale rules are deleted.
        var runner2 = new FakeProcessRunner();
        var applier2 = new WindowsFirewallRuleApplier(runner2, NullLogger<WindowsFirewallRuleApplier>.Instance, sf);
        await applier2.CleanupPreviousSessionAsync();

        Assert.Contains(runner2.Invocations, i => i.Arguments.Contains("delete") && i.Arguments.Contains("name=VG-p"));
        Assert.DoesNotContain(runner2.Invocations, i => i.Arguments.Contains("name=VG-s"));

        File.Delete(sf);
    }
}
