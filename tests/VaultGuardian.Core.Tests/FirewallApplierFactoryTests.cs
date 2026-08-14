using Microsoft.Extensions.Logging.Abstractions;
using VaultGuardian.Core.Firewall;
using VaultGuardian.Core.Firewall.Wfp;

namespace VaultGuardian.Core.Tests;

public class FirewallApplierFactoryTests
{
    private sealed class StubApplier : IFirewallRuleApplier
    {
        public required string Kind { get; init; }
        public Task ApplyAsync(IEnumerable<EgressRule> rules, CancellationToken ct = default) => Task.CompletedTask;
        public Task ClearAsync(CancellationToken ct = default) => Task.CompletedTask;
        public Task CleanupPreviousSessionAsync(CancellationToken ct = default) => Task.CompletedTask;
        public Task ClearSessionRulesAsync(CancellationToken ct = default) => Task.CompletedTask;
    }

    private sealed class StubEngine : IWfpEngine
    {
        public Exception? OpenException { get; init; }
        public bool IsOpen { get; private set; }
        public int DisposeCount { get; private set; }

        public void Open()
        {
            if (OpenException is not null) throw OpenException;
            IsOpen = true;
        }

        public ulong AddFilter(WfpFilterPlan plan) => 1;
        public void DeleteFilter(ulong filterId, bool persistent) { }
        public int DeleteAllPersistentFilters() => 0;
        public void Dispose() => DisposeCount++;
    }

    private static IFirewallRuleApplier Create(
        FirewallBackend backend, StubEngine engine)
        => FirewallApplierFactory.Create(
            backend,
            engineFactory: () => engine,
            wfpApplierFactory: _ => new StubApplier { Kind = "wfp" },
            netshApplierFactory: () => new StubApplier { Kind = "netsh" },
            NullLogger.Instance);

    [Fact]
    public void Create_WithNetshBackend_NeverTouchesWfp()
    {
        var engine = new StubEngine();

        var applier = Create(FirewallBackend.Netsh, engine);

        Assert.Equal("netsh", ((StubApplier)applier).Kind);
        Assert.False(engine.IsOpen);
    }

    [Fact]
    public void Create_WithAutoBackend_PrefersWfpWhenEngineOpens()
    {
        var engine = new StubEngine();

        var applier = Create(FirewallBackend.Auto, engine);

        Assert.Equal("wfp", ((StubApplier)applier).Kind);
        Assert.True(engine.IsOpen);
    }

    [Fact]
    public void Create_WithAutoBackend_FallsBackToNetshWhenEngineFails()
    {
        var engine = new StubEngine { OpenException = new WfpException("FwpmEngineOpen0", 5) };

        var applier = Create(FirewallBackend.Auto, engine);

        Assert.Equal("netsh", ((StubApplier)applier).Kind);
    }

    [Fact]
    public void Create_WhenFallingBack_DisposesTheHalfOpenedEngine()
    {
        var engine = new StubEngine { OpenException = new WfpException("FwpmEngineOpen0", 5) };

        Create(FirewallBackend.Auto, engine);

        Assert.Equal(1, engine.DisposeCount);
    }

    [Fact]
    public void Create_WithRequiredWfpBackend_SurfacesFailureInsteadOfDegrading()
    {
        var engine = new StubEngine { OpenException = new WfpException("FwpmEngineOpen0", 5) };

        // Explicitly asking for WFP means a silent downgrade to netsh would be a
        // security surprise, so the failure must propagate.
        Assert.Throws<WfpException>(() => Create(FirewallBackend.Wfp, engine));
    }
}
