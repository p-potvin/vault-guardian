using Microsoft.Extensions.Logging.Abstractions;
using VaultGuardian.Core.Firewall;
using VaultGuardian.Core.Firewall.Wfp;

namespace VaultGuardian.Core.Tests;

public class WfpFirewallRuleApplierTests
{
    private sealed class FakeWfpEngine : IWfpEngine
    {
        private ulong _nextId = 1;

        public bool IsOpen { get; private set; }
        public List<string> Operations { get; } = [];
        public List<WfpFilterPlan> Added { get; } = [];
        public HashSet<ulong> Live { get; } = [];
        public int PersistentSweeps { get; private set; }
        public int DisposeCount { get; private set; }

        public Exception? OpenException { get; set; }
        public Func<WfpFilterPlan, bool>? FailAddWhen { get; set; }

        public void Open()
        {
            if (OpenException is not null) throw OpenException;
            IsOpen = true;
            Operations.Add("open");
        }

        public ulong AddFilter(WfpFilterPlan plan)
        {
            if (FailAddWhen?.Invoke(plan) == true)
                throw new WfpException("FwpmFilterAdd0", 5);

            var id = _nextId++;
            Live.Add(id);
            Added.Add(plan);
            Operations.Add($"add:{plan.RuleName}:{id}");
            return id;
        }

        public void DeleteFilter(ulong filterId, bool persistent)
        {
            Live.Remove(filterId);
            Operations.Add($"del:{filterId}");
        }

        public int DeleteAllPersistentFilters()
        {
            PersistentSweeps++;
            Operations.Add("sweep");
            return 0;
        }

        public void Dispose()
        {
            DisposeCount++;
            IsOpen = false;
        }
    }

    private static WfpFirewallRuleApplier Create(out FakeWfpEngine engine)
    {
        engine = new FakeWfpEngine();
        return new WfpFirewallRuleApplier(engine, NullLogger<WfpFirewallRuleApplier>.Instance);
    }

    [Fact]
    public async Task ApplyAsync_OpensEngineLazilyOnFirstUse()
    {
        var applier = Create(out var engine);
        Assert.False(engine.IsOpen);

        await applier.ApplyAsync([new EgressRule("r", RemoteAddress: "203.0.113.1")]);

        Assert.True(engine.IsOpen);
    }

    [Fact]
    public async Task ApplyAsync_InstallsPlannedFilters()
    {
        var applier = Create(out var engine);

        await applier.ApplyAsync([
            new EgressRule("block-v4", RemoteAddress: "203.0.113.1"),
            new EgressRule("block-app", ProcessPath: @"C:\a.exe"),
        ]);

        // block-v4 pins IPv4; block-app has no address so it fans out to both families.
        Assert.Equal(3, engine.Added.Count);
        Assert.Equal(3, engine.Live.Count);
    }

    [Fact]
    public async Task ApplyAsync_AddsNewFiltersBeforeRemovingOldOnes()
    {
        var applier = Create(out var engine);
        await applier.ApplyAsync([new EgressRule("old", RemoteAddress: "203.0.113.1")]);

        engine.Operations.Clear();
        await applier.ApplyAsync([new EgressRule("new", RemoteAddress: "203.0.113.2")]);

        var addIndex = engine.Operations.FindIndex(op => op.StartsWith("add:new"));
        var deleteIndex = engine.Operations.FindIndex(op => op.StartsWith("del:"));

        Assert.True(addIndex >= 0 && deleteIndex >= 0);
        Assert.True(addIndex < deleteIndex,
            "the replacement filter must be in force before the old one is retired, so policy is never briefly absent");
    }

    [Fact]
    public async Task ApplyAsync_ReplacesPreviousFilterSet()
    {
        var applier = Create(out var engine);
        await applier.ApplyAsync([new EgressRule("old", RemoteAddress: "203.0.113.1")]);
        var oldId = engine.Live.Single();

        await applier.ApplyAsync([new EgressRule("new", RemoteAddress: "203.0.113.2")]);

        Assert.DoesNotContain(oldId, engine.Live);
        Assert.Single(engine.Live);
    }

    [Fact]
    public async Task ApplyAsync_WhenOneFilterFails_RollsBackBatchAndKeepsPreviousPolicy()
    {
        var applier = Create(out var engine);
        await applier.ApplyAsync([new EgressRule("existing", RemoteAddress: "203.0.113.1")]);
        var existingId = engine.Live.Single();

        engine.FailAddWhen = plan => plan.RuleName == "explodes";

        await Assert.ThrowsAsync<WfpException>(() => applier.ApplyAsync([
            new EgressRule("fine", RemoteAddress: "203.0.113.2"),
            new EgressRule("explodes", RemoteAddress: "203.0.113.3"),
        ]));

        // The half-applied batch is gone and the prior policy is untouched.
        Assert.Equal([existingId], engine.Live);
    }

    [Fact]
    public async Task ApplyAsync_SkippedRulesDoNotFailTheBatch()
    {
        var applier = Create(out var engine);

        await applier.ApplyAsync([
            new EgressRule("good", RemoteAddress: "203.0.113.1"),
            new EgressRule("hostname-only", RemoteHost: "telemetry.example.test"),
        ]);

        Assert.Single(engine.Added);
        Assert.Equal("good", engine.Added[0].RuleName);
    }

    [Fact]
    public async Task ClearSessionRulesAsync_RemovesOnlySessionFilters()
    {
        var applier = Create(out var engine);
        await applier.ApplyAsync([
            new EgressRule("keep", RemoteAddress: "203.0.113.1", IsPersistent: true),
            new EgressRule("drop", RemoteAddress: "203.0.113.2", IsPersistent: false),
        ]);

        var persistentId = engine.Added
            .Select((plan, i) => (plan, id: (ulong)(i + 1)))
            .Single(x => x.plan.RuleName == "keep").id;

        await applier.ClearSessionRulesAsync();

        Assert.Equal([persistentId], engine.Live);
    }

    [Fact]
    public async Task CleanupPreviousSessionAsync_SweepsStalePersistentFilters()
    {
        var applier = Create(out var engine);

        await applier.CleanupPreviousSessionAsync();

        Assert.True(engine.IsOpen);
        Assert.Equal(1, engine.PersistentSweeps);
    }

    [Fact]
    public async Task ClearAsync_RemovesTrackedFiltersAndSweepsPersistent()
    {
        var applier = Create(out var engine);
        await applier.ApplyAsync([
            new EgressRule("a", RemoteAddress: "203.0.113.1", IsPersistent: true),
            new EgressRule("b", RemoteAddress: "203.0.113.2", IsPersistent: false),
        ]);

        await applier.ClearAsync();

        Assert.Empty(engine.Live);
        Assert.Equal(1, engine.PersistentSweeps);
    }

    [Fact]
    public async Task ClearAsync_OnUnopenedEngineIsNoOp()
    {
        var applier = Create(out var engine);

        await applier.ClearAsync();

        Assert.False(engine.IsOpen);
        Assert.Equal(0, engine.PersistentSweeps);
    }
}
