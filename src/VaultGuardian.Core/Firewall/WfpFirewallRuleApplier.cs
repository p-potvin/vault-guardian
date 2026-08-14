using Microsoft.Extensions.Logging;
using VaultGuardian.Core.Firewall.Wfp;

namespace VaultGuardian.Core.Firewall;

/// <summary>
/// Applies egress policy natively through the Windows Filtering Platform instead
/// of shelling out to <c>netsh</c>.
///
/// Differences from <see cref="WindowsFirewallRuleApplier"/> that are intentional:
/// <list type="bullet">
/// <item>Session rules live on a dynamic WFP session, so Windows destroys them
/// when the process exits — even on a crash. No <c>firewall-state.json</c>
/// bookkeeping is needed for them.</item>
/// <item>Stale persistent rules are found by our provider GUID rather than by a
/// recorded name list, so cleanup still works if the state file is lost.</item>
/// <item>Rules apply in list order via descending filter weight, which lets a
/// non-blocking rule act as a genuine exception ahead of a broader block.</item>
/// <item>New filters are installed before old ones are removed, so a rule swap
/// never leaves a window with no policy in force.</item>
/// </list>
/// </summary>
public sealed class WfpFirewallRuleApplier : IFirewallRuleApplier, IDisposable
{
    private readonly IWfpEngine _engine;
    private readonly ILogger<WfpFirewallRuleApplier> _logger;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly List<InstalledFilter> _installed = [];

    public WfpFirewallRuleApplier(IWfpEngine engine, ILogger<WfpFirewallRuleApplier> logger)
    {
        _engine = engine;
        _logger = logger;
    }

    private readonly record struct InstalledFilter(ulong Id, bool Persistent, string RuleName);

    public async Task CleanupPreviousSessionAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureEngineOpen();
            var removed = _engine.DeleteAllPersistentFilters();
            if (removed > 0)
            {
                _logger.LogInformation("Removed {Count} persistent WFP filter(s) from a previous session", removed);
            }

            // Session filters from a previous run were destroyed with that run's
            // dynamic session, so there is nothing else to reclaim.
            _installed.Clear();
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task ApplyAsync(IEnumerable<EgressRule> rules, CancellationToken cancellationToken = default)
    {
        var ruleList = rules as IList<EgressRule> ?? rules.ToList();

        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureEngineOpen();

            var plan = WfpFilterPlanner.Plan(ruleList);
            foreach (var skip in plan.Skipped)
            {
                _logger.LogDebug("Skipping rule '{Rule}': {Reason}", skip.RuleName, skip.Reason);
            }

            var previous = _installed.ToArray();
            var added = new List<InstalledFilter>(plan.Filters.Count);

            var notApplicable = 0;
            try
            {
                foreach (var filterPlan in plan.Filters)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    try
                    {
                        var id = _engine.AddFilter(filterPlan);
                        added.Add(new InstalledFilter(id, filterPlan.Persistent, filterPlan.RuleName));
                    }
                    catch (WfpFilterNotApplicableException ex)
                    {
                        // One unusable rule (typically an uninstalled executable)
                        // must not stop every other rule from being enforced.
                        notApplicable++;
                        _logger.LogWarning("{Message}", ex.Message);
                    }
                }
            }
            catch
            {
                // Roll the partial batch back so policy stays exactly as it was.
                foreach (var filter in added) TryDelete(filter);
                throw;
            }

            // Only once the new set is fully in force do we retire the old one.
            foreach (var filter in previous) TryDelete(filter);

            _installed.Clear();
            _installed.AddRange(added);

            _logger.LogInformation(
                "Applied {FilterCount} WFP filter(s) from {RuleCount} rule(s); {SkipCount} unexpressible, {NotApplicable} not applicable on this machine",
                added.Count, ruleList.Count, plan.Skipped.Count, notApplicable);
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task ClearSessionRulesAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_engine.IsOpen) return;

            foreach (var filter in _installed.Where(f => !f.Persistent).ToArray())
            {
                TryDelete(filter);
                _installed.Remove(filter);
            }
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task ClearAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_engine.IsOpen) return;

            foreach (var filter in _installed.ToArray()) TryDelete(filter);
            _installed.Clear();

            // Catch anything persistent that predates this process.
            _engine.DeleteAllPersistentFilters();
        }
        finally
        {
            _lock.Release();
        }
    }

    private void EnsureEngineOpen()
    {
        if (_engine.IsOpen) return;
        _engine.Open();
    }

    private void TryDelete(InstalledFilter filter)
    {
        try
        {
            _engine.DeleteFilter(filter.Id, filter.Persistent);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to remove WFP filter {FilterId} for rule '{Rule}'", filter.Id, filter.RuleName);
        }
    }

    /// <summary>
    /// Registered as a DI singleton, so this runs at container teardown. Closing
    /// the engine is what releases the dynamic session and therefore every
    /// session filter still in force.
    /// </summary>
    public void Dispose()
    {
        _engine.Dispose();
        _lock.Dispose();
    }
}
