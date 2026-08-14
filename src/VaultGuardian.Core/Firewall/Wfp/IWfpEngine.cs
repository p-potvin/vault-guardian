namespace VaultGuardian.Core.Firewall.Wfp;

/// <summary>
/// Narrow seam over the WFP filter engine so <see cref="WfpFirewallRuleApplier"/>
/// can be tested without an elevated process or a live filter engine.
/// </summary>
public interface IWfpEngine : IDisposable
{
    bool IsOpen { get; }

    /// <summary>
    /// Opens the engine handles and registers the VaultGuardian provider and
    /// sublayer. Throws <see cref="WfpException"/> if the platform rejects the
    /// call (most often ERROR_ACCESS_DENIED when not elevated).
    /// </summary>
    void Open();

    /// <summary>Installs one filter and returns its engine-assigned id.</summary>
    ulong AddFilter(WfpFilterPlan plan);

    /// <summary>Removes a single filter previously returned by <see cref="AddFilter"/>.</summary>
    void DeleteFilter(ulong filterId, bool persistent);

    /// <summary>
    /// Removes every persistent filter tagged with the VaultGuardian provider key,
    /// including ones left behind by a previous run or a previous boot. Returns
    /// how many were removed.
    /// </summary>
    int DeleteAllPersistentFilters();
}
