namespace VaultGuardian.Core.Firewall;

public interface IFirewallRuleApplier
{
    Task ApplyAsync(IEnumerable<EgressRule> rules, CancellationToken cancellationToken = default);
    Task ClearAsync(CancellationToken cancellationToken = default);

    /// Reads firewall-state.json and deletes every rule name recorded there.
    /// Call once at startup before ApplyAsync to remove stale rules from a previous session.
    Task CleanupPreviousSessionAsync(CancellationToken cancellationToken = default);

    /// Deletes session-only rules from the firewall and writes the remaining
    /// persistent rule names to firewall-state.json for the next startup cleanup.
    /// Call once at shutdown.
    Task ClearSessionRulesAsync(CancellationToken cancellationToken = default);
}
