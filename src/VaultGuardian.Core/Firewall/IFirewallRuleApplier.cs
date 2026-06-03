namespace VaultGuardian.Core.Firewall;

public interface IFirewallRuleApplier
{
    Task ApplyAsync(IEnumerable<EgressRule> rules, CancellationToken cancellationToken = default);
    Task ClearAsync(CancellationToken cancellationToken = default);
}
