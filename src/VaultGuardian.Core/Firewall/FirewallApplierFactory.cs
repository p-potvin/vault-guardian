using Microsoft.Extensions.Logging;
using VaultGuardian.Core.Firewall.Wfp;

namespace VaultGuardian.Core.Firewall;

public enum FirewallBackend
{
    /// <summary>Prefer native WFP; fall back to netsh if the engine cannot be opened.</summary>
    Auto,

    /// <summary>Require native WFP. Startup fails loudly if it is unavailable.</summary>
    Wfp,

    /// <summary>Force the legacy netsh backend.</summary>
    Netsh,
}

public static class FirewallApplierFactory
{
    /// <summary>
    /// Chooses the egress policy backend. Under <see cref="FirewallBackend.Auto"/>
    /// the WFP engine is opened eagerly as a probe: if the Base Filtering Engine
    /// service is stopped or the process is not elevated, that surfaces here and
    /// we degrade to netsh rather than failing every later rule change.
    /// </summary>
    public static IFirewallRuleApplier Create(
        FirewallBackend backend,
        Func<IWfpEngine> engineFactory,
        Func<IWfpEngine, IFirewallRuleApplier> wfpApplierFactory,
        Func<IFirewallRuleApplier> netshApplierFactory,
        ILogger logger)
    {
        if (backend == FirewallBackend.Netsh)
        {
            logger.LogInformation("Egress policy backend: netsh (configured)");
            return netshApplierFactory();
        }

        IWfpEngine? engine = null;
        try
        {
            engine = engineFactory();
            engine.Open();
            logger.LogInformation("Egress policy backend: native WFP");
            return wfpApplierFactory(engine);
        }
        catch (Exception ex)
        {
            engine?.Dispose();

            if (backend == FirewallBackend.Wfp)
            {
                logger.LogError(ex, "WFP backend was required but could not be opened");
                throw;
            }

            logger.LogWarning(ex, "WFP backend unavailable; falling back to netsh");
            return netshApplierFactory();
        }
    }
}
