using System.Net;
using System.Net.Sockets;

namespace VaultGuardian.Core.Firewall.Wfp;

/// <summary>
/// Pure translation from <see cref="EgressRule"/> to the concrete WFP filters
/// that express it. Deliberately free of interop so the mapping is unit-testable
/// without an elevated process or a live filter engine.
/// </summary>
public static class WfpFilterPlanner
{
    public const string ManagedNamePrefix = "VG-";

    public static string ManagedName(string ruleName) => ManagedNamePrefix + ruleName;

    public static WfpPlan Plan(IEnumerable<EgressRule> rules)
    {
        var ordered = rules as IList<EgressRule> ?? rules.ToList();
        var filters = new List<WfpFilterPlan>();
        var skipped = new List<WfpSkippedRule>();

        for (var index = 0; index < ordered.Count; index++)
        {
            var rule = ordered[index];

            // Earlier rules must win, and higher WFP weight is evaluated first.
            var weight = (ulong)(ordered.Count - index);

            if (!TryResolveAddress(rule, out var families, out var addressReason))
            {
                skipped.Add(new WfpSkippedRule(rule.Name, addressReason!));
                continue;
            }

            var port = ResolvePort(rule, out var portReason);
            if (portReason != null)
            {
                skipped.Add(new WfpSkippedRule(rule.Name, portReason));
                continue;
            }

            var appPath = string.IsNullOrWhiteSpace(rule.ProcessPath) ? null : rule.ProcessPath.Trim();
            var protocol = ResolveProtocol(rule.Protocol);

            // Refuse to install a filter with no conditions: it would block or
            // permit every connection on the machine.
            var hasAnyCondition = appPath is not null
                || families.Any(f => f.Match is not null)
                || port is not null
                || protocol is not null;

            if (!hasAnyCondition)
            {
                skipped.Add(new WfpSkippedRule(
                    rule.Name,
                    string.IsNullOrWhiteSpace(rule.RemoteHost)
                        ? "no process, remote address, port, or protocol specified — refusing to match all traffic"
                        : "hostname-only rules cannot be expressed as WFP conditions (WFP matches on IP, not name)"));
                continue;
            }

            foreach (var (family, match) in families)
            {
                filters.Add(new WfpFilterPlan
                {
                    RuleName = rule.Name,
                    DisplayName = ManagedName(rule.Name),
                    Family = family,
                    Action = rule.Block ? WfpFilterAction.Block : WfpFilterAction.Permit,
                    Weight = weight,
                    Persistent = rule.IsPersistent,
                    AppPath = appPath,
                    RemoteAddress = match,
                    RemotePort = port,
                    IpProtocol = protocol,
                });
            }
        }

        return new WfpPlan(filters, skipped);
    }

    private static bool TryResolveAddress(
        EgressRule rule,
        out List<(WfpAddressFamily Family, WfpAddressMatch? Match)> families,
        out string? reason)
    {
        families = [];
        reason = null;

        if (string.IsNullOrWhiteSpace(rule.RemoteAddress))
        {
            // No address pin: the rule applies to both families.
            families.Add((WfpAddressFamily.IPv4, null));
            families.Add((WfpAddressFamily.IPv6, null));
            return true;
        }

        var text = rule.RemoteAddress.Trim();

        if (IPAddress.TryParse(text, out var single))
        {
            var family = ToFamily(single);
            families.Add((family, new WfpAddressMatch(family, single.GetAddressBytes(), null)));
            return true;
        }

        if (IPNetwork.TryParse(text, out var network))
        {
            var family = ToFamily(network.BaseAddress);
            families.Add((family, new WfpAddressMatch(
                family,
                network.BaseAddress.GetAddressBytes(),
                network.PrefixLength)));
            return true;
        }

        reason = $"remote address '{text}' is not a valid IP address or CIDR range";
        return false;
    }

    private static ushort? ResolvePort(EgressRule rule, out string? reason)
    {
        reason = null;
        if (!rule.RemotePort.HasValue) return null;

        var port = rule.RemotePort.Value;
        if (port is < 0 or > 65535)
        {
            reason = $"remote port {port} is outside the valid range 0-65535";
            return null;
        }

        return (ushort)port;
    }

    /// <summary>
    /// Maps to an IP protocol number. <see cref="TrafficProtocol.Any"/> yields
    /// null so no protocol condition is added — unlike the netsh backend, WFP can
    /// match a port across both TCP and UDP.
    /// </summary>
    private static byte? ResolveProtocol(TrafficProtocol protocol) => protocol switch
    {
        TrafficProtocol.Tcp => WfpInterop.IPPROTO_TCP,
        TrafficProtocol.Udp => WfpInterop.IPPROTO_UDP,
        _ => null,
    };

    private static WfpAddressFamily ToFamily(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetworkV6
            ? WfpAddressFamily.IPv6
            : WfpAddressFamily.IPv4;
}
