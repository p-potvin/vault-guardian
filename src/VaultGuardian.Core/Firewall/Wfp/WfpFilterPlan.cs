namespace VaultGuardian.Core.Firewall.Wfp;

public enum WfpAddressFamily
{
    IPv4,
    IPv6,
}

public enum WfpFilterAction
{
    Block,
    Permit,
}

/// <summary>
/// A remote-address condition. <see cref="PrefixLength"/> is null for an exact
/// single address, or set for a CIDR range.
/// </summary>
public sealed record WfpAddressMatch(
    WfpAddressFamily Family,
    byte[] Address,
    int? PrefixLength);

/// <summary>
/// One concrete WFP filter to install. A single <see cref="EgressRule"/> can
/// produce two of these (IPv4 + IPv6) when it does not pin an address family.
/// </summary>
public sealed record WfpFilterPlan
{
    public required string RuleName { get; init; }
    public required string DisplayName { get; init; }
    public required WfpAddressFamily Family { get; init; }
    public required WfpFilterAction Action { get; init; }

    /// <summary>
    /// Higher weight is evaluated first within our sublayer. The planner assigns
    /// descending weights by rule order so WFP reproduces the
    /// <see cref="RuleDecisionEngine"/> "first match wins" semantics.
    /// </summary>
    public required ulong Weight { get; init; }

    public required bool Persistent { get; init; }

    public string? AppPath { get; init; }
    public WfpAddressMatch? RemoteAddress { get; init; }
    public ushort? RemotePort { get; init; }

    /// <summary>IP protocol number: 6 (TCP), 17 (UDP), or null for any.</summary>
    public byte? IpProtocol { get; init; }

    /// <summary>True when this filter carries no conditions at all.</summary>
    public bool IsUnconditional =>
        AppPath is null && RemoteAddress is null && RemotePort is null && IpProtocol is null;
}

public sealed record WfpSkippedRule(string RuleName, string Reason);

public sealed record WfpPlan(
    IReadOnlyList<WfpFilterPlan> Filters,
    IReadOnlyList<WfpSkippedRule> Skipped)
{
    public static WfpPlan Empty { get; } = new([], []);
}
