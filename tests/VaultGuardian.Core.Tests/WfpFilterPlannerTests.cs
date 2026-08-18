using VaultGuardian.Core.Firewall.Wfp;

namespace VaultGuardian.Core.Tests;

public class WfpFilterPlannerTests
{
    // ── Address family fan-out ────────────────────────────────────────────────

    [Fact]
    public void Plan_WithoutAddress_EmitsBothFamilies()
    {
        var rule = new EgressRule("block-app", ProcessPath: @"C:\Apps\target.exe");

        var plan = WfpFilterPlanner.Plan([rule]);

        Assert.Equal(2, plan.Filters.Count);
        Assert.Contains(plan.Filters, f => f.Family == WfpAddressFamily.IPv4);
        Assert.Contains(plan.Filters, f => f.Family == WfpAddressFamily.IPv6);
        Assert.All(plan.Filters, f => Assert.Null(f.RemoteAddress));
        Assert.All(plan.Filters, f => Assert.Equal(@"C:\Apps\target.exe", f.AppPath));
    }

    [Fact]
    public void Plan_WithIPv4Address_EmitsSingleV4ExactMatch()
    {
        var rule = new EgressRule("block-host", RemoteAddress: "203.0.113.10");

        var filter = Assert.Single(WfpFilterPlanner.Plan([rule]).Filters);

        Assert.Equal(WfpAddressFamily.IPv4, filter.Family);
        Assert.NotNull(filter.RemoteAddress);
        Assert.Null(filter.RemoteAddress!.PrefixLength);
        Assert.Equal(new byte[] { 203, 0, 113, 10 }, filter.RemoteAddress.Address);
    }

    [Fact]
    public void Plan_WithIPv4Cidr_CarriesPrefixLength()
    {
        var rule = new EgressRule("block-range", RemoteAddress: "203.0.113.0/24");

        var filter = Assert.Single(WfpFilterPlanner.Plan([rule]).Filters);

        Assert.Equal(WfpAddressFamily.IPv4, filter.Family);
        Assert.Equal(24, filter.RemoteAddress!.PrefixLength);
        Assert.Equal(new byte[] { 203, 0, 113, 0 }, filter.RemoteAddress.Address);
    }

    [Fact]
    public void Plan_WithIPv6Address_EmitsSingleV6Filter()
    {
        var rule = new EgressRule("block-v6", RemoteAddress: "2001:db8::1");

        var filter = Assert.Single(WfpFilterPlanner.Plan([rule]).Filters);

        Assert.Equal(WfpAddressFamily.IPv6, filter.Family);
        Assert.Null(filter.RemoteAddress!.PrefixLength);
        Assert.Equal(16, filter.RemoteAddress.Address.Length);
    }

    [Fact]
    public void Plan_WithIPv6Cidr_CarriesPrefixLength()
    {
        var rule = new EgressRule("block-v6-range", RemoteAddress: "2001:db8::/32");

        var filter = Assert.Single(WfpFilterPlanner.Plan([rule]).Filters);

        Assert.Equal(WfpAddressFamily.IPv6, filter.Family);
        Assert.Equal(32, filter.RemoteAddress!.PrefixLength);
    }

    // ── Protocol and port ─────────────────────────────────────────────────────

    [Theory]
    [InlineData(TrafficProtocol.Tcp, (byte)6)]
    [InlineData(TrafficProtocol.Udp, (byte)17)]
    public void Plan_MapsProtocolToIpProtocolNumber(TrafficProtocol protocol, byte expected)
    {
        var rule = new EgressRule("p", RemoteAddress: "203.0.113.10", Protocol: protocol);

        var filter = Assert.Single(WfpFilterPlanner.Plan([rule]).Filters);

        Assert.Equal(expected, filter.IpProtocol);
    }

    [Fact]
    public void Plan_WithAnyProtocol_LeavesProtocolUnconstrained()
    {
        // Unlike the netsh backend — which had to coerce Any to TCP whenever a port
        // was present — WFP can match a port across both TCP and UDP.
        var rule = new EgressRule("p", RemotePort: 443, Protocol: TrafficProtocol.Any);

        var filters = WfpFilterPlanner.Plan([rule]).Filters;

        Assert.NotEmpty(filters);
        Assert.All(filters, f => Assert.Null(f.IpProtocol));
        Assert.All(filters, f => Assert.Equal((ushort)443, f.RemotePort));
    }

    [Fact]
    public void Plan_WithOutOfRangePort_SkipsRule()
    {
        var rule = new EgressRule("bad-port", RemoteAddress: "203.0.113.10", RemotePort: 70000);

        var plan = WfpFilterPlanner.Plan([rule]);

        Assert.Empty(plan.Filters);
        Assert.Contains("70000", Assert.Single(plan.Skipped).Reason);
    }

    // ── Ordering semantics ────────────────────────────────────────────────────

    [Fact]
    public void Plan_AssignsDescendingWeightsSoEarlierRulesWin()
    {
        var rules = new[]
        {
            new EgressRule("first",  RemoteAddress: "203.0.113.1"),
            new EgressRule("second", RemoteAddress: "203.0.113.2"),
            new EgressRule("third",  RemoteAddress: "203.0.113.3"),
        };

        var filters = WfpFilterPlanner.Plan(rules).Filters;

        var first = filters.Single(f => f.RuleName == "first");
        var second = filters.Single(f => f.RuleName == "second");
        var third = filters.Single(f => f.RuleName == "third");

        Assert.True(first.Weight > second.Weight);
        Assert.True(second.Weight > third.Weight);
    }

    [Fact]
    public void Plan_MapsNonBlockingRuleToPermitAction()
    {
        var rules = new[]
        {
            new EgressRule("allow-one", RemoteAddress: "203.0.113.5", Block: false),
            new EgressRule("block-all-range", RemoteAddress: "203.0.113.0/24", Block: true),
        };

        var filters = WfpFilterPlanner.Plan(rules).Filters;

        var permit = filters.Single(f => f.RuleName == "allow-one");
        var block = filters.Single(f => f.RuleName == "block-all-range");

        Assert.Equal(WfpFilterAction.Permit, permit.Action);
        Assert.Equal(WfpFilterAction.Block, block.Action);
        // The exception must outrank the broader block it is carving out of.
        Assert.True(permit.Weight > block.Weight);
    }

    // ── Rules we refuse to install ────────────────────────────────────────────

    [Fact]
    public void Plan_WithNoConditions_SkipsRuleRatherThanMatchingEverything()
    {
        var plan = WfpFilterPlanner.Plan([new EgressRule("catch-all")]);

        Assert.Empty(plan.Filters);
        Assert.Contains("refusing to match all traffic", Assert.Single(plan.Skipped).Reason);
    }

    [Fact]
    public void Plan_WithHostnameOnly_SkipsWithHostnameReason()
    {
        var plan = WfpFilterPlanner.Plan([new EgressRule("by-name", RemoteHost: "telemetry.example.test")]);

        Assert.Empty(plan.Filters);
        Assert.Contains("hostname", Assert.Single(plan.Skipped).Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Plan_WithUnparseableAddress_SkipsWithReason()
    {
        var plan = WfpFilterPlanner.Plan([new EgressRule("junk", RemoteAddress: "not-an-ip")]);

        Assert.Empty(plan.Filters);
        Assert.Contains("not a valid IP address or CIDR", Assert.Single(plan.Skipped).Reason);
    }

    [Fact]
    public void Plan_WithHostBitsSetInCidr_NormalisesToTheNetworkAddress()
    {
        // IPNetwork.TryParse accepts host bits and masks them off, so 203.0.113.10/24
        // becomes 203.0.113.0/24. RuleDecisionEngine.Matches goes through the same
        // parser, so the installed filter and the in-process decision agree.
        var plan = WfpFilterPlanner.Plan([new EgressRule("sloppy-cidr", RemoteAddress: "203.0.113.10/24")]);

        var filter = Assert.Single(plan.Filters);
        Assert.Equal(24, filter.RemoteAddress!.PrefixLength);
        Assert.Equal(new byte[] { 203, 0, 113, 0 }, filter.RemoteAddress.Address);
    }

    [Fact]
    public void Plan_AddressMatching_AgreesWithRuleDecisionEngine()
    {
        // Guards against the planner and the in-process engine drifting apart on
        // what a given RemoteAddress covers.
        var rule = new EgressRule("range", RemoteAddress: "203.0.113.0/24");
        var inside = new TrafficObservation("p", @"C:\p.exe", null, "203.0.113.77", 443, TrafficProtocol.Tcp);
        var outside = new TrafficObservation("p", @"C:\p.exe", null, "198.51.100.5", 443, TrafficProtocol.Tcp);

        Assert.True(rule.Matches(inside));
        Assert.False(rule.Matches(outside));

        var filter = Assert.Single(WfpFilterPlanner.Plan([rule]).Filters);
        Assert.Equal(24, filter.RemoteAddress!.PrefixLength);
        Assert.Equal(new byte[] { 203, 0, 113, 0 }, filter.RemoteAddress.Address);
    }

    [Fact]
    public void Plan_SkippingOneRuleDoesNotDropTheOthers()
    {
        var rules = new[]
        {
            new EgressRule("good-1", RemoteAddress: "203.0.113.1"),
            new EgressRule("junk",   RemoteAddress: "nonsense"),
            new EgressRule("good-2", RemoteAddress: "203.0.113.2"),
        };

        var plan = WfpFilterPlanner.Plan(rules);

        Assert.Equal(2, plan.Filters.Count);
        Assert.Single(plan.Skipped);
    }

    // ── Metadata carried through ──────────────────────────────────────────────

    [Fact]
    public void Plan_CarriesPersistenceFlag()
    {
        var rules = new[]
        {
            new EgressRule("persistent", RemoteAddress: "203.0.113.1", IsPersistent: true),
            new EgressRule("session",    RemoteAddress: "203.0.113.2", IsPersistent: false),
        };

        var filters = WfpFilterPlanner.Plan(rules).Filters;

        Assert.True(filters.Single(f => f.RuleName == "persistent").Persistent);
        Assert.False(filters.Single(f => f.RuleName == "session").Persistent);
    }

    [Fact]
    public void Plan_PrefixesDisplayNameForIdentifiability()
    {
        var filter = Assert.Single(
            WfpFilterPlanner.Plan([new EgressRule("vendor", RemoteAddress: "203.0.113.1")]).Filters);

        Assert.Equal("VG-vendor", filter.DisplayName);
        Assert.Equal("vendor", filter.RuleName);
    }

    [Fact]
    public void Plan_AnyProducedFilterAlwaysHasAtLeastOneCondition()
    {
        var rules = new[]
        {
            new EgressRule("a", ProcessPath: @"C:\a.exe"),
            new EgressRule("b", RemoteAddress: "203.0.113.0/24"),
            new EgressRule("c", RemotePort: 443),
            new EgressRule("d", Protocol: TrafficProtocol.Udp),
        };

        var plan = WfpFilterPlanner.Plan(rules);

        Assert.NotEmpty(plan.Filters);
        Assert.All(plan.Filters, f => Assert.False(f.IsUnconditional));
    }
}
