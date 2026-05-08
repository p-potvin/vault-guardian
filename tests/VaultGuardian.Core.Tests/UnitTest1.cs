namespace VaultGuardian.Core.Tests;

public class UnitTest1
{
    [Fact]
    public void Evaluate_ShouldAllow_WhenNoRuleMatches()
    {
        var engine = new RuleDecisionEngine(
        [
            new EgressRule(Name: "block-example", ProcessPath: @"C:\Apps\app.exe", RemoteAddress: "203.0.113.10")
        ]);

        var observation = new TrafficObservation(
            ProcessName: "app",
            ProcessPath: @"C:\Apps\app.exe",
            RemoteAddress: "198.51.100.4",
            RemotePort: 443,
            Protocol: TrafficProtocol.Tcp);

        var result = engine.Evaluate(observation);

        Assert.Equal(DecisionAction.Allow, result.Action);
        Assert.Null(result.MatchedRuleName);
    }

    [Fact]
    public void Evaluate_ShouldBlockSpecificDestination_ForTargetProcessOnly()
    {
        var engine = new RuleDecisionEngine(
        [
            new EgressRule(
                Name: "block-vendor-endpoint",
                ProcessPath: @"C:\Apps\target.exe",
                RemoteAddress: "203.0.113.10",
                RemotePort: 443,
                Protocol: TrafficProtocol.Tcp)
        ]);

        var blockedObservation = new TrafficObservation(
            ProcessName: "target",
            ProcessPath: @"C:\Apps\target.exe",
            RemoteAddress: "203.0.113.10",
            RemotePort: 443,
            Protocol: TrafficProtocol.Tcp);

        var allowedForOtherDestination = new TrafficObservation(
            ProcessName: "target",
            ProcessPath: @"C:\Apps\target.exe",
            RemoteAddress: "198.51.100.4",
            RemotePort: 443,
            Protocol: TrafficProtocol.Tcp);

        var allowedForOtherProcess = new TrafficObservation(
            ProcessName: "other",
            ProcessPath: @"C:\Apps\other.exe",
            RemoteAddress: "203.0.113.10",
            RemotePort: 443,
            Protocol: TrafficProtocol.Tcp);

        var blockedResult = engine.Evaluate(blockedObservation);
        var destinationAllowedResult = engine.Evaluate(allowedForOtherDestination);
        var processAllowedResult = engine.Evaluate(allowedForOtherProcess);

        Assert.Equal(DecisionAction.Block, blockedResult.Action);
        Assert.Equal("block-vendor-endpoint", blockedResult.MatchedRuleName);
        Assert.Equal(DecisionAction.Allow, destinationAllowedResult.Action);
        Assert.Equal(DecisionAction.Allow, processAllowedResult.Action);
    }
}
