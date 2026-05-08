namespace VaultGuardian.Core;

public enum TrafficProtocol
{
    Any,
    Tcp,
    Udp
}

public enum DecisionAction
{
    Allow,
    Block
}

public sealed record TrafficObservation(
    string ProcessName,
    string ProcessPath,
    string RemoteAddress,
    int RemotePort,
    TrafficProtocol Protocol);

public sealed record EgressRule(
    string Name,
    string? ProcessPath = null,
    string? RemoteAddress = null,
    int? RemotePort = null,
    TrafficProtocol Protocol = TrafficProtocol.Any,
    bool Block = true)
{
    public bool Matches(TrafficObservation observation)
    {
        if (!string.IsNullOrWhiteSpace(ProcessPath) &&
            !string.Equals(ProcessPath, observation.ProcessPath, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(RemoteAddress) &&
            !string.Equals(RemoteAddress, observation.RemoteAddress, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (RemotePort.HasValue && RemotePort.Value != observation.RemotePort)
        {
            return false;
        }

        if (Protocol != TrafficProtocol.Any && Protocol != observation.Protocol)
        {
            return false;
        }

        return true;
    }
}

public sealed record DecisionResult(DecisionAction Action, string? MatchedRuleName)
{
    public static DecisionResult Allow() => new(DecisionAction.Allow, null);
}

public sealed class RuleDecisionEngine
{
    private readonly IReadOnlyList<EgressRule> _rules;

    public RuleDecisionEngine(IEnumerable<EgressRule> rules)
    {
        _rules = rules.ToList();
    }

    public DecisionResult Evaluate(TrafficObservation observation)
    {
        foreach (var rule in _rules)
        {
            if (!rule.Matches(observation))
            {
                continue;
            }

            return rule.Block
                ? new DecisionResult(DecisionAction.Block, rule.Name)
                : DecisionResult.Allow();
        }

        return DecisionResult.Allow();
    }
}
