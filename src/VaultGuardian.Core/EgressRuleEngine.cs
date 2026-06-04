using System.Net;

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
    string? RemoteHost,
    string RemoteAddress,
    int RemotePort,
    TrafficProtocol Protocol);

public sealed record EgressRule(
    string Name,
    string? ProcessPath = null,
    string? RemoteHost = null,
    string? RemoteAddress = null,
    int? RemotePort = null,
    TrafficProtocol Protocol = TrafficProtocol.Any,
    bool Block = true,
    bool IsPersistent = true)
{
    public bool Matches(TrafficObservation observation)
    {
        if (!string.IsNullOrWhiteSpace(ProcessPath) &&
            !string.Equals(ProcessPath, observation.ProcessPath, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(RemoteAddress))
        {
            if (IPNetwork.TryParse(RemoteAddress, out var network))
            {
                if (!IPAddress.TryParse(observation.RemoteAddress, out var obsAddress) || !network.Contains(obsAddress))
                {
                    return false;
                }
            }
            else if (!string.Equals(RemoteAddress, observation.RemoteAddress, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        if (!string.IsNullOrWhiteSpace(RemoteHost) &&
            !string.Equals(RemoteHost, observation.RemoteHost, StringComparison.OrdinalIgnoreCase))
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
    private List<EgressRule> _rules;
    private readonly object _lock = new();

    public RuleDecisionEngine(IEnumerable<EgressRule> rules)
    {
        _rules = rules.ToList();
    }

    public IReadOnlyList<EgressRule> Rules
    {
        get
        {
            lock (_lock) return _rules.ToList();
        }
    }

    public void UpdateRules(IEnumerable<EgressRule> rules)
    {
        lock (_lock)
        {
            _rules = rules.ToList();
        }
    }

    public DecisionResult Evaluate(TrafficObservation observation)
    {
        List<EgressRule> currentRules;
        lock (_lock)
        {
            currentRules = _rules;
        }

        foreach (var rule in currentRules)
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
