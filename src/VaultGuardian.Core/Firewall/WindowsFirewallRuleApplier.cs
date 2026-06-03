using Microsoft.Extensions.Logging;

namespace VaultGuardian.Core.Firewall;

public sealed class WindowsFirewallRuleApplier : IFirewallRuleApplier
{
    public const string ManagedRulePrefix = "VG-";

    private readonly IProcessRunner _runner;
    private readonly ILogger<WindowsFirewallRuleApplier> _logger;
    private readonly HashSet<string> _appliedNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _lock = new(1, 1);

    public WindowsFirewallRuleApplier(IProcessRunner runner, ILogger<WindowsFirewallRuleApplier> logger)
    {
        _runner = runner;
        _logger = logger;
    }

    public async Task ApplyAsync(IEnumerable<EgressRule> rules, CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var incoming = rules.ToList();
            var incomingNames = incoming.Select(r => ManagedName(r.Name)).ToHashSet(StringComparer.OrdinalIgnoreCase);

            var toDelete = new HashSet<string>(_appliedNames, StringComparer.OrdinalIgnoreCase);
            toDelete.UnionWith(incomingNames);

            foreach (var name in toDelete)
            {
                var args = new[] { "advfirewall", "firewall", "delete", "rule", $"name={name}" };
                await _runner.RunAsync("netsh", args, cancellationToken);
            }

            _appliedNames.Clear();

            foreach (var rule in incoming)
            {
                if (!rule.Block) continue;
                if (!TryBuildAddArguments(rule, out var args, out var skipReason))
                {
                    _logger.LogDebug("Skipping rule '{Rule}': {Reason}", rule.Name, skipReason);
                    continue;
                }

                var exitCode = await _runner.RunAsync("netsh", args, cancellationToken);
                if (exitCode != 0)
                {
                    throw new InvalidOperationException(
                        $"Failed to add firewall rule '{rule.Name}' (netsh exit code: {exitCode}). Ensure the app is running as Administrator.");
                }

                _appliedNames.Add(ManagedName(rule.Name));
            }
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task ClearAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            foreach (var name in _appliedNames.ToArray())
            {
                var args = new[] { "advfirewall", "firewall", "delete", "rule", $"name={name}" };
                await _runner.RunAsync("netsh", args, cancellationToken);
            }
            _appliedNames.Clear();
        }
        finally
        {
            _lock.Release();
        }
    }

    public static string ManagedName(string ruleName) => ManagedRulePrefix + ruleName;

    internal static bool TryBuildAddArguments(EgressRule rule, out List<string> arguments, out string? skipReason)
    {
        arguments = new List<string>();
        skipReason = null;

        var hasProgram = !string.IsNullOrWhiteSpace(rule.ProcessPath);
        var hasRemoteIp = !string.IsNullOrWhiteSpace(rule.RemoteAddress);
        var hasRemotePort = rule.RemotePort.HasValue;

        if (!hasProgram && !hasRemoteIp && !hasRemotePort)
        {
            skipReason = "no program, remote address, or remote port specified (hostnames are not supported by netsh)";
            return false;
        }

        arguments.AddRange(new[]
        {
            "advfirewall", "firewall", "add", "rule",
            $"name={ManagedName(rule.Name)}",
            "dir=out",
            "action=block",
            "enable=yes",
        });

        if (hasProgram)
        {
            arguments.Add($"program={rule.ProcessPath}");
        }

        if (hasRemoteIp)
        {
            arguments.Add($"remoteip={rule.RemoteAddress}");
        }

        if (hasRemotePort)
        {
            arguments.Add($"remoteport={rule.RemotePort!.Value}");
        }

        // netsh rejects remoteport when protocol=any; fall back to TCP in that case.
        var protocol = rule.Protocol;
        if (hasRemotePort && protocol == TrafficProtocol.Any)
        {
            protocol = TrafficProtocol.Tcp;
        }
        arguments.Add($"protocol={ProtocolToken(protocol)}");

        return true;
    }

    private static string ProtocolToken(TrafficProtocol protocol) => protocol switch
    {
        TrafficProtocol.Tcp => "TCP",
        TrafficProtocol.Udp => "UDP",
        _ => "any",
    };
}
