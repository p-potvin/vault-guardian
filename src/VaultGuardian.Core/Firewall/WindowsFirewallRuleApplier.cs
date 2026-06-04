using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace VaultGuardian.Core.Firewall;

public sealed class WindowsFirewallRuleApplier : IFirewallRuleApplier
{
    public const string ManagedRulePrefix = "VG-";
    public const string StateFilePath = "firewall-state.json";

    private readonly IProcessRunner _runner;
    private readonly ILogger<WindowsFirewallRuleApplier> _logger;
    private readonly string _stateFilePath;
    private readonly SemaphoreSlim _lock = new(1, 1);

    // Tracked separately so ClearSessionRulesAsync only touches session rules.
    private readonly HashSet<string> _persistentApplied = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _sessionApplied = new(StringComparer.OrdinalIgnoreCase);

    public WindowsFirewallRuleApplier(IProcessRunner runner, ILogger<WindowsFirewallRuleApplier> logger)
        : this(runner, logger, StateFilePath) { }

    internal WindowsFirewallRuleApplier(IProcessRunner runner, ILogger<WindowsFirewallRuleApplier> logger, string stateFilePath)
    {
        _runner = runner;
        _logger = logger;
        _stateFilePath = stateFilePath;
    }

    public async Task CleanupPreviousSessionAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var previousNames = await LoadStateAsync(cancellationToken);
            foreach (var name in previousNames)
            {
                await DeleteRuleAsync(name, cancellationToken);
            }

            SaveState([], cancellationToken);
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task ApplyAsync(IEnumerable<EgressRule> rules, CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var incoming = rules.ToList();

            // Delete all currently tracked rules (persistent + session).
            var allTracked = new HashSet<string>(_persistentApplied, StringComparer.OrdinalIgnoreCase);
            allTracked.UnionWith(_sessionApplied);

            // Also pre-delete incoming names in case they appear under different tracking.
            var incomingNames = incoming.Select(r => ManagedName(r.Name));
            allTracked.UnionWith(incomingNames);

            foreach (var name in allTracked)
            {
                await DeleteRuleAsync(name, cancellationToken);
            }

            _persistentApplied.Clear();
            _sessionApplied.Clear();

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

                var managedName = ManagedName(rule.Name);
                if (rule.IsPersistent)
                    _persistentApplied.Add(managedName);
                else
                    _sessionApplied.Add(managedName);
            }

            // Persist only the names of persistent rules; session rules are intentionally
            // omitted so they are gone after a restart without needing cleanup.
            SaveState(_persistentApplied, cancellationToken);
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task ClearSessionRulesAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            foreach (var name in _sessionApplied.ToArray())
            {
                await DeleteRuleAsync(name, cancellationToken);
            }
            _sessionApplied.Clear();

            // Update state file to reflect only the persistent rules that remain.
            SaveState(_persistentApplied, cancellationToken);
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
            var all = _persistentApplied.Concat(_sessionApplied).ToArray();
            foreach (var name in all)
            {
                await DeleteRuleAsync(name, cancellationToken);
            }
            _persistentApplied.Clear();
            _sessionApplied.Clear();

            if (File.Exists(_stateFilePath))
                File.Delete(_stateFilePath);
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
            arguments.Add($"program={rule.ProcessPath}");

        if (hasRemoteIp)
            arguments.Add($"remoteip={rule.RemoteAddress}");

        if (hasRemotePort)
            arguments.Add($"remoteport={rule.RemotePort!.Value}");

        // netsh rejects remoteport when protocol=any; fall back to TCP in that case.
        var protocol = rule.Protocol;
        if (hasRemotePort && protocol == TrafficProtocol.Any)
            protocol = TrafficProtocol.Tcp;

        arguments.Add($"protocol={ProtocolToken(protocol)}");
        return true;
    }

    private async Task DeleteRuleAsync(string managedName, CancellationToken cancellationToken)
    {
        var args = new[] { "advfirewall", "firewall", "delete", "rule", $"name={managedName}" };
        await _runner.RunAsync("netsh", args, cancellationToken);
    }

    private async Task<List<string>> LoadStateAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_stateFilePath)) return [];
        try
        {
            using var stream = File.OpenRead(_stateFilePath);
            return await JsonSerializer.DeserializeAsync<List<string>>(stream, cancellationToken: cancellationToken) ?? [];
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to read firewall state file; treating as empty");
            return [];
        }
    }

    private void SaveState(IEnumerable<string> names, CancellationToken cancellationToken)
    {
        try
        {
            var list = names.ToList();
            var json = JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_stateFilePath, json);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to write firewall state file");
        }
    }

    private static string ProtocolToken(TrafficProtocol protocol) => protocol switch
    {
        TrafficProtocol.Tcp => "TCP",
        TrafficProtocol.Udp => "UDP",
        _ => "any",
    };
}
