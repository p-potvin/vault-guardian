using VaultGuardian.Core;

namespace VaultGuardian.UI;

public sealed class RuleRowVM
{
    public string Name { get; set; } = string.Empty;
    public string RemoteAddress { get; set; } = string.Empty;
    public string RemotePort { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public bool Block { get; set; }
    public EgressRule Rule { get; set; } = new(string.Empty);

    public static RuleRowVM From(EgressRule r) => new()
    {
        Name = r.Name,
        RemoteAddress = r.RemoteAddress ?? r.RemoteHost ?? string.Empty,
        RemotePort = r.RemotePort?.ToString() ?? string.Empty,
        Protocol = r.Protocol.ToString(),
        Block = r.Block,
        Rule = r,
    };
}
