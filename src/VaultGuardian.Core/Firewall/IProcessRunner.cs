namespace VaultGuardian.Core.Firewall;

public interface IProcessRunner
{
    Task<int> RunAsync(string fileName, IEnumerable<string> arguments, CancellationToken cancellationToken = default);
}
