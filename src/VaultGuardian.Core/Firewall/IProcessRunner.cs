namespace VaultGuardian.Core.Firewall;

public interface IProcessRunner
{
    Task<int> RunAsync(string fileName, string arguments, CancellationToken cancellationToken = default);
}
