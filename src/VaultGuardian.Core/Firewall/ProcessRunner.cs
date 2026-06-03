using System.Diagnostics;

namespace VaultGuardian.Core.Firewall;

public sealed class ProcessRunner : IProcessRunner
{
    public async Task<int> RunAsync(string fileName, IEnumerable<string> arguments, CancellationToken cancellationToken = default)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
        };

        foreach (var arg in arguments)
        {
            psi.ArgumentList.Add(arg);
        }

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {fileName}");

        await process.WaitForExitAsync(cancellationToken);
        return process.ExitCode;
    }
}
