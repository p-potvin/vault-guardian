using System.Diagnostics;

namespace VaultGuardian.Core.Firewall;

public sealed class ProcessRunner : IProcessRunner
{
    public async Task<int> RunAsync(string fileName, string arguments, CancellationToken cancellationToken = default)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {fileName}");

        await process.WaitForExitAsync(cancellationToken);
        return process.ExitCode;
    }
}
