using System.Diagnostics;

namespace VaultGuardian.Core.Diagnostics;

public sealed class ManagedProcessLauncher : IManagedProcessLauncher
{
    public IManagedProcess Start(string fileName, IReadOnlyList<string> arguments)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
        };

        foreach (var argument in arguments)
        {
            psi.ArgumentList.Add(argument);
        }

        var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {fileName}");
        return new ManagedProcess(process);
    }

    private sealed class ManagedProcess : IManagedProcess
    {
        private readonly Process _process;

        public ManagedProcess(Process process)
        {
            _process = process;
        }

        public int ProcessId => _process.Id;
        public bool HasExited => _process.HasExited;

        public void Stop()
        {
            if (_process.HasExited)
            {
                return;
            }

            try
            {
                if (!_process.CloseMainWindow())
                {
                    _process.Kill(entireProcessTree: true);
                }
            }
            catch (InvalidOperationException)
            {
            }
        }

        public void Dispose()
        {
            Stop();
            _process.Dispose();
        }
    }
}
