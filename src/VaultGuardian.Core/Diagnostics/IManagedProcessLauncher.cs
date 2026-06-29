namespace VaultGuardian.Core.Diagnostics;

public interface IManagedProcessLauncher
{
    IManagedProcess Start(string fileName, IReadOnlyList<string> arguments);
}

public interface IManagedProcess : IDisposable
{
    int ProcessId { get; }
    bool HasExited { get; }
    void Stop();
}
