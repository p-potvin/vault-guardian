namespace VaultGuardian.Core.Processes;

/// <summary>Authenticode trust state of a process image.</summary>
public enum SignatureStatus
{
    Unknown,
    Unsigned,
    SignedUntrusted,
    SignedTrusted
}

/// <summary>Overall trust tag surfaced to the operator.</summary>
public enum ProcessDisposition
{
    /// <summary>Signed/known/OS-owned — expected to be here.</summary>
    Legit,

    /// <summary>Not enough signal to judge.</summary>
    Unknown,

    /// <summary>Unsigned, running from a user-writable path, or otherwise off.</summary>
    Suspicious
}

/// <summary>What happens if the operator terminates the process.</summary>
public enum KillSafety
{
    /// <summary>Background process; terminating it is low-risk.</summary>
    SafeToShutdown,

    /// <summary>Hosts a service or session component; killing it may disrupt features.</summary>
    RiskyToShutdown,

    /// <summary>OS-critical; terminating it bugchecks or forces a sign-out.</summary>
    BreaksWindows
}

/// <summary>
/// The observable facts about a process, gathered by a platform inspector and
/// fed to <see cref="ProcessTriageClassifier"/>. Kept free of platform types so
/// the classification logic is fully unit-testable.
/// </summary>
public sealed record ProcessFacts(
    int ProcessId,
    string Name,
    string? ImagePath,
    int ParentProcessId,
    double CpuPercent,
    long WorkingSetBytes,
    SignatureStatus Signature,
    string? Publisher,
    bool IsCriticalProcess,
    bool IsServiceHost,
    IReadOnlyList<string> HostedServices,
    bool RunsInUtilityVm,
    IReadOnlyList<string> Hostnames)
{
    public static ProcessFacts Minimal(int processId, string name) =>
        new(processId, name, null, 0, 0, 0, SignatureStatus.Unknown, null,
            false, false, [], false, []);
}

/// <summary>Classifier output: a disposition, a kill-safety rating, and the reasons behind both.</summary>
public sealed record ProcessTriageVerdict(
    ProcessDisposition Disposition,
    KillSafety KillSafety,
    IReadOnlyList<string> Reasons);

/// <summary>A fully triaged process row for the UI: facts + verdict.</summary>
public sealed record ProcessTriageEntry(
    ProcessFacts Facts,
    ProcessTriageVerdict Verdict);
