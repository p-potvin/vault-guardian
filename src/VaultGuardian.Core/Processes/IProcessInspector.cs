namespace VaultGuardian.Core.Processes;

/// <summary>
/// Enumerates running processes with resource cost and a triage verdict, so the
/// operator can spot an expensive or suspicious process and decide what to do
/// without manually retracing the tree in Process Explorer.
/// </summary>
public interface IProcessInspector
{
    /// <summary>
    /// Returns triaged processes ordered by resource cost (highest first),
    /// capped at <paramref name="maxEntries"/>.
    /// </summary>
    IReadOnlyList<ProcessTriageEntry> Snapshot(int maxEntries = 150);
}
