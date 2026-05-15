namespace VaultGuardian.Core.Observability;

public sealed record TrafficStatsSnapshot(
    long TotalPackets,
    long AllowedPackets,
    long BlockedPackets);

public sealed class TrafficStats
{
    private long _total;
    private long _allowed;
    private long _blocked;

    public void IncrementAllowed()
    {
        Interlocked.Increment(ref _total);
        Interlocked.Increment(ref _allowed);
    }

    public void IncrementBlocked()
    {
        Interlocked.Increment(ref _total);
        Interlocked.Increment(ref _blocked);
    }

    public TrafficStatsSnapshot GetSnapshot()
    {
        return new TrafficStatsSnapshot(
            Volatile.Read(ref _total),
            Volatile.Read(ref _allowed),
            Volatile.Read(ref _blocked)
        );
    }
}
