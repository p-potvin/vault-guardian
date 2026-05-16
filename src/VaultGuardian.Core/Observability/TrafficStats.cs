namespace VaultGuardian.Core.Observability;

public sealed class TrafficStats
{
    private long _total;
    private long _allowed;
    private long _blocked;
    private long _sentBytes;
    private long _recvBytes;

    public void IncrementAllowed(long bytes, bool isOutbound)
    {
        Interlocked.Increment(ref _total);
        Interlocked.Increment(ref _allowed);
        if (isOutbound) Interlocked.Add(ref _sentBytes, bytes);
        else Interlocked.Add(ref _recvBytes, bytes);
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
            Volatile.Read(ref _blocked),
            Volatile.Read(ref _sentBytes),
            Volatile.Read(ref _recvBytes)
        );
    }
}
