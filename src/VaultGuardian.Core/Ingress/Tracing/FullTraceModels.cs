namespace VaultGuardian.Core.Ingress.Tracing;

public enum FullTraceScopeKind
{
    Flow,
    Source,
    BrowserProfile
}

public enum FullTraceState
{
    Idle,
    Active,
    Stopped
}

public sealed record FullTraceOptions(
    TimeSpan MaxDuration,
    long MaxBytes,
    int MaxPackets)
{
    public static FullTraceOptions Default { get; } = new(
        TimeSpan.FromMinutes(2),
        25 * 1024 * 1024,
        10_000);
}

public sealed record FullTraceTrigger(
    FullTraceScopeKind ScopeKind,
    IngressFlowKey? Flow,
    string Reason,
    DateTimeOffset TriggeredAt);

public sealed record ActiveFullTrace(
    string TraceId,
    FullTraceScopeKind ScopeKind,
    IngressFlowKey? Flow,
    string Reason,
    DateTimeOffset StartedAt,
    long CapturedBytes,
    int CapturedPackets);

public sealed record FullTraceStatus(
    FullTraceState State,
    string? ActiveTraceId,
    string? LastTraceId,
    string? Reason,
    long CapturedBytes,
    int CapturedPackets);
