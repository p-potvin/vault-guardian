namespace VaultGuardian.Core.Observability;

public sealed record SystemResourceMetrics(
    double CpuUsagePercentage,
    double RamUsageBytes,
    double RamAvailableBytes,
    double GpuUsagePercentage = 0);

public sealed record AggregateMetrics(
    SystemResourceMetrics Resources,
    TrafficStatsSnapshot Traffic);
