namespace VaultGuardian.Core.Observability;

public sealed record SystemResourceMetrics(
    double CpuUsagePercentage,
    double RamUsageBytes,
    double RamAvailableBytes,
    double GpuUsagePercentage = 0,
    double GpuTempCelsius = 0,
    uint GpuFanSpeedPercentage = 0,
    double GpuMemoryUsedBytes = 0,
    double GpuMemoryTotalBytes = 0,
    double GpuPowerDrawWatts = 0,
    double CudaCoreUtilization = 0,
    uint ActiveCudaKernels = 0,
    double DiskReadBytesPerSec = 0,
    double DiskWriteBytesPerSec = 0,
    double DiskActiveTimePercentage = 0,
    uint DiskQueueLength = 0);

public sealed record TrafficStatsSnapshot(
    long TotalPackets,
    long AllowedPackets,
    long BlockedPackets,
    long TotalBytesSent = 0,
    long TotalBytesRecv = 0);

public sealed record AggregateMetrics(
    SystemResourceMetrics Resources,
    TrafficStatsSnapshot Traffic);
