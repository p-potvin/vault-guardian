using VaultGuardian.Core.Ingress;
using VaultGuardian.Core.Ingress.Mitm;
using VaultGuardian.Core.Ingress.Telemetry;
using VaultGuardian.Core.Ingress.Tracing;

namespace VaultGuardian.Core.Observability;

/// <summary>Per-device GPU readout. One of these exists for every NVML device found.</summary>
public sealed record GpuMetrics(
    int Index,
    string Name,
    double UsagePercentage = 0,
    double TempCelsius = 0,
    uint FanSpeedPercentage = 0,
    double MemoryUsedBytes = 0,
    double MemoryTotalBytes = 0,
    double PowerDrawWatts = 0)
{
    public double MemoryUsedPercentage =>
        MemoryTotalBytes > 0 ? MemoryUsedBytes / MemoryTotalBytes * 100 : 0;
}

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
    uint DiskQueueLength = 0,
    IReadOnlyList<GpuMetrics>? Gpus = null)
{
    /// <summary>
    /// Every detected GPU. The flat Gpu* properties above mirror the first device
    /// so existing single-GPU consumers keep working unchanged.
    /// </summary>
    public IReadOnlyList<GpuMetrics> GpuList => Gpus ?? [];
}

public sealed record TrafficStatsSnapshot(
    long TotalPackets,
    long AllowedPackets,
    long BlockedPackets,
    long TotalBytesSent = 0,
    long TotalBytesRecv = 0);

public sealed record AggregateMetrics(
    SystemResourceMetrics Resources,
    TrafficStatsSnapshot Traffic,
    IngressTrafficSnapshot Ingress,
    IngressWatcherStatus IngressWatcher,
    IReadOnlyList<PrivacyTelemetryHit> IngressTelemetryHits,
    FullTraceStatus FullTrace,
    MitmProxyStatus MitmProxy);
