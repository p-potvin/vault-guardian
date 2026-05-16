using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;

namespace VaultGuardian.Core.Observability;

public sealed partial class ResourceMonitor : IDisposable
{
    private readonly PerformanceCounter _cpuCounter;
    private readonly PerformanceCounter _ramAvailableCounter;
    private readonly PerformanceCounter _diskReadCounter;
    private readonly PerformanceCounter _diskWriteCounter;
    private readonly PerformanceCounter _diskQueueCounter;
    private readonly PerformanceCounter _diskTimeCounter;
    private readonly CudaProfiler _cudaProfiler;
    private bool _disposed;
    private bool _nvmlInitialized;
    private IntPtr _gpuHandle;

    public ResourceMonitor(CudaProfiler cudaProfiler)
    {
        _cudaProfiler = cudaProfiler;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
            _ramAvailableCounter = new PerformanceCounter("Memory", "Available MBytes");
            _diskReadCounter = new PerformanceCounter("PhysicalDisk", "Disk Read Bytes/sec", "_Total");
            _diskWriteCounter = new PerformanceCounter("PhysicalDisk", "Disk Write Bytes/sec", "_Total");
            _diskQueueCounter = new PerformanceCounter("PhysicalDisk", "Current Disk Queue Length", "_Total");
            _diskTimeCounter = new PerformanceCounter("PhysicalDisk", "% Disk Time", "_Total");

            // Initial read to avoid first value being 0
            _cpuCounter.NextValue();
            _diskReadCounter.NextValue();
            _diskWriteCounter.NextValue();
            _diskQueueCounter.NextValue();
            _diskTimeCounter.NextValue();
            
            InitializeNvml();
        }
        else
        {
            throw new PlatformNotSupportedException("ResourceMonitor is currently only supported on Windows.");
        }
    }

    private void InitializeNvml()
    {
        try
        {
            if (nvmlInit() == 0)
            {
                _nvmlInitialized = true;
                // Get handle for the first GPU (index 0)
                if (nvmlDeviceGetHandleByIndex(0, out _gpuHandle) != 0)
                {
                    _gpuHandle = IntPtr.Zero;
                }
            }
        }
        catch { /* NVML not found or failed to init */ }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct nvmlUtilization_t
    {
        public uint gpu;
        public uint memory;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct nvmlMemory_t
    {
        public ulong total;
        public ulong free;
        public ulong used;
    }

    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlInit();

    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlShutdown();

    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlDeviceGetHandleByIndex(uint index, out IntPtr device);

    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlDeviceGetUtilizationRates(IntPtr device, out nvmlUtilization_t utilization);

    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlDeviceGetTemperature(IntPtr device, int sensorType, out uint temp);

    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlDeviceGetFanSpeed(IntPtr device, out uint speed);

    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlDeviceGetMemoryInfo(IntPtr device, out nvmlMemory_t memory);

    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlDeviceGetPowerUsage(IntPtr device, out uint power);

    public SystemResourceMetrics GetCurrentMetrics()
    {
        var cpuUsage = _cpuCounter.NextValue();
        var availableUnits = _ramAvailableCounter.NextValue();

        // Approximate Total RAM using computer info
        var totalRamBytes = GetTotalPhysicalMemory();
        var availableBytes = availableUnits * 1024 * 1024;
        var usedBytes = totalRamBytes - availableBytes;

        var gpuStats = GetExtendedGpuStats();

        return new SystemResourceMetrics(
            CpuUsagePercentage: cpuUsage,
            RamUsageBytes: usedBytes,
            RamAvailableBytes: availableBytes,
            GpuUsagePercentage: gpuStats.Usage,
            GpuTempCelsius: gpuStats.Temp,
            GpuFanSpeedPercentage: gpuStats.Fan,
            GpuMemoryUsedBytes: gpuStats.MemUsed,
            GpuMemoryTotalBytes: gpuStats.MemTotal,
            GpuPowerDrawWatts: gpuStats.Power,
            CudaCoreUtilization: _cudaProfiler.GetCoreUtilization(),
            ActiveCudaKernels: _cudaProfiler.GetActiveKernelCount(),
            DiskReadBytesPerSec: _diskReadCounter.NextValue(),
            DiskWriteBytesPerSec: _diskWriteCounter.NextValue(),
            DiskActiveTimePercentage: _diskTimeCounter.NextValue(),
            DiskQueueLength: (uint)_diskQueueCounter.NextValue()
        );
    }

    private (double Usage, double Temp, uint Fan, double MemUsed, double MemTotal, double Power) GetExtendedGpuStats()
    {
        if (_nvmlInitialized && _gpuHandle != IntPtr.Zero)
        {
            double usage = 0, temp = 0, memUsed = 0, memTotal = 0, power = 0;
            uint fan = 0;

            if (nvmlDeviceGetUtilizationRates(_gpuHandle, out var utilization) == 0) usage = utilization.gpu;
            if (nvmlDeviceGetTemperature(_gpuHandle, 0, out var t) == 0) temp = t;
            if (nvmlDeviceGetFanSpeed(_gpuHandle, out var f) == 0) fan = f;
            if (nvmlDeviceGetMemoryInfo(_gpuHandle, out var mem) == 0)
            {
                memUsed = mem.used;
                memTotal = mem.total;
            }
            if (nvmlDeviceGetPowerUsage(_gpuHandle, out var p) == 0) power = p / 1000.0; // mW to W

            return (usage, temp, fan, memUsed, memTotal, power);
        }

        return (0, 0, 0, 0, 0, 0);
    }

    private double GetTotalPhysicalMemory()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
            foreach (var obj in searcher.Get())
            {
                return Convert.ToDouble(obj["TotalPhysicalMemory"]);
            }
        }
        catch { }
        return 16.0 * 1024 * 1024 * 1024; // Fallback
    }

    public void Dispose()
    {
        if (_disposed) return;
        _cpuCounter?.Dispose();
        _ramAvailableCounter?.Dispose();
        _diskReadCounter?.Dispose();
        _diskWriteCounter?.Dispose();
        _diskQueueCounter?.Dispose();
        _diskTimeCounter?.Dispose();
        _cudaProfiler?.Dispose();

        if (_nvmlInitialized)
        {
            try { nvmlShutdown(); } catch { }
        }
        
        _disposed = true;
    }
}
